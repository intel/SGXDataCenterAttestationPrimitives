// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-19 Intel Corporation.

#include <linux/freezer.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>
#include <linux/ratelimit.h>
#include <linux/slab.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include "encl.h"
#include "encls.h"
#include "driver.h"

#include <linux/version.h>

struct task_struct *ksgxswapd_tsk;
DECLARE_WAIT_QUEUE_HEAD(ksgxswapd_waitq);
LIST_HEAD(sgx_active_page_list);
DEFINE_SPINLOCK(sgx_active_page_list_lock);

static void sgx_sanitize_section(struct sgx_epc_section *section)
{
	struct sgx_epc_page *page;
	LIST_HEAD(secs_list);
	int ret;

	while (!list_empty(&section->unsanitized_page_list)) {
		if (kthread_should_stop())
			return;

		spin_lock(&section->lock);

		page = list_first_entry(&section->unsanitized_page_list,
					struct sgx_epc_page, list);

		ret = __eremove(sgx_epc_addr(page));
		if (!ret)
			list_move(&page->list, &section->page_list);
		else
			list_move_tail(&page->list, &secs_list);

		spin_unlock(&section->lock);

		cond_resched();
	}
}

static int ksgxswapd(void *p)
{
	int i;

	set_freezable();

	/*
	 * Reset all pages to uninitialized state. Pages could be in initialized
	 * on kmemexec.
	 */
	for (i = 0; i < sgx_nr_epc_sections; i++)
		sgx_sanitize_section(&sgx_epc_sections[i]);

	/*
	 * 2nd round for the SECS pages as they cannot be removed when they
	 * still hold child pages.
	 */
	for (i = 0; i < sgx_nr_epc_sections; i++) {
		sgx_sanitize_section(&sgx_epc_sections[i]);

		/* Should never happen. */
		if (!list_empty(&sgx_epc_sections[i].unsanitized_page_list))
			WARN(1, "EPC section %d has unsanitized pages.\n", i);
	}

	while (!kthread_should_stop()) {
		if (try_to_freeze())
			continue;

		wait_event_freezable(ksgxswapd_waitq,
				     kthread_should_stop() ||
				     sgx_should_reclaim(SGX_NR_HIGH_PAGES));

		if (sgx_should_reclaim(SGX_NR_HIGH_PAGES))
			sgx_reclaim_pages();

		cond_resched();
	}

	return 0;
}

bool __init sgx_page_reclaimer_init(void)
{
	struct task_struct *tsk;

	tsk = kthread_run(ksgxswapd, NULL, "ksgxswapd");
	if (IS_ERR(tsk))
		return false;

	ksgxswapd_tsk = tsk;

	return true;
}

/**
 * sgx_mark_page_reclaimable() - Mark a page as reclaimable
 * @page:	EPC page
 *
 * Mark a page as reclaimable and add it to the active page list. Pages
 * are automatically removed from the active list when freed.
 */
void sgx_mark_page_reclaimable(struct sgx_epc_page *page)
{
	spin_lock(&sgx_active_page_list_lock);
	page->desc |= SGX_EPC_PAGE_RECLAIMABLE;
	list_add_tail(&page->list, &sgx_active_page_list);
	spin_unlock(&sgx_active_page_list_lock);
}

/**
 * sgx_unmark_page_reclaimable() - Remove a page from the reclaim list
 * @page:	EPC page
 *
 * Clear the reclaimable flag and remove the page from the active page list.
 *
 * Return:
 *   0 on success,
 *   -EBUSY if the page is in the process of being reclaimed
 */
int sgx_unmark_page_reclaimable(struct sgx_epc_page *page)
{
	/*
	 * Remove the page from the active list if necessary.  If the page
	 * is actively being reclaimed, i.e. RECLAIMABLE is set but the
	 * page isn't on the active list, return -EBUSY as we can't free
	 * the page at this time since it is "owned" by the reclaimer.
	 */
	spin_lock(&sgx_active_page_list_lock);
	if (page->desc & SGX_EPC_PAGE_RECLAIMABLE) {
		if (list_empty(&page->list)) {
			spin_unlock(&sgx_active_page_list_lock);
			return -EBUSY;
		}
		list_del(&page->list);
		page->desc &= ~SGX_EPC_PAGE_RECLAIMABLE;
	}
	spin_unlock(&sgx_active_page_list_lock);

	return 0;
}

static bool sgx_reclaimer_age(struct sgx_epc_page *epc_page)
{
	struct sgx_encl_page *page = epc_page->owner;
	struct sgx_encl *encl = page->encl;
	struct sgx_encl_mm *encl_mm;
	bool ret = true;
	int idx;

	/*
	 * Note, this can race with sgx_encl_mm_add(), but worst case scenario
	 * a page will be reclaimed immediately after it's accessed in the new
	 * process/mm.
	 */
	idx = srcu_read_lock(&encl->srcu);

	list_for_each_entry_rcu(encl_mm, &encl->mm_list, list) {
		if (!mmget_not_zero(encl_mm->mm))
			continue;

		down_read(&encl_mm->mm->mmap_sem);
		ret = !sgx_encl_test_and_clear_young(encl_mm->mm, page);
		up_read(&encl_mm->mm->mmap_sem);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0) || LINUX_VERSION_CODE > KERNEL_VERSION(5, 4, 0) )
		mmput(encl_mm->mm);
#else
		mmput_async(encl_mm->mm);
#endif

		if (!ret || (atomic_read(&encl->flags) & SGX_ENCL_DEAD))
			break;
	}

	srcu_read_unlock(&encl->srcu, idx);

	if (!ret && !(atomic_read(&encl->flags) & SGX_ENCL_DEAD))
		return false;

	return true;
}

static void sgx_reclaimer_block(struct sgx_epc_page *epc_page)
{
	struct sgx_encl_page *page = epc_page->owner;
	unsigned long addr = SGX_ENCL_PAGE_ADDR(page);
	struct sgx_encl *encl = page->encl;
	struct sgx_encl_mm *encl_mm;
	struct vm_area_struct *vma;
	unsigned long mm_list_gen;
	int idx, ret;

retry:
	mm_list_gen = encl->mm_list_gen;
	/*
	 * Ensure mm_list_gen is snapshotted before walking mm_list to prevent
	 * beginning the walk with the old list in the new generation.  Pairs
	 * with the smp_wmb() in sgx_encl_mm_add().
	 */
	smp_rmb();

	idx = srcu_read_lock(&encl->srcu);

	list_for_each_entry_rcu(encl_mm, &encl->mm_list, list) {
		if (!mmget_not_zero(encl_mm->mm))
			continue;

		down_read(&encl_mm->mm->mmap_sem);

		ret = sgx_encl_find(encl_mm->mm, addr, &vma);
		if (!ret && encl == vma->vm_private_data)
			zap_vma_ptes(vma, addr, PAGE_SIZE);

		up_read(&encl_mm->mm->mmap_sem);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0) || LINUX_VERSION_CODE > KERNEL_VERSION(5, 4, 0) )
		mmput(encl_mm->mm);
#else
		mmput_async(encl_mm->mm);
#endif
	}

	srcu_read_unlock(&encl->srcu, idx);

	/*
	 * Redo the zapping if a mm was added to mm_list while zapping was in
	 * progress.  dup_mmap() copies the PTEs for VM_PFNMAP VMAs, i.e. the
	 * new mm won't take a page fault and so won't see that the page is
	 * tagged RECLAIMED.  Note, vm_ops->open()/sgx_encl_mm_add() is called
	 * _after_ PTEs are copied, and dup_mmap() holds the old mm's mmap_sem
	 * for write, so the generation check is only needed to protect against
	 * dup_mmap() running after the mm_list walk started but before the old
	 * mm's PTEs were zapped.
	 */
	if (unlikely(encl->mm_list_gen != mm_list_gen))
		goto retry;

	mutex_lock(&encl->lock);

	if (!(atomic_read(&encl->flags) & SGX_ENCL_DEAD)) {
		ret = __eblock(sgx_epc_addr(epc_page));
		if (encls_failed(ret))
			ENCLS_WARN(ret, "EBLOCK");
	}

	mutex_unlock(&encl->lock);
}

static int __sgx_encl_ewb(struct sgx_epc_page *epc_page, void *va_slot,
			  struct sgx_backing *backing)
{
	struct sgx_pageinfo pginfo;
	int ret;

	pginfo.addr = 0;
	pginfo.secs = 0;

	pginfo.contents = (unsigned long)kmap_atomic(backing->contents);
	pginfo.metadata = (unsigned long)kmap_atomic(backing->pcmd) +
			  backing->pcmd_offset;

	ret = __ewb(&pginfo, sgx_epc_addr(epc_page), va_slot);

	kunmap_atomic((void *)(unsigned long)(pginfo.metadata -
					      backing->pcmd_offset));
	kunmap_atomic((void *)(unsigned long)pginfo.contents);

	return ret;
}

static void sgx_ipi_cb(void *info)
{
}

static const cpumask_t *sgx_encl_ewb_cpumask(struct sgx_encl *encl)
{
	cpumask_t *cpumask = &encl->cpumask;
	struct sgx_encl_mm *encl_mm;
	int idx;

	/*
	 * Note, this can race with sgx_encl_mm_add(), but ETRACK has already
	 * been executed, so CPUs running in the new mm will enter the enclave
	 * in a different epoch.
	 */
	cpumask_clear(cpumask);

	idx = srcu_read_lock(&encl->srcu);

	list_for_each_entry_rcu(encl_mm, &encl->mm_list, list) {
		if (!mmget_not_zero(encl_mm->mm))
			continue;

		cpumask_or(cpumask, cpumask, mm_cpumask(encl_mm->mm));

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0) || LINUX_VERSION_CODE > KERNEL_VERSION(5, 4, 0) )
		mmput(encl_mm->mm);
#else
		mmput_async(encl_mm->mm);
#endif
	}

	srcu_read_unlock(&encl->srcu, idx);

	return cpumask;
}

static void sgx_encl_ewb(struct sgx_epc_page *epc_page,
			 struct sgx_backing *backing)
{
	struct sgx_encl_page *encl_page = epc_page->owner;
	struct sgx_encl *encl = encl_page->encl;
	struct sgx_va_page *va_page;
	unsigned int va_offset;
	void *va_slot;
	int ret;

	encl_page->desc &= ~SGX_ENCL_PAGE_RECLAIMED;

	va_page = list_first_entry(&encl->va_pages, struct sgx_va_page,
				   list);
	va_offset = sgx_alloc_va_slot(va_page);
	va_slot = sgx_epc_addr(va_page->epc_page) + va_offset;
	if (sgx_va_page_full(va_page))
		list_move_tail(&va_page->list, &encl->va_pages);

	ret = __sgx_encl_ewb(epc_page, va_slot, backing);
	if (ret == SGX_NOT_TRACKED) {
		ret = __etrack(sgx_epc_addr(encl->secs.epc_page));
		if (ret) {
			if (encls_failed(ret))
				ENCLS_WARN(ret, "ETRACK");
		}

		ret = __sgx_encl_ewb(epc_page, va_slot, backing);
		if (ret == SGX_NOT_TRACKED) {
			/*
			 * Slow path, send IPIs to kick cpus out of the
			 * enclave.  Note, it's imperative that the cpu
			 * mask is generated *after* ETRACK, else we'll
			 * miss cpus that entered the enclave between
			 * generating the mask and incrementing epoch.
			 */
			on_each_cpu_mask(sgx_encl_ewb_cpumask(encl),
					 sgx_ipi_cb, NULL, 1);
			ret = __sgx_encl_ewb(epc_page, va_slot, backing);
		}
	}

	if (ret) {
		if (encls_failed(ret))
			ENCLS_WARN(ret, "EWB");

		sgx_free_va_slot(va_page, va_offset);
	} else {
		encl_page->desc |= va_offset;
		encl_page->va_page = va_page;
	}
}

static void sgx_reclaimer_write(struct sgx_epc_page *epc_page,
				struct sgx_backing *backing)
{
	struct sgx_encl_page *encl_page = epc_page->owner;
	struct sgx_encl *encl = encl_page->encl;
	struct sgx_backing secs_backing;
	int ret;

	mutex_lock(&encl->lock);

	if (atomic_read(&encl->flags) & SGX_ENCL_DEAD) {
		ret = __eremove(sgx_epc_addr(epc_page));
		WARN(ret, "EREMOVE returned %d\n", ret);
	} else {
		sgx_encl_ewb(epc_page, backing);
	}

	encl_page->epc_page = NULL;
	encl->secs_child_cnt--;

	if (!encl->secs_child_cnt) {
		if (atomic_read(&encl->flags) & SGX_ENCL_DEAD) {
			sgx_free_page(encl->secs.epc_page);
			encl->secs.epc_page = NULL;
		} else if (atomic_read(&encl->flags) & SGX_ENCL_INITIALIZED) {
			ret = sgx_encl_get_backing(encl, PFN_DOWN(encl->size),
						   &secs_backing);
			if (ret)
				goto out;

			sgx_encl_ewb(encl->secs.epc_page, &secs_backing);

			sgx_free_page(encl->secs.epc_page);
			encl->secs.epc_page = NULL;

			sgx_encl_put_backing(&secs_backing, true);
		}
	}

out:
	mutex_unlock(&encl->lock);
}

/**
 * sgx_reclaim_pages() - Reclaim EPC pages from the consumers
 *
 * Take a fixed number of pages from the head of the active page pool and
 * reclaim them to the enclave's private shmem files. Skip the pages, which
 * have been accessed since the last scan. Move those pages to the tail of
 * active page pool so that the pages get scanned in LRU like fashion.
 */
void sgx_reclaim_pages(void)
{
	struct sgx_epc_page *chunk[SGX_NR_TO_SCAN];
	struct sgx_backing backing[SGX_NR_TO_SCAN];
	struct sgx_epc_section *section;
	struct sgx_encl_page *encl_page;
	struct sgx_epc_page *epc_page;
	int cnt = 0;
	int ret;
	int i;

	spin_lock(&sgx_active_page_list_lock);
	for (i = 0; i < SGX_NR_TO_SCAN; i++) {
		if (list_empty(&sgx_active_page_list))
			break;

		epc_page = list_first_entry(&sgx_active_page_list,
					    struct sgx_epc_page, list);
		list_del_init(&epc_page->list);
		encl_page = epc_page->owner;

		if (kref_get_unless_zero(&encl_page->encl->refcount) != 0)
			chunk[cnt++] = epc_page;
		else
			/* The owner is freeing the page. No need to add the
			 * page back to the list of reclaimable pages.
			 */
			epc_page->desc &= ~SGX_EPC_PAGE_RECLAIMABLE;
	}
	spin_unlock(&sgx_active_page_list_lock);

	for (i = 0; i < cnt; i++) {
		epc_page = chunk[i];
		encl_page = epc_page->owner;

		if (!sgx_reclaimer_age(epc_page))
			goto skip;

		ret = sgx_encl_get_backing(encl_page->encl,
					   SGX_ENCL_PAGE_INDEX(encl_page),
					   &backing[i]);
		if (ret)
			goto skip;

		mutex_lock(&encl_page->encl->lock);
		encl_page->desc |= SGX_ENCL_PAGE_RECLAIMED;
		mutex_unlock(&encl_page->encl->lock);
		continue;

skip:
		kref_put(&encl_page->encl->refcount, sgx_encl_release);

		spin_lock(&sgx_active_page_list_lock);
		list_add_tail(&epc_page->list, &sgx_active_page_list);
		spin_unlock(&sgx_active_page_list_lock);

		chunk[i] = NULL;
	}

	for (i = 0; i < cnt; i++) {
		epc_page = chunk[i];
		if (epc_page)
			sgx_reclaimer_block(epc_page);
	}

	for (i = 0; i < cnt; i++) {
		epc_page = chunk[i];
		if (!epc_page)
			continue;

		encl_page = epc_page->owner;
		sgx_reclaimer_write(epc_page, &backing[i]);
		sgx_encl_put_backing(&backing[i], true);

		kref_put(&encl_page->encl->refcount, sgx_encl_release);
		epc_page->desc &= ~SGX_EPC_PAGE_RECLAIMABLE;

		section = sgx_epc_section(epc_page);
		spin_lock(&section->lock);
		list_add_tail(&epc_page->list, &section->page_list);
		section->free_cnt++;
		spin_unlock(&section->lock);
	}
}
