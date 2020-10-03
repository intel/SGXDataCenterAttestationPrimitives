// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.

#include <linux/freezer.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>
#include <linux/ratelimit.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include "driver.h"
#include "encl.h"
#include "encls.h"

#include <linux/module.h>
#include "version.h"
#include "dcap.h"
#ifndef MSR_IA32_FEAT_CTL
#define MSR_IA32_FEAT_CTL MSR_IA32_FEATURE_CONTROL
#endif

#ifndef FEAT_CTL_LOCKED
#define FEAT_CTL_LOCKED FEATURE_CONTROL_LOCKED
#endif
struct sgx_epc_section sgx_epc_sections[SGX_MAX_EPC_SECTIONS];
static int sgx_nr_epc_sections;
static struct task_struct *ksgxswapd_tsk;
static DECLARE_WAIT_QUEUE_HEAD(ksgxswapd_waitq);
static LIST_HEAD(sgx_active_page_list);
static DEFINE_SPINLOCK(sgx_active_page_list_lock);

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
	struct mm_struct *mm;
	bool ret = true;
	int idx;

	idx = srcu_read_lock(&encl->srcu);

	list_for_each_entry_rcu(encl_mm, &encl->mm_list, list) {
		if (!mmget_not_zero(encl_mm->mm))
			continue;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0))
                mmap_read_lock(encl_mm->mm);
#else
		down_read(&encl_mm->mm->mmap_sem);
#endif
		ret = !sgx_encl_test_and_clear_young(encl_mm->mm, page);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0))
                mmap_read_unlock(encl_mm->mm);
#else
		up_read(&encl_mm->mm->mmap_sem);
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0) )
		mm = encl_mm->mm;
		srcu_read_unlock(&encl->srcu, idx);
		mmput(mm);
		idx = srcu_read_lock(&encl->srcu);
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
	unsigned long mm_list_version;
	struct sgx_encl_mm *encl_mm;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	int idx, ret;

	do {
		mm_list_version = encl->mm_list_version;

		/* Pairs with smp_rmb() in sgx_encl_mm_add(). */
		smp_rmb();

		idx = srcu_read_lock(&encl->srcu);

		list_for_each_entry_rcu(encl_mm, &encl->mm_list, list) {
			if (!mmget_not_zero(encl_mm->mm))
				continue;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0))
			mmap_read_lock(encl_mm->mm);
#else
			down_read(&encl_mm->mm->mmap_sem);
#endif

			ret = sgx_encl_find(encl_mm->mm, addr, &vma);
			if (!ret && encl == vma->vm_private_data)
				zap_vma_ptes(vma, addr, PAGE_SIZE);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0))
			mmap_read_unlock(encl_mm->mm);
#else
			up_read(&encl_mm->mm->mmap_sem);
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0) )
			mm = encl_mm->mm;
			srcu_read_unlock(&encl->srcu, idx);
			mmput(mm);
			idx = srcu_read_lock(&encl->srcu);
#else
			mmput_async(encl_mm->mm);
#endif
		}

		srcu_read_unlock(&encl->srcu, idx);
	} while (unlikely(encl->mm_list_version != mm_list_version));

	mutex_lock(&encl->lock);

	if (!(atomic_read(&encl->flags) & SGX_ENCL_DEAD)) {
		ret = __eblock(sgx_get_epc_addr(epc_page));
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

	ret = __ewb(&pginfo, sgx_get_epc_addr(epc_page), va_slot);

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
	struct mm_struct *mm;
	int idx;

	/*
	 * Can race with sgx_encl_mm_add(), but ETRACK has already been
	 * executed, which means that the CPUs running in the new mm will enter
	 * into the enclave with a fresh epoch.
	 */
	cpumask_clear(cpumask);

	idx = srcu_read_lock(&encl->srcu);

	list_for_each_entry_rcu(encl_mm, &encl->mm_list, list) {
		if (!mmget_not_zero(encl_mm->mm))
			continue;

		cpumask_or(cpumask, cpumask, mm_cpumask(encl_mm->mm));

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0) )
		mm = encl_mm->mm;
		srcu_read_unlock(&encl->srcu, idx);
		mmput(mm);
		idx = srcu_read_lock(&encl->srcu);
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
	va_slot = sgx_get_epc_addr(va_page->epc_page) + va_offset;
	if (sgx_va_page_full(va_page))
		list_move_tail(&va_page->list, &encl->va_pages);

	ret = __sgx_encl_ewb(epc_page, va_slot, backing);
	if (ret == SGX_NOT_TRACKED) {
		ret = __etrack(sgx_get_epc_addr(encl->secs.epc_page));
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
		ret = __eremove(sgx_get_epc_addr(epc_page));
		ENCLS_WARN(ret, "EREMOVE");
	} else {
		sgx_encl_ewb(epc_page, backing);
	}

	encl_page->epc_page = NULL;
	encl->secs_child_cnt--;

	if (!encl->secs_child_cnt) {
		if (atomic_read(&encl->flags) & SGX_ENCL_DEAD) {
			sgx_free_epc_page(encl->secs.epc_page);
			encl->secs.epc_page = NULL;
		} else if (atomic_read(&encl->flags) & SGX_ENCL_INITIALIZED) {
			ret = sgx_encl_get_backing(encl, PFN_DOWN(encl->size),
						   &secs_backing);
			if (ret)
				goto out;

			sgx_encl_ewb(encl->secs.epc_page, &secs_backing);

			sgx_free_epc_page(encl->secs.epc_page);
			encl->secs.epc_page = NULL;

			sgx_encl_put_backing(&secs_backing, true);
		}
	}

out:
	mutex_unlock(&encl->lock);
}

/*
 * Take a fixed number of pages from the head of the active page pool and
 * reclaim them to the enclave's private shmem files. Skip the pages, which have
 * been accessed since the last scan. Move those pages to the tail of active
 * page pool so that the pages get scanned in LRU like fashion.
 */
static void sgx_reclaim_pages(void)
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
		spin_lock(&sgx_active_page_list_lock);
		list_add_tail(&epc_page->list, &sgx_active_page_list);
		spin_unlock(&sgx_active_page_list_lock);

		kref_put(&encl_page->encl->refcount, sgx_encl_release);

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

		section = sgx_get_epc_section(epc_page);
		spin_lock(&section->lock);
		list_add_tail(&epc_page->list, &section->page_list);
		section->free_cnt++;
		spin_unlock(&section->lock);
	}
}


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

		ret = __eremove(sgx_get_epc_addr(page));
		if (!ret)
			list_move(&page->list, &section->page_list);
		else
			list_move_tail(&page->list, &secs_list);

		spin_unlock(&section->lock);

		cond_resched();
	}
}

static unsigned long sgx_nr_free_pages(void)
{
	unsigned long cnt = 0;
	int i;

	for (i = 0; i < sgx_nr_epc_sections; i++)
		cnt += sgx_epc_sections[i].free_cnt;

	return cnt;
}

static bool sgx_should_reclaim(unsigned long watermark)
{
	return sgx_nr_free_pages() < watermark &&
	       !list_empty(&sgx_active_page_list);
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

static bool __init sgx_page_reclaimer_init(void)
{
	struct task_struct *tsk;

	tsk = kthread_run(ksgxswapd, NULL, "ksgxswapd");
	if (IS_ERR(tsk))
		return false;

	ksgxswapd_tsk = tsk;

	return true;
}

// Based on arch/x86/kernel/cpu/intel.c
static bool detect_sgx(struct cpuinfo_x86 *c)
{
    unsigned long long fc;

    rdmsrl(MSR_IA32_FEAT_CTL, fc);
    if (!(fc & FEAT_CTL_LOCKED)) {
        pr_err_once("sgx: The feature control MSR is not locked\n");
        return false;
    }

    if (!(fc & FEAT_CTL_SGX_ENABLED)) {
        pr_err_once("sgx: SGX is not enabled in IA32_FEATURE_CONTROL MSR\n");
        return false;
    }

    if (!cpu_has(c, X86_FEATURE_SGX)) {
        pr_err_once("sgx: SGX1 instruction set is not supported\n");
        return false;
    }

    if (!(fc & FEAT_CTL_SGX_LC_ENABLED)) {
        pr_info_once("sgx: The launch control MSRs are not writable\n");
        return false;
    }

    return true;
}


static struct sgx_epc_page *__sgx_alloc_epc_page_from_section(struct sgx_epc_section *section)
{
	struct sgx_epc_page *page;

	if (list_empty(&section->page_list))
		return NULL;

	page = list_first_entry(&section->page_list, struct sgx_epc_page, list);
	list_del_init(&page->list);
	section->free_cnt--;

	return page;
}

/**
 * __sgx_alloc_epc_page() - Allocate an EPC page
 *
 * Iterate through EPC sections and borrow a free EPC page to the caller. When a
 * page is no longer needed it must be released with sgx_free_epc_page().
 *
 * Return:
 *   an EPC page,
 *   -errno on error
 */
struct sgx_epc_page *__sgx_alloc_epc_page(void)
{
	struct sgx_epc_section *section;
	struct sgx_epc_page *page;
	int i;

	for (i = 0; i < sgx_nr_epc_sections; i++) {
		section = &sgx_epc_sections[i];
		spin_lock(&section->lock);
		page = __sgx_alloc_epc_page_from_section(section);
		spin_unlock(&section->lock);

		if (page)
			return page;
	}

	return ERR_PTR(-ENOMEM);
}


/**
 * sgx_alloc_epc_page() - Allocate an EPC page
 * @owner:	the owner of the EPC page
 * @reclaim:	reclaim pages if necessary
 *
 * Iterate through EPC sections and borrow a free EPC page to the caller. When a
 * page is no longer needed it must be released with sgx_free_epc_page(). If
 * @reclaim is set to true, directly reclaim pages when we are out of pages. No
 * mm's can be locked when @reclaim is set to true.
 *
 * Finally, wake up ksgxswapd when the number of pages goes below the watermark
 * before returning back to the caller.
 *
 * Return:
 *   an EPC page,
 *   -errno on error
 */
struct sgx_epc_page *sgx_alloc_epc_page(void *owner, bool reclaim)
{
	struct sgx_epc_page *entry;

	for ( ; ; ) {
		entry = __sgx_alloc_epc_page();
		if (!IS_ERR(entry)) {
			entry->owner = owner;
			break;
		}

		if (list_empty(&sgx_active_page_list))
			return ERR_PTR(-ENOMEM);

		if (!reclaim) {
			entry = ERR_PTR(-EBUSY);
			break;
		}

		if (signal_pending(current)) {
			entry = ERR_PTR(-ERESTARTSYS);
			break;
		}

		sgx_reclaim_pages();
		schedule();
	}

	if (sgx_should_reclaim(SGX_NR_LOW_PAGES))
		wake_up(&ksgxswapd_waitq);

	return entry;
}

/**
 * sgx_free_epc_page() - Free an EPC page
 * @page:	an EPC page
 *
 * Call EREMOVE for an EPC page and insert it back to the list of free pages.
 */
void sgx_free_epc_page(struct sgx_epc_page *page)
{
	struct sgx_epc_section *section = sgx_get_epc_section(page);
	int ret;

	/*
	 * Don't take sgx_active_page_list_lock when asserting the page isn't
	 * reclaimable, missing a WARN in the very rare case is preferable to
	 * unnecessarily taking a global lock in the common case.
	 */
	WARN_ON_ONCE(page->desc & SGX_EPC_PAGE_RECLAIMABLE);

	ret = __eremove(sgx_get_epc_addr(page));
	if (WARN_ONCE(ret, "EREMOVE returned %d (0x%x)", ret, ret))
		return;

	spin_lock(&section->lock);
	list_add_tail(&page->list, &section->page_list);
	section->free_cnt++;
	spin_unlock(&section->lock);
}

static void sgx_free_epc_section(struct sgx_epc_section *section)
{
	struct sgx_epc_page *page;

	while (!list_empty(&section->page_list)) {
		page = list_first_entry(&section->page_list,
					struct sgx_epc_page, list);
		list_del(&page->list);
		kfree(page);
	}

	while (!list_empty(&section->unsanitized_page_list)) {
		page = list_first_entry(&section->unsanitized_page_list,
					struct sgx_epc_page, list);
		list_del(&page->list);
		kfree(page);
	}

	memunmap(section->va);
}

static bool __init sgx_setup_epc_section(u64 addr, u64 size,
					 unsigned long index,
					 struct sgx_epc_section *section)
{
	unsigned long nr_pages = size >> PAGE_SHIFT;
	struct sgx_epc_page *page;
	unsigned long i;

	section->va = memremap(addr, size, MEMREMAP_WB);
	if (!section->va)
		return false;

	section->pa = addr;
	spin_lock_init(&section->lock);
	INIT_LIST_HEAD(&section->page_list);
	INIT_LIST_HEAD(&section->unsanitized_page_list);

	for (i = 0; i < nr_pages; i++) {
		page = kzalloc(sizeof(*page), GFP_KERNEL);
		if (!page)
			goto err_out;

		page->desc = (addr + (i << PAGE_SHIFT)) | index;
		list_add_tail(&page->list, &section->unsanitized_page_list);
	}

	section->free_cnt = nr_pages;
	return true;

err_out:
	sgx_free_epc_section(section);
	return false;
}

static void sgx_page_cache_teardown(void)
{
	int i;

	for (i = 0; i < sgx_nr_epc_sections; i++)
		sgx_free_epc_section(&sgx_epc_sections[i]);
}

/**
 * A section metric is concatenated in a way that @low bits 12-31 define the
 * bits 12-31 of the metric and @high bits 0-19 define the bits 32-51 of the
 * metric.
 */
static inline u64 __init sgx_calc_section_metric(u64 low, u64 high)
{
	return (low & GENMASK_ULL(31, 12)) +
	       ((high & GENMASK_ULL(19, 0)) << 32);
}

static bool __init sgx_page_cache_init(void)
{
	u32 eax, ebx, ecx, edx, type;
	u64 pa, size;
	int i;

	for (i = 0; i < ARRAY_SIZE(sgx_epc_sections); i++) {
		cpuid_count(SGX_CPUID, i + SGX_CPUID_FIRST_VARIABLE_SUB_LEAF,
			    &eax, &ebx, &ecx, &edx);

		type = eax & SGX_CPUID_SUB_LEAF_TYPE_MASK;
		if (type == SGX_CPUID_SUB_LEAF_INVALID)
			break;

		if (type != SGX_CPUID_SUB_LEAF_EPC_SECTION) {
			pr_err_once("Unknown EPC section type: %u\n", type);
			break;
		}

		pa = sgx_calc_section_metric(eax, ebx);
		size = sgx_calc_section_metric(ecx, edx);

		pr_info("EPC section 0x%llx-0x%llx\n", pa, pa + size - 1);

		if (!sgx_setup_epc_section(pa, size, i, &sgx_epc_sections[i])) {
			pr_err("No free memory for an EPC section\n");
			break;
		}

		sgx_nr_epc_sections++;
	}

	if (!sgx_nr_epc_sections) {
		pr_err("There are zero EPC sections.\n");
		return false;
	}

	return true;
}

static int __init sgx_init(void)
{
	int ret;

	if (!detect_sgx(&boot_cpu_data))
		return -ENODEV;

	if (!sgx_page_cache_init())
		return -EFAULT;

	if (!sgx_page_reclaimer_init())
		goto err_page_cache;

	ret = sgx_drv_init();
	if (ret)
		goto err_kthread;

	pr_info("intel_sgx: " DRV_DESCRIPTION " v" DRV_VERSION "\n");

	return 0;

err_kthread:
	kthread_stop(ksgxswapd_tsk);

err_page_cache:
	sgx_page_cache_teardown();
	return -EFAULT;
}
module_init(sgx_init);

static void __exit sgx_exit(void)
{
	sgx_drv_exit();
	kthread_stop(ksgxswapd_tsk);
	sgx_page_cache_teardown();
}
module_exit(sgx_exit);
