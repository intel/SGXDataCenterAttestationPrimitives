// This file is provided under a dual BSD/GPLv2 license.  When using or
// redistributing this file, you may do so under either license.
//
// GPL LICENSE SUMMARY
//
// Copyright(c) 2016-2018 Intel Corporation.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of version 2 of the GNU General Public License as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// Contact Information:
// Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
// Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
//
// BSD LICENSE
//
// Copyright(c) 2016-2018 Intel Corporation.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//   * Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//   * Neither the name of Intel Corporation nor the names of its
//     contributors may be used to endorse or promote products derived
//     from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Authors:
//
// Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
// Suresh Siddha <suresh.b.siddha@intel.com>
// Serge Ayoun <serge.ayoun@intel.com>
// Shay Katz-zamir <shay.katz-zamir@intel.com>
// Sean Christopherson <sean.j.christopherson@intel.com>

#include <linux/device.h>
#include <linux/freezer.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/ratelimit.h>
#include <linux/version.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include "sgx.h"

#define SGX_NR_LOW_PAGES 32
#define SGX_NR_HIGH_PAGES 64
#define SGX_NR_TO_SCAN	16

LIST_HEAD(sgx_encl_list);
DEFINE_MUTEX(sgx_encl_list_lock);
atomic_t sgx_va_pages_cnt = ATOMIC_INIT(0);

struct sgx_epc_bank {
	unsigned long pa;
	unsigned long va;
	unsigned long size;
	void **pages;
	atomic_t free_cnt;
	struct rw_semaphore lock;
};

static struct sgx_epc_bank sgx_epc_banks[SGX_MAX_EPC_BANKS];
static int sgx_nr_epc_banks;
static unsigned int sgx_nr_total_pages;
static atomic_t sgx_nr_free_pages = ATOMIC_INIT(0);
static struct task_struct *ksgxswapd_tsk;
static DECLARE_WAIT_QUEUE_HEAD(ksgxswapd_waitq);

static int sgx_test_and_clear_young_cb(pte_t *ptep,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0))
				pgtable_t token,
#endif
				unsigned long addr, void *data)
{
	pte_t pte;
	int ret;

	ret = pte_young(*ptep);
	if (ret) {
		pte = pte_mkold(*ptep);
		set_pte_at((struct mm_struct *)data, addr, ptep, pte);
	}

	return ret;
}

/**
 * sgx_test_and_clear_young() - Test and reset the accessed bit
 * @page:	enclave page to be tested for recent access
 *
 * Checks the Access (A) bit from the PTE corresponding to the
 * enclave page and clears it.  Returns 1 if the page has been
 * recently accessed and 0 if not.
 */
int sgx_test_and_clear_young(struct sgx_encl_page *page)
{
	unsigned long addr = SGX_ENCL_PAGE_ADDR(page);
	struct sgx_encl *encl = page->encl;
	struct vm_area_struct *vma;
	int ret;

	ret = sgx_encl_find(encl->mm, addr, &vma);
	if (ret)
		return 0;

	if (encl != vma->vm_private_data)
		return 0;

	return apply_to_page_range(vma->vm_mm, addr, PAGE_SIZE,
				   sgx_test_and_clear_young_cb, vma->vm_mm);
}

static struct sgx_encl *sgx_isolate_encl(void)
{
	struct sgx_encl *encl = NULL;
	int i;

	mutex_lock(&sgx_encl_list_lock);

	if (list_empty(&sgx_encl_list)) {
		mutex_unlock(&sgx_encl_list_lock);
		return NULL;
	}

	for (i = 0; i < SGX_NR_TO_SCAN; i++) {
		encl = list_first_entry(&sgx_encl_list, struct sgx_encl,
					encl_list);

		list_move_tail(&encl->encl_list, &sgx_encl_list);

		/* Select a victim with faulted pages and a valid refcount. */
		if (!list_empty(&encl->load_list) &&
		    kref_get_unless_zero(&encl->refcount))
			break;

		encl = NULL;
	}

	mutex_unlock(&sgx_encl_list_lock);

	return encl;
}

static void sgx_isolate_pages(struct sgx_encl *encl,
			      struct sgx_encl_page **cluster)
{
	struct sgx_encl_page *entry;
	int i;

	mutex_lock(&encl->lock);

	if (encl->flags & SGX_ENCL_DEAD)
		goto out;

	for (i = 0; i < SGX_NR_TO_SCAN; i++) {
		if (list_empty(&encl->load_list))
			break;

		entry = list_first_entry(&encl->load_list, struct sgx_encl_page,
					 list);

		if (!sgx_test_and_clear_young(entry) &&
		    !(entry->desc & SGX_ENCL_PAGE_RESERVED)) {
			entry->desc |= SGX_ENCL_PAGE_RESERVED;
			list_del(&entry->list);
			entry->desc &= ~SGX_ENCL_PAGE_LOADED;
			*cluster++ = entry;
		} else {
			list_move_tail(&entry->list, &encl->load_list);
		}
	}
out:
	*cluster = NULL;
	mutex_unlock(&encl->lock);
}

static int __sgx_ewb(struct sgx_encl *encl,
		     struct sgx_encl_page *encl_page,
		     struct sgx_va_page *va_page,
		     unsigned int va_offset)
{
	unsigned long pcmd_offset = SGX_ENCL_PAGE_PCMD_OFFSET(encl_page);
	struct sgx_pageinfo pginfo;
	struct page *backing;
	struct page *pcmd;
	void *epc;
	void *va;
	int ret;

	backing = sgx_get_backing(encl, encl_page, false);
	if (IS_ERR(backing)) {
		ret = PTR_ERR(backing);
		sgx_warn(encl, "pinning the backing page for EWB failed with %d\n",
			 ret);
		return ret;
	}

	pcmd = sgx_get_backing(encl, encl_page, true);
	if (IS_ERR(pcmd)) {
		ret = PTR_ERR(pcmd);
		sgx_warn(encl, "pinning the pcmd page for EWB failed with %d\n",
			 ret);
		goto out;
	}

	epc = sgx_get_page(encl_page->epc_page);
	va = sgx_get_page(va_page->epc_page);

	pginfo.srcpge = (unsigned long)kmap_atomic(backing);
	pginfo.pcmd = (unsigned long)kmap_atomic(pcmd) + pcmd_offset;
	pginfo.linaddr = 0;
	pginfo.secs = 0;
	ret = __ewb(&pginfo, epc, (void *)((unsigned long)va + va_offset));
	kunmap_atomic((void *)(unsigned long)(pginfo.pcmd - pcmd_offset));
	kunmap_atomic((void *)(unsigned long)pginfo.srcpge);

	sgx_put_page(va);
	sgx_put_page(epc);
	sgx_put_backing(pcmd, true);

out:
	sgx_put_backing(backing, true);
	return ret;
}

static void sgx_eblock(struct sgx_encl *encl, struct sgx_encl_page **cluster)
{
	struct vm_area_struct *vma;
	unsigned long addr;
	void *ptr;
	int ret;

	for ( ; *cluster; cluster++) {
		addr = SGX_ENCL_PAGE_ADDR(*cluster);

		ret = sgx_encl_find(encl->mm, addr, &vma);
		if (!ret && encl == vma->vm_private_data)
			zap_vma_ptes(vma, addr, PAGE_SIZE);

		ptr = sgx_get_page((*cluster)->epc_page);
		ret = __eblock(ptr);
		sgx_put_page(ptr);
		if (ret) {
			sgx_crit(encl, "EBLOCK returned %d\n", ret);
			sgx_invalidate(encl, true);
		}
	}
}

static void sgx_etrack(struct sgx_encl *encl)
{
	void *ptr;
	int ret;

	ptr = sgx_get_page(encl->secs.epc_page);
	ret = __etrack(ptr);
	sgx_put_page(ptr);
	if (ret) {
		sgx_crit(encl, "ETRACK returned %d\n", ret);
		sgx_invalidate(encl, true);
	}
}

static void sgx_ewb(struct sgx_encl *encl, struct sgx_encl_page *entry)
{
	struct sgx_va_page *va_page;
	unsigned int va_offset;
	int ret;

	va_page = list_first_entry(&encl->va_pages, struct sgx_va_page, list);
	va_offset = sgx_alloc_va_slot(va_page);
	if (sgx_va_page_full(va_page))
		list_move_tail(&va_page->list, &encl->va_pages);

	ret = __sgx_ewb(encl, entry, va_page, va_offset);
	if (ret == SGX_NOT_TRACKED) {
		/* slow path, IPI needed */
		sgx_flush_cpus(encl);
		ret = __sgx_ewb(encl, entry, va_page, va_offset);
	}

	if (ret) {
		sgx_invalidate(encl, true);
		if (ret > 0)
			sgx_err(encl, "EWB returned %d, enclave invalidated\n",
				ret);
	}

	sgx_free_page(entry->epc_page, encl);
	entry->desc |= va_offset;
	entry->va_page = va_page;
	entry->desc &= ~SGX_ENCL_PAGE_RESERVED;
}

static void sgx_write_pages(struct sgx_encl *encl,
			    struct sgx_encl_page **cluster)
{
	if (!*cluster)
		return;

	mutex_lock(&encl->lock);

	sgx_eblock(encl, cluster);
	sgx_etrack(encl);

	for ( ; *cluster; cluster++) {
		sgx_ewb(encl, *cluster);
		encl->secs_child_cnt--;
	}

	if (!encl->secs_child_cnt && (encl->flags & SGX_ENCL_INITIALIZED)) {
		sgx_ewb(encl, &encl->secs);
		encl->flags |= SGX_ENCL_SECS_EVICTED;
	}

	mutex_unlock(&encl->lock);
}

static void sgx_swap_pages(void)
{
	struct sgx_encl *encl;
	struct sgx_encl_page *cluster[SGX_NR_TO_SCAN + 1];

	encl = sgx_isolate_encl();
	if (!encl)
		return;

	down_read(&encl->mm->mmap_sem);
	sgx_isolate_pages(encl, cluster);
	sgx_write_pages(encl, cluster);
	up_read(&encl->mm->mmap_sem);

	kref_put(&encl->refcount, sgx_encl_release);
}

static int ksgxswapd(void *p)
{
	set_freezable();

	while (!kthread_should_stop()) {
		if (try_to_freeze())
			continue;

		wait_event_freezable(ksgxswapd_waitq, kthread_should_stop() ||
				     atomic_read(&sgx_nr_free_pages) <
				     SGX_NR_HIGH_PAGES);

		if (atomic_read(&sgx_nr_free_pages) < SGX_NR_HIGH_PAGES)
			sgx_swap_pages();
	}

	pr_info("%s: done\n", __func__);
	return 0;
}

static int sgx_init_epc_bank(unsigned long addr, unsigned long size,
			     unsigned long index, struct sgx_epc_bank *bank)
{
	unsigned long nr_pages = size >> PAGE_SHIFT;
	unsigned long i;
	void *va;

	if (IS_ENABLED(CONFIG_X86_64)) {
		va = ioremap_cache(addr, size);
		if (!va)
			return -ENOMEM;
	}

	bank->pages = kzalloc(nr_pages * sizeof(void *), GFP_KERNEL);
	if (!bank->pages) {
		if (IS_ENABLED(CONFIG_X86_64))
			iounmap(va);

		return -ENOMEM;
	}

	for (i = 0; i < nr_pages; i++)
		bank->pages[i] = (void *)((addr + (i << PAGE_SHIFT)) | index);

	bank->pa = addr;
	bank->size = size;

	if (IS_ENABLED(CONFIG_X86_64))
		bank->va = (unsigned long)va;

	atomic_set(&bank->free_cnt, nr_pages);

	init_rwsem(&bank->lock);

	sgx_nr_total_pages += nr_pages;
	atomic_add(nr_pages, &sgx_nr_free_pages);
	return 0;
}

int sgx_page_cache_init(struct device *parent)
{
	struct task_struct *tsk;
	unsigned long size;
	unsigned int eax = 0;
	unsigned int ebx = 0;
	unsigned int ecx = 0;
	unsigned int edx = 0;
	unsigned long pa;
	int i;
	int ret;

	for (i = 0; i < SGX_MAX_EPC_BANKS; i++) {
		cpuid_count(SGX_CPUID, i + SGX_CPUID_EPC_BANKS, &eax, &ebx,
			    &ecx, &edx);
		if (!(eax & 0xf))
			break;

		pa = ((u64)(ebx & 0xfffff) << 32) + (u64)(eax & 0xfffff000);
		size = ((u64)(edx & 0xfffff) << 32) + (u64)(ecx & 0xfffff000);

		dev_info(parent, "EPC bank 0x%lx-0x%lx\n", pa, pa + size);

		ret = sgx_init_epc_bank(pa, size, i, &sgx_epc_banks[i]);
		if (ret)
			return ret;

		sgx_nr_epc_banks++;
	}

	tsk = kthread_run(ksgxswapd, NULL, "ksgxswapd");
	if (IS_ERR(tsk)) {
		sgx_page_cache_teardown();
		return PTR_ERR(tsk);
	}

	ksgxswapd_tsk = tsk;
	return 0;
}

void sgx_page_cache_teardown(void)
{
	struct sgx_epc_bank *bank;
	int i;

	if (ksgxswapd_tsk) {
		kthread_stop(ksgxswapd_tsk);
		ksgxswapd_tsk = NULL;
	}

	for (i = 0; i < sgx_nr_epc_banks; i++) {
		bank = &sgx_epc_banks[i];

		if (IS_ENABLED(CONFIG_X86_64))
			iounmap((void *)bank->va);

		kfree(bank->pages);
	}
}

static void *sgx_try_alloc_page(void)
{
	struct sgx_epc_bank *bank;
	void *page = NULL;
	int i;

	for (i = 0; i < sgx_nr_epc_banks; i++) {
		bank = &sgx_epc_banks[i];

		down_write(&bank->lock);

		if (atomic_read(&bank->free_cnt))
			page = bank->pages[atomic_dec_return(&bank->free_cnt)];

		up_write(&bank->lock);

		if (page)
			break;
	}

	if (page)
		atomic_dec(&sgx_nr_free_pages);

	return page;
}

/**
 * sgx_alloc_page - allocate an EPC page
 * @flags:	allocation flags
 *
 * Try to grab a page from the free EPC page list. If there is a free page
 * available, it is returned to the caller. If called with SGX_ALLOC_ATOMIC,
 * the function will return immediately if the list is empty. Otherwise, it
 * will swap pages up until there is a free page available. Before returning
 * the low watermark is checked and ksgxswapd is waken up if we are below it.
 *
 * Return: an EPC page or a system error code
 */
void *sgx_alloc_page(unsigned int flags)
{
	void *entry;

	for ( ; ; ) {
		entry = sgx_try_alloc_page();
		if (entry)
			break;

		/* We need at minimum two pages for the #PF handler. */
		if (atomic_read(&sgx_va_pages_cnt) > (sgx_nr_total_pages - 2))
			return ERR_PTR(-ENOMEM);

		if (flags & SGX_ALLOC_ATOMIC) {
			entry = ERR_PTR(-EBUSY);
			break;
		}

		if (signal_pending(current)) {
			entry = ERR_PTR(-ERESTARTSYS);
			break;
		}

		sgx_swap_pages();
		schedule();
	}

	if (atomic_read(&sgx_nr_free_pages) < SGX_NR_LOW_PAGES)
		wake_up(&ksgxswapd_waitq);

	return entry;
}

/**
 * sgx_free_page - free an EPC page
 *
 * EREMOVE an EPC page and insert it back to the list of free pages.
 * If EREMOVE fails, the error is printed out loud as a critical error.
 * It is an indicator of a driver bug if that would happen.
 *
 * @page:	any EPC page
 * @encl:	enclave that owns the given EPC page
 */
void sgx_free_page(void *page, struct sgx_encl *encl)
{
	struct sgx_epc_bank *bank = SGX_EPC_BANK(page);
	void *va;
	int ret;

	va = sgx_get_page(page);
	ret = __eremove(va);
	sgx_put_page(va);

	if (ret)
		sgx_crit(encl, "EREMOVE returned %d\n", ret);

	down_read(&bank->lock);
	bank->pages[atomic_inc_return(&bank->free_cnt) - 1] = page;
	up_read(&bank->lock);

	atomic_inc(&sgx_nr_free_pages);
}

void *sgx_get_page(void *page)
{
	struct sgx_epc_bank *bank = SGX_EPC_BANK(page);

	if (IS_ENABLED(CONFIG_X86_64))
		return (void *)(bank->va + SGX_EPC_ADDR(page) - bank->pa);

	return kmap_atomic_pfn(SGX_EPC_PFN(page));
}

void sgx_put_page(void *ptr)
{
	if (IS_ENABLED(CONFIG_X86_64))
		return;

	kunmap_atomic(ptr);
}
