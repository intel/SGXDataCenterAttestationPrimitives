// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.

#include <linux/freezer.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include "driver.h"
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
int sgx_nr_epc_sections;

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
static struct sgx_epc_page *__sgx_try_alloc_page(struct sgx_epc_section *section)
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
 * sgx_try_alloc_page() - Allocate an EPC page
 *
 * Try to grab a page from the free EPC page list.
 *
 * Return:
 *   a pointer to a &struct sgx_epc_page instance,
 *   -errno on error
 */
struct sgx_epc_page *sgx_try_alloc_page(void)
{
	struct sgx_epc_section *section;
	struct sgx_epc_page *page;
	int i;

	for (i = 0; i < sgx_nr_epc_sections; i++) {
		section = &sgx_epc_sections[i];
		spin_lock(&section->lock);
		page = __sgx_try_alloc_page(section);
		spin_unlock(&section->lock);

		if (page)
			return page;
	}

	return ERR_PTR(-ENOMEM);
}

/**
 * sgx_alloc_page() - Allocate an EPC page
 * @owner:	the owner of the EPC page
 * @reclaim:	reclaim pages if necessary
 *
 * Try to grab a page from the free EPC page list. If there is a free page
 * available, it is returned to the caller. The @reclaim parameter hints
 * the EPC memory manager to swap pages when required.
 *
 * Return:
 *   a pointer to a &struct sgx_epc_page instance,
 *   -errno on error
 */
struct sgx_epc_page *sgx_alloc_page(void *owner, bool reclaim)
{
	struct sgx_epc_page *entry;

	for ( ; ; ) {
		entry = sgx_try_alloc_page();
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
 * sgx_free_page() - Free an EPC page
 * @page:	pointer a previously allocated EPC page
 *
 * EREMOVE an EPC page and insert it back to the list of free pages. The page
 * must not be reclaimable.
 */
void sgx_free_page(struct sgx_epc_page *page)
{
	struct sgx_epc_section *section = sgx_epc_section(page);
	int ret;

	/*
	 * Don't take sgx_active_page_list_lock when asserting the page isn't
	 * reclaimable, missing a WARN in the very rare case is preferable to
	 * unnecessarily taking a global lock in the common case.
	 */
	WARN_ON_ONCE(page->desc & SGX_EPC_PAGE_RECLAIMABLE);

	ret = __eremove(sgx_epc_addr(page));
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

static bool __init sgx_alloc_epc_section(u64 addr, u64 size,
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

	for (i = 0; i <= ARRAY_SIZE(sgx_epc_sections); i++) {
		cpuid_count(SGX_CPUID, i + SGX_CPUID_FIRST_VARIABLE_SUB_LEAF,
			    &eax, &ebx, &ecx, &edx);

		type = eax & SGX_CPUID_SUB_LEAF_TYPE_MASK;
		if (type == SGX_CPUID_SUB_LEAF_INVALID)
			break;

		if (type != SGX_CPUID_SUB_LEAF_EPC_SECTION) {
			pr_err_once("Unknown EPC section type: %u\n", type);
			break;
		}

		if (i == ARRAY_SIZE(sgx_epc_sections)) {
			pr_warn("No free slot for an EPC section\n");
			break;
		}

		pa = sgx_calc_section_metric(eax, ebx);
		size = sgx_calc_section_metric(ecx, edx);

		pr_info("EPC section 0x%llx-0x%llx\n", pa, pa + size - 1);

		if (!sgx_alloc_epc_section(pa, size, i, &sgx_epc_sections[i])) {
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
