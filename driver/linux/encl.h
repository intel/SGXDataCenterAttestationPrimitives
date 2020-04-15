/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/**
 * Copyright(c) 2016-19 Intel Corporation.
 */
#ifndef _X86_ENCL_H
#define _X86_ENCL_H

#include <linux/version.h>
#include <linux/cpumask.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/mm_types.h>
#include <linux/mmu_notifier.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/radix-tree.h>
#include <linux/srcu.h>
#include <linux/workqueue.h>
#include "sgx.h"

/**
 * enum sgx_encl_page_desc - defines bits for an enclave page's descriptor
 * %SGX_ENCL_PAGE_RECLAIMED:		The page is in the process of being
 *					reclaimed.
 * %SGX_ENCL_PAGE_VA_OFFSET_MASK:	Holds the offset in the Version Array
 *					(VA) page for a swapped page.
 * %SGX_ENCL_PAGE_ADDR_MASK:		Holds the virtual address of the page.
 *
 * The page address for SECS is zero and is used by the subsystem to recognize
 * the SECS page.
 */
enum sgx_encl_page_desc {
	/* Bits 11:3 are available when the page is not swapped. */
	SGX_ENCL_PAGE_RECLAIMED		= BIT(3),
	SGX_ENCL_PAGE_VA_OFFSET_MASK	= GENMASK_ULL(11, 3),
	SGX_ENCL_PAGE_ADDR_MASK		= PAGE_MASK,
};

#define SGX_ENCL_PAGE_ADDR(page) \
	((page)->desc & SGX_ENCL_PAGE_ADDR_MASK)
#define SGX_ENCL_PAGE_VA_OFFSET(page) \
	((page)->desc & SGX_ENCL_PAGE_VA_OFFSET_MASK)
#define SGX_ENCL_PAGE_INDEX(page) \
	PFN_DOWN((page)->desc - (page)->encl->base)

struct sgx_encl_page {
	unsigned long desc;
	unsigned long vm_max_prot_bits;
	struct sgx_epc_page *epc_page;
	struct sgx_va_page *va_page;
	struct sgx_encl *encl;
};

enum sgx_encl_flags {
	SGX_ENCL_CREATED	= BIT(0),
	SGX_ENCL_INITIALIZED	= BIT(1),
	SGX_ENCL_DEBUG		= BIT(2),
	SGX_ENCL_DEAD		= BIT(3),
	SGX_ENCL_IOCTL		= BIT(4),
};

struct sgx_encl_mm {
	struct sgx_encl *encl;
	struct mm_struct *mm;
	struct list_head list;
	struct mmu_notifier mmu_notifier;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0))
	struct rcu_head rcu;
#endif
};

struct sgx_encl {
	atomic_t flags;
	u64 secs_attributes;
	u64 allowed_attributes;
	unsigned int page_cnt;
	unsigned int secs_child_cnt;
	struct mutex lock;
	struct list_head mm_list;
	spinlock_t mm_lock;
	unsigned long mm_list_gen;
	struct file *backing;
	struct kref refcount;
	struct srcu_struct srcu;
	unsigned long base;
	unsigned long size;
	unsigned long ssaframesize;
	struct list_head va_pages;
	struct radix_tree_root page_tree;
	struct sgx_encl_page secs;
	cpumask_t cpumask;
};

#define SGX_VA_SLOT_COUNT 512

struct sgx_va_page {
	struct sgx_epc_page *epc_page;
	DECLARE_BITMAP(slots, SGX_VA_SLOT_COUNT);
	struct list_head list;
};

extern const struct vm_operations_struct sgx_vm_ops;

int sgx_encl_find(struct mm_struct *mm, unsigned long addr,
		  struct vm_area_struct **vma);
void sgx_encl_destroy(struct sgx_encl *encl);
void sgx_encl_release(struct kref *ref);
int sgx_encl_mm_add(struct sgx_encl *encl, struct mm_struct *mm);
int sgx_encl_may_map(struct sgx_encl *encl, unsigned long start,
		     unsigned long end, unsigned long vm_prot_bits);

struct sgx_backing {
	pgoff_t page_index;
	struct page *contents;
	struct page *pcmd;
	unsigned long pcmd_offset;
};

int sgx_encl_get_backing(struct sgx_encl *encl, unsigned long page_index,
			 struct sgx_backing *backing);
void sgx_encl_put_backing(struct sgx_backing *backing, bool do_write);
int sgx_encl_test_and_clear_young(struct mm_struct *mm,
				  struct sgx_encl_page *page);
struct sgx_encl_page *sgx_encl_reserve_page(struct sgx_encl *encl,
					    unsigned long addr);

struct sgx_epc_page *sgx_alloc_va_page(void);
unsigned int sgx_alloc_va_slot(struct sgx_va_page *va_page);
void sgx_free_va_slot(struct sgx_va_page *va_page, unsigned int offset);
bool sgx_va_page_full(struct sgx_va_page *va_page);

#endif /* _X86_ENCL_H */
