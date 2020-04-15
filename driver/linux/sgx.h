/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
#ifndef _X86_SGX_H
#define _X86_SGX_H

#include <linux/bitops.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/rwsem.h>
#include <linux/types.h>
#include <asm/asm.h>
#include "arch.h"

#undef pr_fmt
#define pr_fmt(fmt) "sgx: " fmt

struct sgx_epc_page {
	unsigned long desc;
	struct sgx_encl_page *owner;
	struct list_head list;
};

/**
 * struct sgx_epc_section
 *
 * The firmware can define multiple chunks of EPC to the different areas of the
 * physical memory e.g. for memory areas of the each node. This structure is
 * used to store EPC pages for one EPC section and virtual memory area where
 * the pages have been mapped.
 */
struct sgx_epc_section {
	unsigned long pa;
	void *va;
	unsigned long free_cnt;
	struct list_head page_list;
	struct list_head unsanitized_page_list;
	spinlock_t lock;
};

/**
 * enum sgx_epc_page_desc - bits and masks for an EPC page's descriptor
 * %SGX_EPC_SECTION_MASK:	SGX allows to have multiple EPC sections in the
 *				physical memory. The existing and near-future
 *				hardware defines at most eight sections, hence
 *				three bits to hold a section.
 * %SGX_EPC_PAGE_RECLAIMABLE:	The page has been been marked as reclaimable.
 *				Pages need to be colored this way because a page
 *				can be out of the active page list in the
 *				process of being swapped out.
 */
enum sgx_epc_page_desc {
	SGX_EPC_SECTION_MASK			= GENMASK_ULL(3, 0),
	SGX_EPC_PAGE_RECLAIMABLE		= BIT(4),
	/* bits 12-63 are reserved for the physical page address of the page */
};

#define SGX_MAX_EPC_SECTIONS (SGX_EPC_SECTION_MASK + 1)

extern struct sgx_epc_section sgx_epc_sections[SGX_MAX_EPC_SECTIONS];

static inline struct sgx_epc_section *sgx_epc_section(struct sgx_epc_page *page)
{
	return &sgx_epc_sections[page->desc & SGX_EPC_SECTION_MASK];
}

static inline void *sgx_epc_addr(struct sgx_epc_page *page)
{
	struct sgx_epc_section *section = sgx_epc_section(page);

	return section->va + (page->desc & PAGE_MASK) - section->pa;
}

#define SGX_NR_TO_SCAN		16
#define SGX_NR_LOW_PAGES	32
#define SGX_NR_HIGH_PAGES	64

extern int sgx_nr_epc_sections;
extern struct task_struct *ksgxswapd_tsk;
extern struct wait_queue_head(ksgxswapd_waitq);
extern struct list_head sgx_active_page_list;
extern spinlock_t sgx_active_page_list_lock;

static inline unsigned long sgx_nr_free_pages(void)
{
	unsigned long cnt = 0;
	int i;

	for (i = 0; i < sgx_nr_epc_sections; i++)
		cnt += sgx_epc_sections[i].free_cnt;

	return cnt;
}

static inline bool sgx_should_reclaim(unsigned long watermark)
{
	return sgx_nr_free_pages() < watermark &&
	       !list_empty(&sgx_active_page_list);
}

bool __init sgx_page_reclaimer_init(void);
void sgx_mark_page_reclaimable(struct sgx_epc_page *page);
int sgx_unmark_page_reclaimable(struct sgx_epc_page *page);
void sgx_reclaim_pages(void);

struct sgx_epc_page *sgx_try_alloc_page(void);
struct sgx_epc_page *sgx_alloc_page(void *owner, bool reclaim);
void sgx_free_page(struct sgx_epc_page *page);

#endif /* _X86_SGX_H */
