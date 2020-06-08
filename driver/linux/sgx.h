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

/*
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

#define SGX_EPC_SECTION_MASK		GENMASK(7, 0)
#define SGX_MAX_EPC_SECTIONS		(SGX_EPC_SECTION_MASK + 1)
#define SGX_EPC_PAGE_RECLAIMABLE	BIT(8)
#define SGX_NR_TO_SCAN			16
#define SGX_NR_LOW_PAGES		32
#define SGX_NR_HIGH_PAGES		64

extern struct sgx_epc_section sgx_epc_sections[SGX_MAX_EPC_SECTIONS];

static inline struct sgx_epc_section *sgx_get_epc_section(
		struct sgx_epc_page *page)
{
	return &sgx_epc_sections[page->desc & SGX_EPC_SECTION_MASK];
}

static inline void *sgx_get_epc_addr(struct sgx_epc_page *page)
{
	struct sgx_epc_section *section = sgx_get_epc_section(page);

	return section->va + (page->desc & PAGE_MASK) - section->pa;
}

void sgx_mark_page_reclaimable(struct sgx_epc_page *page);
int sgx_unmark_page_reclaimable(struct sgx_epc_page *page);
struct sgx_epc_page *__sgx_alloc_epc_page(void);
struct sgx_epc_page *sgx_alloc_epc_page(void *owner, bool reclaim);
void sgx_free_epc_page(struct sgx_epc_page *page);

#endif /* _X86_SGX_H */
