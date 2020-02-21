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

#ifndef __ARCH_INTEL_SGX_H__
#define __ARCH_INTEL_SGX_H__

#include <crypto/hash.h>
#include <linux/kref.h>
#include <linux/mmu_notifier.h>
#include <linux/mmu_notifier.h>
#include <linux/radix-tree.h>
#include <linux/radix-tree.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <asm/sgx.h>
#include <asm/sgx_pr.h>
#include <uapi/asm/sgx.h>

#define SGX_MAX_EPC_BANKS 8

#ifndef X86_FEATURE_SGX
        #define X86_FEATURE_SGX 			(9 * 32 + 2)
#endif

#define FEATURE_CONTROL_SGX_ENABLE			(1<<18)

#ifndef MSR_IA32_FEATURE_CONTROL
    #define MSR_IA32_FEATURE_CONTROL 		0x0000003a
#endif

#ifndef FEATURE_CONTROL_SGX_LE_WR
    #define FEATURE_CONTROL_SGX_LE_WR		(1<<17)
#endif

#ifndef X86_FEATURE_SGX_LC
    #define X86_FEATURE_SGX_LC				(16*32+30) /* supports SGX launch configuration */
#endif

#ifndef MSR_IA32_FEATURE_CONFIG
	#define MSR_IA32_FEATURE_CONFIG			0x0000013C
#endif

#ifndef FEATURE_CONFIG_LOCKED
	#define FEATURE_CONFIG_LOCKED			(1<<0)
#endif

#ifndef FEATURE_CONFIG_AES_DISABLE
	#define FEATURE_CONFIG_AES_DISABLE		(1<<1)
#endif

#define FEATURE_CONFIG_AES_DISABLE_LOCKED (FEATURE_CONFIG_AES_DISABLE | FEATURE_CONFIG_LOCKED)


/* Intel SGX MSRs */
#ifndef MSR_IA32_SGXLEPUBKEYHASH0
    #define MSR_IA32_SGXLEPUBKEYHASH0	0x0000008C
    #define MSR_IA32_SGXLEPUBKEYHASH1	0x0000008D
    #define MSR_IA32_SGXLEPUBKEYHASH2	0x0000008E
    #define MSR_IA32_SGXLEPUBKEYHASH3	0x0000008F
#endif

#define SGX_EINIT_SPIN_COUNT	20
#define SGX_EINIT_SLEEP_COUNT	50
#define SGX_EINIT_SLEEP_TIME	20

#define SGX_VA_SLOT_COUNT 512
#define SGX_VA_OFFSET_MASK ((SGX_VA_SLOT_COUNT - 1) << 3)

#define SGX_EPC_BANK(epc_page) \
	(&sgx_epc_banks[(unsigned long)(epc_page) & ~PAGE_MASK])
#define SGX_EPC_PFN(epc_page) PFN_DOWN((unsigned long)(epc_page))
#define SGX_EPC_ADDR(epc_page) ((unsigned long)(epc_page) & PAGE_MASK)

enum sgx_alloc_flags {
	SGX_ALLOC_ATOMIC	= BIT(0),
};

struct sgx_va_page {
	void *epc_page;
	DECLARE_BITMAP(slots, SGX_VA_SLOT_COUNT);
	struct list_head list;
};

static inline unsigned int sgx_alloc_va_slot(struct sgx_va_page *page)
{
	int slot = find_first_zero_bit(page->slots, SGX_VA_SLOT_COUNT);

	if (slot < SGX_VA_SLOT_COUNT)
		set_bit(slot, page->slots);

	return slot << 3;
}

static inline void sgx_free_va_slot(struct sgx_va_page *page,
				    unsigned int offset)
{
	clear_bit(offset >> 3, page->slots);
}

static inline bool sgx_va_page_full(struct sgx_va_page *page)
{
	int slot = find_first_zero_bit(page->slots, SGX_VA_SLOT_COUNT);

	return slot == SGX_VA_SLOT_COUNT;
}

enum sgx_encl_page_flags {
	SGX_ENCL_PAGE_TCS	= BIT(0),
	SGX_ENCL_PAGE_RESERVED	= BIT(1),
	SGX_ENCL_PAGE_LOADED	= BIT(2),
};

#define SGX_ENCL_PAGE_ADDR(encl_page) ((encl_page)->desc & PAGE_MASK)
#define SGX_ENCL_PAGE_VA_OFFSET(encl_page) \
	((encl_page)->desc & SGX_VA_OFFSET_MASK)
#define SGX_ENCL_PAGE_PCMD_OFFSET(encl_page) \
	((PFN_DOWN((encl_page)->desc) & 31) * 128)

struct sgx_encl_page {
	unsigned long desc;
	union {
		void *epc_page;
		struct sgx_va_page *va_page;
	};
	struct sgx_encl *encl;
	struct list_head list;
};

enum sgx_encl_flags {
	SGX_ENCL_INITIALIZED	= BIT(0),
	SGX_ENCL_DEBUG		= BIT(1),
	SGX_ENCL_SECS_EVICTED	= BIT(2),
	SGX_ENCL_SUSPEND	= BIT(3),
	SGX_ENCL_DEAD		= BIT(4),
};

struct sgx_encl {
	unsigned int flags;
	uint64_t attributes;
	uint64_t allowed_attributes;
	uint64_t xfrm;
	unsigned int page_cnt;
	unsigned int secs_child_cnt;
	struct mutex lock;
	struct mm_struct *mm;
	struct file *backing;
	struct file *pcmd;
	struct list_head load_list;
	struct kref refcount;
	unsigned long base;
	unsigned long size;
	unsigned long ssaframesize;
	struct list_head va_pages;
	struct radix_tree_root page_tree;
	struct list_head add_page_reqs;
	struct work_struct add_page_work;
	struct sgx_encl_page secs;
	struct pid *tgid;
	struct list_head encl_list;
	struct mmu_notifier mmu_notifier;
};

extern struct workqueue_struct *sgx_add_page_wq;
extern u64 sgx_encl_size_max_32;
extern u64 sgx_encl_size_max_64;
extern u64 sgx_xfrm_mask;
extern u32 sgx_misc_reserved;
extern u32 sgx_xsave_size_tbl[64];
extern bool sgx_unlocked_msrs;

extern const struct file_operations sgx_fops;
extern const struct vm_operations_struct sgx_vm_ops;
extern const struct file_operations sgx_provision_fops;

int sgx_encl_find(struct mm_struct *mm, unsigned long addr,
		  struct vm_area_struct **vma);
struct sgx_encl *sgx_encl_alloc(struct sgx_secs *secs);
int sgx_encl_create(struct sgx_encl *encl, struct sgx_secs *secs);
int sgx_encl_add_page(struct sgx_encl *encl, unsigned long addr, void *data,
		      struct sgx_secinfo *secinfo, unsigned int mrmask);
int sgx_encl_init(struct sgx_encl *encl, struct sgx_sigstruct *sigstruct,
		  struct sgx_einittoken *einittoken);
void sgx_encl_release(struct kref *ref);

long sgx_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);
#ifdef CONFIG_COMPAT
long sgx_compat_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);
#endif

/* Utility functions */
int sgx_test_and_clear_young(struct sgx_encl_page *page);
struct page *sgx_get_backing(struct sgx_encl *encl,
			     struct sgx_encl_page *entry,
			     bool pcmd);
void sgx_put_backing(struct page *backing, bool write);
void sgx_insert_pte(struct sgx_encl *encl,
		    struct sgx_encl_page *encl_page,
		    void *epc_page,
		    struct vm_area_struct *vma);
int sgx_eremove(void *epc_page);
void sgx_zap_tcs_ptes(struct sgx_encl *encl,
		      struct vm_area_struct *vma);
void sgx_invalidate(struct sgx_encl *encl, bool flush_cpus);
void sgx_flush_cpus(struct sgx_encl *encl);

enum sgx_fault_flags {
	SGX_FAULT_RESERVE	= BIT(0),
};

struct sgx_encl_page *sgx_fault_page(struct vm_area_struct *vma,
				     unsigned long addr,
				     unsigned int flags);

int sgx_get_key_hash(struct crypto_shash *tfm, const void *modulus, void *hash);
int sgx_get_key_hash_simple(const void *modulus, void *hash);

extern struct mutex sgx_encl_list_lock;
extern struct list_head sgx_encl_list;
extern atomic_t sgx_va_pages_cnt;

int sgx_add_epc_bank(resource_size_t start, unsigned long size, int bank);
int sgx_page_cache_init(struct device *parent);
void sgx_page_cache_teardown(void);
void *sgx_alloc_page(unsigned int flags);
void sgx_free_page(void *page, struct sgx_encl *encl);
void *sgx_get_page(void *page);
void sgx_put_page(void *ptr);


#endif /* __ARCH_X86_INTEL_SGX_H__ */
