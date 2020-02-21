// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#include <linux/lockdep.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/shmem_fs.h>
#include <linux/suspend.h>
#include <linux/sched/mm.h>
#include "arch.h"
#include "encl.h"
#include "encls.h"
#include "sgx.h"

#include <linux/version.h>

static int __sgx_encl_eldu(struct sgx_encl_page *encl_page,
			   struct sgx_epc_page *epc_page,
			   struct sgx_epc_page *secs_page)
{
	unsigned long va_offset = SGX_ENCL_PAGE_VA_OFFSET(encl_page);
	struct sgx_encl *encl = encl_page->encl;
	struct sgx_pageinfo pginfo;
	struct sgx_backing b;
	pgoff_t page_index;
	int ret;

	if (secs_page)
		page_index = SGX_ENCL_PAGE_INDEX(encl_page);
	else
		page_index = PFN_DOWN(encl->size);

	ret = sgx_encl_get_backing(encl, page_index, &b);
	if (ret)
		return ret;

	pginfo.addr = SGX_ENCL_PAGE_ADDR(encl_page);
	pginfo.contents = (unsigned long)kmap_atomic(b.contents);
	pginfo.metadata = (unsigned long)kmap_atomic(b.pcmd) +
			  b.pcmd_offset;

	if (secs_page)
		pginfo.secs = (u64)sgx_epc_addr(secs_page);
	else
		pginfo.secs = 0;

	ret = __eldu(&pginfo, sgx_epc_addr(epc_page),
		     sgx_epc_addr(encl_page->va_page->epc_page) + va_offset);
	if (ret) {
		if (encls_failed(ret))
			ENCLS_WARN(ret, "ELDU");

		ret = -EFAULT;
	}

	kunmap_atomic((void *)(unsigned long)(pginfo.metadata - b.pcmd_offset));
	kunmap_atomic((void *)(unsigned long)pginfo.contents);

	sgx_encl_put_backing(&b, false);

	return ret;
}

static struct sgx_epc_page *sgx_encl_eldu(struct sgx_encl_page *encl_page,
					  struct sgx_epc_page *secs_page)
{
	unsigned long va_offset = SGX_ENCL_PAGE_VA_OFFSET(encl_page);
	struct sgx_encl *encl = encl_page->encl;
	struct sgx_epc_page *epc_page;
	int ret;

	epc_page = sgx_alloc_page(encl_page, false);
	if (IS_ERR(epc_page))
		return epc_page;

	ret = __sgx_encl_eldu(encl_page, epc_page, secs_page);
	if (ret) {
		sgx_free_page(epc_page);
		return ERR_PTR(ret);
	}

	sgx_free_va_slot(encl_page->va_page, va_offset);
	list_move(&encl_page->va_page->list, &encl->va_pages);
	encl_page->desc &= ~SGX_ENCL_PAGE_VA_OFFSET_MASK;
	encl_page->epc_page = epc_page;

	return epc_page;
}

static struct sgx_encl_page *sgx_encl_load_page(struct sgx_encl *encl,
						unsigned long addr)
{
	struct sgx_epc_page *epc_page;
	struct sgx_encl_page *entry;
	unsigned int flags;

	/* If process was forked, VMA is still there but vm_private_data is set
	 * to NULL.
	 */
	if (!encl)
		return ERR_PTR(-EFAULT);

	flags = atomic_read(&encl->flags);

	if ((flags & SGX_ENCL_DEAD) || !(flags & SGX_ENCL_INITIALIZED))
		return ERR_PTR(-EFAULT);

	entry = radix_tree_lookup(&encl->page_tree, addr >> PAGE_SHIFT);
	if (!entry)
		return ERR_PTR(-EFAULT);

	/* Page is already resident in the EPC. */
	if (entry->epc_page) {
		if (entry->desc & SGX_ENCL_PAGE_RECLAIMED)
			return ERR_PTR(-EBUSY);

		return entry;
	}

	if (!(encl->secs.epc_page)) {
		epc_page = sgx_encl_eldu(&encl->secs, NULL);
		if (IS_ERR(epc_page))
			return ERR_CAST(epc_page);
	}

	epc_page = sgx_encl_eldu(entry, encl->secs.epc_page);
	if (IS_ERR(epc_page))
		return ERR_CAST(epc_page);

	encl->secs_child_cnt++;
	sgx_mark_page_reclaimable(entry->epc_page);

	return entry;
}

static void sgx_mmu_notifier_release(struct mmu_notifier *mn,
				     struct mm_struct *mm)
{
	struct sgx_encl_mm *encl_mm =
		container_of(mn, struct sgx_encl_mm, mmu_notifier);
	struct sgx_encl_mm *tmp = NULL;

	/*
	 * The enclave itself can remove encl_mm.  Note, objects can't be moved
	 * off an RCU protected list, but deletion is ok.
	 */
	spin_lock(&encl_mm->encl->mm_lock);
	list_for_each_entry(tmp, &encl_mm->encl->mm_list, list) {
		if (tmp == encl_mm) {
			list_del_rcu(&encl_mm->list);
			break;
		}
	}
	spin_unlock(&encl_mm->encl->mm_lock);

	if (tmp == encl_mm) {
		synchronize_srcu(&encl_mm->encl->srcu);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0))
		mmu_notifier_put(mn);
#else
		kfree(encl_mm);
#endif
	}
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0))
static void sgx_mmu_notifier_free(struct mmu_notifier *mn)
{
	struct sgx_encl_mm *encl_mm =
		container_of(mn, struct sgx_encl_mm, mmu_notifier);

	kfree(encl_mm);
}
#endif

static const struct mmu_notifier_ops sgx_mmu_notifier_ops = {
	.release		= sgx_mmu_notifier_release,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0))
	.free_notifier		= sgx_mmu_notifier_free,
#endif
};

static struct sgx_encl_mm *sgx_encl_find_mm(struct sgx_encl *encl,
					    struct mm_struct *mm)
{
	struct sgx_encl_mm *encl_mm = NULL;
	struct sgx_encl_mm *tmp;
	int idx;

	idx = srcu_read_lock(&encl->srcu);

	list_for_each_entry_rcu(tmp, &encl->mm_list, list) {
		if (tmp->mm == mm) {
			encl_mm = tmp;
			break;
		}
	}

	srcu_read_unlock(&encl->srcu, idx);

	return encl_mm;
}

int sgx_encl_mm_add(struct sgx_encl *encl, struct mm_struct *mm)
{
	struct sgx_encl_mm *encl_mm;
	int ret;

	if (atomic_read(&encl->flags) & SGX_ENCL_DEAD)
		return -EINVAL;

	/*
	 * mm_structs are kept on mm_list until the mm or the enclave dies,
	 * i.e. once an mm is off the list, it's gone for good, therefore it's
	 * impossible to get a false positive on @mm due to a stale mm_list.
	 */
	if (sgx_encl_find_mm(encl, mm))
		return 0;

	encl_mm = kzalloc(sizeof(*encl_mm), GFP_KERNEL);
	if (!encl_mm)
		return -ENOMEM;

	encl_mm->encl = encl;
	encl_mm->mm = mm;
	encl_mm->mmu_notifier.ops = &sgx_mmu_notifier_ops;

	ret = __mmu_notifier_register(&encl_mm->mmu_notifier, mm);
	if (ret) {
		kfree(encl_mm);
		return ret;
	}

	spin_lock(&encl->mm_lock);
	list_add_rcu(&encl_mm->list, &encl->mm_list);
	spin_unlock(&encl->mm_lock);

	synchronize_srcu(&encl->srcu);

	return 0;
}

static void sgx_vma_open(struct vm_area_struct *vma)
{
	struct sgx_encl *encl = vma->vm_private_data;

	if (!encl)
		return;

	if (sgx_encl_mm_add(encl, vma->vm_mm))
		vma->vm_private_data = NULL;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,1,0))
static unsigned int sgx_vma_fault(struct vm_fault *vmf)
#else
static int sgx_vma_fault(struct vm_fault *vmf)
#endif
{
	unsigned long addr = (unsigned long)vmf->address;
	struct vm_area_struct *vma = vmf->vma;
	struct sgx_encl *encl = vma->vm_private_data;
	struct sgx_encl_page *entry;
	int ret = VM_FAULT_NOPAGE;
	unsigned long pfn;

	if (!encl)
		return VM_FAULT_SIGBUS;

	mutex_lock(&encl->lock);

	entry = sgx_encl_load_page(encl, addr);
	if (IS_ERR(entry)) {
		if (unlikely(PTR_ERR(entry) != -EBUSY))
			ret = VM_FAULT_SIGBUS;

		goto out;
	}

	if (!follow_pfn(vma, addr, &pfn))
		goto out;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
		ret = vmf_insert_pfn(vma, addr, PFN_DOWN(entry->epc_page->desc));
		if (ret != VM_FAULT_NOPAGE) {
#else
		ret = vm_insert_pfn(vma, addr, PFN_DOWN(entry->epc_page->desc));
		if (ret) {
#endif
		ret = VM_FAULT_SIGBUS;
		goto out;
	}

	sgx_encl_test_and_clear_young(vma->vm_mm, entry);

out:
	mutex_unlock(&encl->lock);
	return ret;
}

/**
 * sgx_encl_may_map() - Check if a requested VMA mapping is allowed
 * @encl:		an enclave
 * @start:		lower bound of the address range, inclusive
 * @end:		upper bound of the address range, exclusive
 * @vm_prot_bits:	requested protections of the address range
 *
 * Iterate through the enclave pages contained within [@start, @end) to verify
 * the permissions requested by @vm_prot_bits do not exceed that of any enclave
 * page to be mapped.  Page addresses that do not have an associated enclave
 * page are interpreted to zero permissions.
 *
 * Return:
 *   0 on success,
 *   -EACCES if VMA permissions exceed enclave page permissions
 */
int sgx_encl_may_map(struct sgx_encl *encl, unsigned long start,
		     unsigned long end, unsigned long vm_prot_bits)
{
	unsigned long idx, idx_start, idx_end;
	struct sgx_encl_page *page;

	/* PROT_NONE always succeeds. */
	if (!vm_prot_bits)
		return 0;

	idx_start = PFN_DOWN(start);
	idx_end = PFN_DOWN(end - 1);

	for (idx = idx_start; idx <= idx_end; ++idx) {
		mutex_lock(&encl->lock);
		page = radix_tree_lookup(&encl->page_tree, idx);
		mutex_unlock(&encl->lock);

		if (!page || (~page->vm_max_prot_bits & vm_prot_bits))
			return -EACCES;
	}

	return 0;
}

/*
static int sgx_vma_mprotect(struct vm_area_struct *vma, unsigned long start,
			    unsigned long end, unsigned long prot)
{
	return sgx_encl_may_map(vma->vm_private_data, start, end,
				calc_vm_prot_bits(prot, 0));
}
*/

static int sgx_edbgrd(struct sgx_encl *encl, struct sgx_encl_page *page,
		      unsigned long addr, void *data)
{
	unsigned long offset = addr & ~PAGE_MASK;
	int ret;


	ret = __edbgrd(sgx_epc_addr(page->epc_page) + offset, data);
	if (ret)
		return -EIO;

	return 0;
}

static int sgx_edbgwr(struct sgx_encl *encl, struct sgx_encl_page *page,
		      unsigned long addr, void *data)
{
	unsigned long offset = addr & ~PAGE_MASK;
	int ret;

	ret = __edbgwr(sgx_epc_addr(page->epc_page) + offset, data);
	if (ret)
		return -EIO;

	return 0;
}

static int sgx_vma_access(struct vm_area_struct *vma, unsigned long addr,
			  void *buf, int len, int write)
{
	struct sgx_encl *encl = vma->vm_private_data;
	struct sgx_encl_page *entry = NULL;
	char data[sizeof(unsigned long)];
	unsigned long align;
	unsigned int flags;
	int offset;
	int cnt;
	int ret = 0;
	int i;

	/* If process was forked, VMA is still there but vm_private_data is set
	 * to NULL.
	 */
	if (!encl)
		return -EFAULT;

	flags = atomic_read(&encl->flags);

	if (!(flags & SGX_ENCL_DEBUG) || !(flags & SGX_ENCL_INITIALIZED) ||
	    (flags & SGX_ENCL_DEAD))
		return -EFAULT;

	for (i = 0; i < len; i += cnt) {
		entry = sgx_encl_reserve_page(encl, (addr + i) & PAGE_MASK);
		if (IS_ERR(entry)) {
			ret = PTR_ERR(entry);
			break;
		}

		align = ALIGN_DOWN(addr + i, sizeof(unsigned long));
		offset = (addr + i) & (sizeof(unsigned long) - 1);
		cnt = sizeof(unsigned long) - offset;
		cnt = min(cnt, len - i);

		ret = sgx_edbgrd(encl, entry, align, data);
		if (ret)
			goto out;

		if (write) {
			memcpy(data + offset, buf + i, cnt);
			ret = sgx_edbgwr(encl, entry, align, data);
			if (ret)
				goto out;
		} else
			memcpy(buf + i, data + offset, cnt);

out:
		mutex_unlock(&encl->lock);

		if (ret)
			break;
	}

	return ret < 0 ? ret : i;
}

const struct vm_operations_struct sgx_vm_ops = {
	.open = sgx_vma_open,
	.fault = sgx_vma_fault,
//	.may_mprotect = sgx_vma_mprotect,
	.access = sgx_vma_access,
};

/**
 * sgx_encl_find - find an enclave
 * @mm:		mm struct of the current process
 * @addr:	address in the ELRANGE
 * @vma:	the resulting VMA
 *
 * Find an enclave identified by the given address. Give back a VMA that is
 * part of the enclave and located in that address. The VMA is given back if it
 * is a proper enclave VMA even if an &sgx_encl instance does not exist yet
 * (enclave creation has not been performed).
 *
 * Return:
 *   0 on success,
 *   -EINVAL if an enclave was not found,
 *   -ENOENT if the enclave has not been created yet
 */
int sgx_encl_find(struct mm_struct *mm, unsigned long addr,
		  struct vm_area_struct **vma)
{
	struct vm_area_struct *result;
	struct sgx_encl *encl;

	result = find_vma(mm, addr);
	if (!result || result->vm_ops != &sgx_vm_ops || addr < result->vm_start)
		return -EINVAL;

	encl = result->vm_private_data;
	*vma = result;

	return encl ? 0 : -ENOENT;
}

/**
 * sgx_encl_destroy() - destroy enclave resources
 * @encl:	an &sgx_encl instance
 */
void sgx_encl_destroy(struct sgx_encl *encl)
{
	struct sgx_va_page *va_page;
	struct sgx_encl_page *entry;
	struct radix_tree_iter iter;
	void **slot;

	atomic_or(SGX_ENCL_DEAD, &encl->flags);

	radix_tree_for_each_slot(slot, &encl->page_tree, &iter, 0) {
		entry = *slot;

		if (entry->epc_page) {
			/*
			 * The page and its radix tree entry cannot be freed
			 * if the page is being held by the reclaimer.
			 */
			if (sgx_unmark_page_reclaimable(entry->epc_page))
				continue;

			sgx_free_page(entry->epc_page);
			encl->secs_child_cnt--;
			entry->epc_page = NULL;
		}

		radix_tree_delete(&entry->encl->page_tree,
				  PFN_DOWN(entry->desc));
		kfree(entry);
	}

	if (!encl->secs_child_cnt && encl->secs.epc_page) {
		sgx_free_page(encl->secs.epc_page);
		encl->secs.epc_page = NULL;
	}

	/*
	 * The reclaimer is responsible for checking SGX_ENCL_DEAD before doing
	 * EWB, thus it's safe to free VA pages even if the reclaimer holds a
	 * reference to the enclave.
	 */
	while (!list_empty(&encl->va_pages)) {
		va_page = list_first_entry(&encl->va_pages, struct sgx_va_page,
					   list);
		list_del(&va_page->list);
		sgx_free_page(va_page->epc_page);
		kfree(va_page);
	}
}

/**
 * sgx_encl_release - Destroy an enclave instance
 * @kref:	address of a kref inside &sgx_encl
 *
 * Used together with kref_put(). Frees all the resources associated with the
 * enclave and the instance itself.
 */
void sgx_encl_release(struct kref *ref)
{
	struct sgx_encl *encl = container_of(ref, struct sgx_encl, refcount);

	sgx_encl_destroy(encl);

	if (encl->backing)
		fput(encl->backing);

	WARN_ON_ONCE(!list_empty(&encl->mm_list));

	/* Detect EPC page leak's. */
	WARN_ON_ONCE(encl->secs_child_cnt);
	WARN_ON_ONCE(encl->secs.epc_page);

	kfree(encl);
}

static struct page *sgx_encl_get_backing_page(struct sgx_encl *encl,
					      pgoff_t index)
{
	struct inode *inode = encl->backing->f_path.dentry->d_inode;
	struct address_space *mapping = inode->i_mapping;
	gfp_t gfpmask = mapping_gfp_mask(mapping);

	return shmem_read_mapping_page_gfp(mapping, index, gfpmask);
}

/**
 * sgx_encl_get_backing() - Pin the backing storage
 * @encl:	an enclave
 * @page_index:	enclave page index
 * @backing:	data for accessing backing storage for the page
 *
 * Pin the backing storage pages for storing the encrypted contents and Paging
 * Crypto MetaData (PCMD) of an enclave page.
 *
 * Return:
 *   0 on success,
 *   -errno otherwise.
 */
int sgx_encl_get_backing(struct sgx_encl *encl, unsigned long page_index,
			 struct sgx_backing *backing)
{
	pgoff_t pcmd_index = PFN_DOWN(encl->size) + 1 + (page_index >> 5);
	struct page *contents;
	struct page *pcmd;

	contents = sgx_encl_get_backing_page(encl, page_index);
	if (IS_ERR(contents))
		return PTR_ERR(contents);

	pcmd = sgx_encl_get_backing_page(encl, pcmd_index);
	if (IS_ERR(pcmd)) {
		put_page(contents);
		return PTR_ERR(pcmd);
	}

	backing->page_index = page_index;
	backing->contents = contents;
	backing->pcmd = pcmd;
	backing->pcmd_offset =
		(page_index & (PAGE_SIZE / sizeof(struct sgx_pcmd) - 1)) *
		sizeof(struct sgx_pcmd);

	return 0;
}

/**
 * sgx_encl_put_backing() - Unpin the backing storage
 * @backing:	data for accessing backing storage for the page
 * @do_write:	mark pages dirty
 */
void sgx_encl_put_backing(struct sgx_backing *backing, bool do_write)
{
	if (do_write) {
		set_page_dirty(backing->pcmd);
		set_page_dirty(backing->contents);
	}

	put_page(backing->pcmd);
	put_page(backing->contents);
}

static int sgx_encl_test_and_clear_young_cb(pte_t *ptep,
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
 * sgx_encl_test_and_clear_young() - Test and reset the accessed bit
 * @mm:		mm_struct that is checked
 * @page:	enclave page to be tested for recent access
 *
 * Checks the Access (A) bit from the PTE corresponding to the enclave page and
 * clears it.
 *
 * Return: 1 if the page has been recently accessed and 0 if not.
 */
int sgx_encl_test_and_clear_young(struct mm_struct *mm,
				  struct sgx_encl_page *page)
{
	unsigned long addr = SGX_ENCL_PAGE_ADDR(page);
	struct sgx_encl *encl = page->encl;
	struct vm_area_struct *vma;
	int ret;

	ret = sgx_encl_find(mm, addr, &vma);
	if (ret)
		return 0;

	if (encl != vma->vm_private_data)
		return 0;

	ret = apply_to_page_range(vma->vm_mm, addr, PAGE_SIZE,
				  sgx_encl_test_and_clear_young_cb, vma->vm_mm);
	if (ret < 0)
		return 0;

	return ret;
}

/**
 * sgx_encl_reserve_page() - Reserve an enclave page
 * @encl:	an enclave
 * @addr:	a page address
 *
 * Load an enclave page and lock the enclave so that the page can be used by
 * EDBG* and EMOD*.
 *
 * Return:
 *   an enclave page on success
 *   -EFAULT	if the load fails
 */
struct sgx_encl_page *sgx_encl_reserve_page(struct sgx_encl *encl,
					    unsigned long addr)
{
	struct sgx_encl_page *entry;

	for ( ; ; ) {
		mutex_lock(&encl->lock);

		entry = sgx_encl_load_page(encl, addr);
		if (PTR_ERR(entry) != -EBUSY)
			break;

		mutex_unlock(&encl->lock);
	}

	if (IS_ERR(entry))
		mutex_unlock(&encl->lock);

	return entry;
}

/**
 * sgx_alloc_page - allocate a VA page
 *
 * Allocates an &sgx_epc_page instance and converts it to a VA page.
 *
 * Return:
 *   a &struct sgx_va_page instance,
 *   -errno otherwise
 */
struct sgx_epc_page *sgx_alloc_va_page(void)
{
	struct sgx_epc_page *epc_page;
	int ret;

	epc_page = sgx_alloc_page(NULL, true);
	if (IS_ERR(epc_page))
		return ERR_CAST(epc_page);

	ret = __epa(sgx_epc_addr(epc_page));
	if (ret) {
		WARN_ONCE(1, "EPA returned %d (0x%x)", ret, ret);
		sgx_free_page(epc_page);
		return ERR_PTR(-EFAULT);
	}

	return epc_page;
}

/**
 * sgx_alloc_va_slot - allocate a VA slot
 * @va_page:	a &struct sgx_va_page instance
 *
 * Allocates a slot from a &struct sgx_va_page instance.
 *
 * Return: offset of the slot inside the VA page
 */
unsigned int sgx_alloc_va_slot(struct sgx_va_page *va_page)
{
	int slot = find_first_zero_bit(va_page->slots, SGX_VA_SLOT_COUNT);

	if (slot < SGX_VA_SLOT_COUNT)
		set_bit(slot, va_page->slots);

	return slot << 3;
}

/**
 * sgx_free_va_slot - free a VA slot
 * @va_page:	a &struct sgx_va_page instance
 * @offset:	offset of the slot inside the VA page
 *
 * Frees a slot from a &struct sgx_va_page instance.
 */
void sgx_free_va_slot(struct sgx_va_page *va_page, unsigned int offset)
{
	clear_bit(offset >> 3, va_page->slots);
}

/**
 * sgx_va_page_full - is the VA page full?
 * @va_page:	a &struct sgx_va_page instance
 *
 * Return: true if all slots have been taken
 */
bool sgx_va_page_full(struct sgx_va_page *va_page)
{
	int slot = find_first_zero_bit(va_page->slots, SGX_VA_SLOT_COUNT);

	return slot == SGX_VA_SLOT_COUNT;
}
