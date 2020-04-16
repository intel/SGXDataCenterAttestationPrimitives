// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-19 Intel Corporation.

#include <asm/mman.h>
#include <linux/mman.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <linux/hashtable.h>
#include <linux/highmem.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/suspend.h>
#include "driver.h"
#include "encl.h"
#include "encls.h"

#include <linux/version.h>
#include "sgx_wl.h"

/* A per-cpu cache for the last known values of IA32_SGXLEPUBKEYHASHx MSRs. */
static DEFINE_PER_CPU(u64 [4], sgx_lepubkeyhash_cache);

static struct sgx_va_page *sgx_encl_grow(struct sgx_encl *encl)
{
	struct sgx_va_page *va_page = NULL;
	void *err;

	BUILD_BUG_ON(SGX_VA_SLOT_COUNT !=
		(SGX_ENCL_PAGE_VA_OFFSET_MASK >> 3) + 1);

	if (!(encl->page_cnt % SGX_VA_SLOT_COUNT)) {
		va_page = kzalloc(sizeof(*va_page), GFP_KERNEL);
		if (!va_page)
			return ERR_PTR(-ENOMEM);

		va_page->epc_page = sgx_alloc_va_page();
		if (IS_ERR(va_page->epc_page)) {
			err = ERR_CAST(va_page->epc_page);
			kfree(va_page);
			return err;
		}

		WARN_ON_ONCE(encl->page_cnt % SGX_VA_SLOT_COUNT);
	}
	encl->page_cnt++;
	return va_page;
}

static void sgx_encl_shrink(struct sgx_encl *encl, struct sgx_va_page *va_page)
{
	encl->page_cnt--;

	if (va_page) {
		sgx_free_page(va_page->epc_page);
		list_del(&va_page->list);
		kfree(va_page);
	}
}

static u32 sgx_calc_ssaframesize(u32 miscselect, u64 xfrm)
{
	u32 size_max = PAGE_SIZE;
	u32 size;
	int i;

	for (i = 2; i < 64; i++) {
		if (!((1 << i) & xfrm))
			continue;

		size = SGX_SSA_GPRS_SIZE + sgx_xsave_size_tbl[i];
		if (miscselect & SGX_MISC_EXINFO)
			size += SGX_SSA_MISC_EXINFO_SIZE;

		if (size > size_max)
			size_max = size;
	}

	return PFN_UP(size_max);
}

static int sgx_validate_secs(const struct sgx_secs *secs,
			     unsigned long ssaframesize)
{
	if (secs->size < (2 * PAGE_SIZE) || !is_power_of_2(secs->size))
		return -EINVAL;

	if (secs->base & (secs->size - 1))
		return -EINVAL;

	if (secs->miscselect & sgx_misc_reserved_mask ||
	    secs->attributes & sgx_attributes_reserved_mask ||
	    secs->xfrm & sgx_xfrm_reserved_mask)
		return -EINVAL;

	if (secs->attributes & SGX_ATTR_MODE64BIT) {
		if (secs->size > sgx_encl_size_max_64)
			return -EINVAL;
	} else if (secs->size > sgx_encl_size_max_32)
		return -EINVAL;

	if (!(secs->xfrm & XFEATURE_MASK_FP) ||
	    !(secs->xfrm & XFEATURE_MASK_SSE) ||
	    (((secs->xfrm >> XFEATURE_BNDREGS) & 1) !=
	     ((secs->xfrm >> XFEATURE_BNDCSR) & 1)))
		return -EINVAL;

	if (!secs->ssa_frame_size || ssaframesize > secs->ssa_frame_size)
		return -EINVAL;

	if (memchr_inv(secs->reserved1, 0, sizeof(secs->reserved1)) ||
	    memchr_inv(secs->reserved2, 0, sizeof(secs->reserved2)) ||
	    memchr_inv(secs->reserved3, 0, sizeof(secs->reserved3)) ||
	    memchr_inv(secs->reserved4, 0, sizeof(secs->reserved4)))
		return -EINVAL;

	return 0;
}

static struct sgx_encl_page *sgx_encl_page_alloc(struct sgx_encl *encl,
						 unsigned long offset,
						 u64 secinfo_flags)
{
	struct sgx_encl_page *encl_page;
	unsigned long prot;

	encl_page = kzalloc(sizeof(*encl_page), GFP_KERNEL);
	if (!encl_page)
		return ERR_PTR(-ENOMEM);

	encl_page->desc = encl->base + offset;
	encl_page->encl = encl;

	prot = _calc_vm_trans(secinfo_flags, SGX_SECINFO_R, PROT_READ)  |
	       _calc_vm_trans(secinfo_flags, SGX_SECINFO_W, PROT_WRITE) |
	       _calc_vm_trans(secinfo_flags, SGX_SECINFO_X, PROT_EXEC);

	/*
	 * TCS pages must always RW set for CPU access while the SECINFO
	 * permissions are *always* zero - the CPU ignores the user provided
	 * values and silently overwrites them with zero permissions.
	 */
	if ((secinfo_flags & SGX_SECINFO_PAGE_TYPE_MASK) == SGX_SECINFO_TCS)
		prot |= PROT_READ | PROT_WRITE;

	/* Calculate maximum of the VM flags for the page. */
	encl_page->vm_max_prot_bits = calc_vm_prot_bits(prot, 0);

	return encl_page;
}

static int sgx_encl_create(struct sgx_encl *encl, struct sgx_secs *secs)
{
	unsigned long encl_size = secs->size + PAGE_SIZE;
	struct sgx_epc_page *secs_epc;
	struct sgx_va_page *va_page;
	unsigned long ssaframesize;
	struct sgx_pageinfo pginfo;
	struct sgx_secinfo secinfo;
	struct file *backing;
	long ret;

	if (atomic_read(&encl->flags) & SGX_ENCL_CREATED)
		return -EINVAL;

	va_page = sgx_encl_grow(encl);
	if (IS_ERR(va_page))
		return PTR_ERR(va_page);
	else if (va_page)
		list_add(&va_page->list, &encl->va_pages);

	ssaframesize = sgx_calc_ssaframesize(secs->miscselect, secs->xfrm);
	if (sgx_validate_secs(secs, ssaframesize)) {
		pr_debug("invalid SECS\n");
		ret = -EINVAL;
		goto err_out_shrink;
	}

	backing = shmem_file_setup("SGX backing", encl_size + (encl_size >> 5),
				   VM_NORESERVE);
	if (IS_ERR(backing)) {
		ret = PTR_ERR(backing);
		goto err_out_shrink;
	}

	encl->backing = backing;

	secs_epc = sgx_alloc_page(&encl->secs, true);
	if (IS_ERR(secs_epc)) {
		ret = PTR_ERR(secs_epc);
		goto err_out_backing;
	}

	encl->secs.epc_page = secs_epc;

	pginfo.addr = 0;
	pginfo.contents = (unsigned long)secs;
	pginfo.metadata = (unsigned long)&secinfo;
	pginfo.secs = 0;
	memset(&secinfo, 0, sizeof(secinfo));

	ret = __ecreate((void *)&pginfo, sgx_epc_addr(secs_epc));
	if (ret) {
		pr_debug("ECREATE returned %ld\n", ret);
		goto err_out;
	}

	if (secs->attributes & SGX_ATTR_DEBUG)
		atomic_or(SGX_ENCL_DEBUG, &encl->flags);

	encl->secs.encl = encl;
	encl->secs_attributes = secs->attributes;
	encl->allowed_attributes |= SGX_ATTR_ALLOWED_MASK;
	encl->base = secs->base;
	encl->size = secs->size;
	encl->ssaframesize = secs->ssa_frame_size;

	/*
	 * Set SGX_ENCL_CREATED only after the enclave is fully prepped.  This
	 * allows setting and checking enclave creation without having to take
	 * encl->lock.
	 */
	atomic_or(SGX_ENCL_CREATED, &encl->flags);

	return 0;

err_out:
	sgx_free_page(encl->secs.epc_page);
	encl->secs.epc_page = NULL;

err_out_backing:
	fput(encl->backing);
	encl->backing = NULL;

err_out_shrink:
	sgx_encl_shrink(encl, va_page);

	return ret;
}

/**
 * sgx_ioc_enclave_create - handler for %SGX_IOC_ENCLAVE_CREATE
 * @filep:	open file to /dev/sgx
 * @arg:	userspace pointer to a struct sgx_enclave_create instance
 *
 * Allocate kernel data structures for a new enclave and execute ECREATE after
 * verifying the correctness of the provided SECS.
 *
 * Note, enforcement of restricted and disallowed attributes is deferred until
 * sgx_ioc_enclave_init(), only the architectural correctness of the SECS is
 * checked by sgx_ioc_enclave_create().
 *
 * Return:
 *   0 on success,
 *   -errno otherwise
 */
static long sgx_ioc_enclave_create(struct sgx_encl *encl, void __user *arg)
{
	struct sgx_enclave_create ecreate;
	struct page *secs_page;
	struct sgx_secs *secs;
	int ret;

	if (copy_from_user(&ecreate, arg, sizeof(ecreate)))
		return -EFAULT;

	secs_page = alloc_page(GFP_KERNEL);
	if (!secs_page)
		return -ENOMEM;

	secs = kmap(secs_page);
	if (copy_from_user(secs, (void __user *)ecreate.src, sizeof(*secs))) {
		ret = -EFAULT;
		goto out;
	}

	ret = sgx_encl_create(encl, secs);

out:
	kunmap(secs_page);
	__free_page(secs_page);
	return ret;
}

static int sgx_validate_secinfo(struct sgx_secinfo *secinfo)
{
	u64 perm = secinfo->flags & SGX_SECINFO_PERMISSION_MASK;
	u64 pt = secinfo->flags & SGX_SECINFO_PAGE_TYPE_MASK;

	if (pt != SGX_SECINFO_REG && pt != SGX_SECINFO_TCS)
		return -EINVAL;

	if ((perm & SGX_SECINFO_W) && !(perm & SGX_SECINFO_R))
		return -EINVAL;

	/*
	 * CPU will silently overwrite the permissions as zero, which means
	 * that we need to validate it ourselves.
	 */
	if (pt == SGX_SECINFO_TCS && perm)
		return -EINVAL;

	if (secinfo->flags & SGX_SECINFO_RESERVED_MASK)
		return -EINVAL;

	if (memchr_inv(secinfo->reserved, 0, sizeof(secinfo->reserved)))
		return -EINVAL;

	return 0;
}

static int __sgx_encl_add_page(struct sgx_encl *encl,
			       struct sgx_encl_page *encl_page,
			       struct sgx_epc_page *epc_page,
			       struct sgx_secinfo *secinfo, unsigned long src)
{
	struct sgx_pageinfo pginfo;
	struct vm_area_struct *vma;
	struct page *src_page;
	int ret;

	/* Query vma's VM_MAYEXEC as an indirect path_noexec() check. */
	if (encl_page->vm_max_prot_bits & VM_EXEC) {
		vma = find_vma(current->mm, src);
		if (!vma)
			return -EFAULT;

		if (!(vma->vm_flags & VM_MAYEXEC))
			return -EACCES;
	}

	ret = get_user_pages(src, 1, 0, &src_page, NULL);
	if (ret < 1)
		return ret;

	pginfo.secs = (unsigned long)sgx_epc_addr(encl->secs.epc_page);
	pginfo.addr = SGX_ENCL_PAGE_ADDR(encl_page);
	pginfo.metadata = (unsigned long)secinfo;
	pginfo.contents = (unsigned long)kmap_atomic(src_page);

	ret = __eadd(&pginfo, sgx_epc_addr(epc_page));

	kunmap_atomic((void *)pginfo.contents);
	put_page(src_page);

	return ret ? -EIO : 0;
}

static int __sgx_encl_extend(struct sgx_encl *encl,
			     struct sgx_epc_page *epc_page)
{
	int ret;
	int i;

	for (i = 0; i < 16; i++) {
		ret = __eextend(sgx_epc_addr(encl->secs.epc_page),
				sgx_epc_addr(epc_page) + (i * 0x100));
		if (ret) {
			if (encls_failed(ret))
				ENCLS_WARN(ret, "EEXTEND");
			return -EIO;
		}
	}

	return 0;
}

static int sgx_encl_add_page(struct sgx_encl *encl, unsigned long src,
			     unsigned long offset, unsigned long length,
			     struct sgx_secinfo *secinfo, unsigned long flags)
{
	struct sgx_encl_page *encl_page;
	struct sgx_epc_page *epc_page;
	struct sgx_va_page *va_page;
	int ret;

	encl_page = sgx_encl_page_alloc(encl, offset, secinfo->flags);
	if (IS_ERR(encl_page))
		return PTR_ERR(encl_page);

	epc_page = sgx_alloc_page(encl_page, true);
	if (IS_ERR(epc_page)) {
		kfree(encl_page);
		return PTR_ERR(epc_page);
	}

	if (atomic_read(&encl->flags) &
	    (SGX_ENCL_INITIALIZED | SGX_ENCL_DEAD)) {
		ret = -EFAULT;
		goto err_out_free;
	}

	va_page = sgx_encl_grow(encl);
	if (IS_ERR(va_page)) {
		ret = PTR_ERR(va_page);
		goto err_out_free;
	}

	down_read(&current->mm->mmap_sem);
	mutex_lock(&encl->lock);

	/*
	 * Adding to encl->va_pages must be done under encl->lock.  Ditto for
	 * deleting (via sgx_encl_shrink()) in the error path.
	 */
	if (va_page)
		list_add(&va_page->list, &encl->va_pages);

	/*
	 * Insert prior to EADD in case of OOM.  EADD modifies MRENCLAVE, i.e.
	 * can't be gracefully unwound, while failure on EADD/EXTEND is limited
	 * to userspace errors (or kernel/hardware bugs).
	 */
	ret = radix_tree_insert(&encl->page_tree, PFN_DOWN(encl_page->desc),
				encl_page);
	if (ret)
		goto err_out_unlock;

	ret = __sgx_encl_add_page(encl, encl_page, epc_page, secinfo,
				  src);
	if (ret)
		goto err_out;

	/*
	 * Complete the "add" before doing the "extend" so that the "add"
	 * isn't in a half-baked state in the extremely unlikely scenario the
	 * the enclave will be destroyed in response to EEXTEND failure.
	 */
	encl_page->encl = encl;
	encl_page->epc_page = epc_page;
	encl->secs_child_cnt++;

	if (flags & SGX_PAGE_MEASURE) {
		ret = __sgx_encl_extend(encl, epc_page);
		if (ret)
			goto err_out;
	}

	sgx_mark_page_reclaimable(encl_page->epc_page);
	mutex_unlock(&encl->lock);
	up_read(&current->mm->mmap_sem);
	return ret;

err_out:
	radix_tree_delete(&encl_page->encl->page_tree,
			  PFN_DOWN(encl_page->desc));

err_out_unlock:
	sgx_encl_shrink(encl, va_page);
	mutex_unlock(&encl->lock);
	up_read(&current->mm->mmap_sem);

err_out_free:
	sgx_free_page(epc_page);
	kfree(encl_page);

	/*
	 * Destroy enclave on ENCLS failure as this means that EPC has been
	 * invalidated.
	 */
	if (ret == -EIO)
		sgx_encl_destroy(encl);

	return ret;
}

/**
 * sgx_ioc_enclave_add_pages() - The handler for %SGX_IOC_ENCLAVE_ADD_PAGES
 * @encl:       pointer to an enclave instance (via ioctl() file pointer)
 * @arg:	a user pointer to a struct sgx_enclave_add_pages instance
 *
 * Add one or more pages to an uninitialized enclave, and optionally extend the
 * measurement with the contents of the page. The address range of pages must
 * be contiguous. The SECINFO and measurement mask are applied to all pages.
 *
 * A SECINFO for a TCS is required to always contain zero permissions because
 * CPU silently zeros them. Allowing anything else would cause a mismatch in
 * the measurement.
 *
 * mmap()'s protection bits are capped by the page permissions. For each page
 * address, the maximum protection bits are computed with the following
 * heuristics:
 *
 * 1. A regular page: PROT_R, PROT_W and PROT_X match the SECINFO permissions.
 * 2. A TCS page: PROT_R | PROT_W.
 * 3. No page: PROT_NONE.
 *
 * mmap() is not allowed to surpass the minimum of the maximum protection bits
 * within the given address range.
 *
 * As stated above, a non-existent page is interpreted as a page with no
 * permissions. In effect, this allows mmap() with PROT_NONE to be used to seek
 * an address range for the enclave that can be then populated into SECS.
 *
 * If ENCLS opcode fails, that effectively means that EPC has been invalidated.
 * When this happens the enclave is destroyed and -EIO is returned to the
 * caller.
 *
 * Return:
 *   0 on success,
 *   -EACCES if an executable source page is located in a noexec partition,
 *   -EIO if either ENCLS[EADD] or ENCLS[EEXTEND] fails
 *   -errno otherwise
 */
static long sgx_ioc_enclave_add_pages(struct sgx_encl *encl, void __user *arg)
{
	struct sgx_enclave_add_pages addp;
	struct sgx_secinfo secinfo;
	unsigned long c;
	int ret;

	if (!(atomic_read(&encl->flags) & SGX_ENCL_CREATED))
		return -EINVAL;

	if (copy_from_user(&addp, arg, sizeof(addp)))
		return -EFAULT;

	if (!IS_ALIGNED(addp.offset, PAGE_SIZE) ||
	    !IS_ALIGNED(addp.src, PAGE_SIZE))
		return -EINVAL;

	if (!(access_ok(
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0) && (!defined(RHEL_RELEASE_CODE)))
		VERIFY_READ,
#else
    #if( defined(RHEL_RELEASE_VERSION) && defined(RHEL_RELEASE_CODE))
        #if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8, 0))
            #error "RHEL version not supported"
        #elif (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8, 1))
		VERIFY_READ,
        #endif
    #endif
#endif
	        addp.src, PAGE_SIZE)))
		return -EFAULT;

	if (addp.length & (PAGE_SIZE - 1))
		return -EINVAL;

	if (addp.offset + addp.length - PAGE_SIZE >= encl->size)
		return -EINVAL;

	if (copy_from_user(&secinfo, (void __user *)addp.secinfo,
			   sizeof(secinfo)))
		return -EFAULT;

	if (sgx_validate_secinfo(&secinfo))
		return -EINVAL;

	for (c = 0 ; c < addp.length; c += PAGE_SIZE) {
		if (signal_pending(current)) {
			ret = -EINTR;
			break;
		}

		if (need_resched())
			cond_resched();

		ret = sgx_encl_add_page(encl, addp.src + c, addp.offset + c,
					addp.length - c, &secinfo, addp.flags);
		if (ret)
			break;
	}

	addp.count = c;

	if (copy_to_user(arg, &addp, sizeof(addp)))
		return -EFAULT;

	return ret;
}

static int __sgx_get_key_hash(struct crypto_shash *tfm, const void *modulus,
			      void *hash)
{
	SHASH_DESC_ON_STACK(shash, tfm);

	shash->tfm = tfm;

	return crypto_shash_digest(shash, modulus, SGX_MODULUS_SIZE, hash);
}

static int sgx_get_key_hash(const void *modulus, void *hash)
{
	struct crypto_shash *tfm;
	int ret;

	tfm = crypto_alloc_shash("sha256", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	ret = __sgx_get_key_hash(tfm, modulus, hash);

	crypto_free_shash(tfm);
	return ret;
}

static void sgx_update_lepubkeyhash_msrs(u64 *lepubkeyhash, bool enforce)
{
	u64 *cache;
	int i;

	cache = per_cpu(sgx_lepubkeyhash_cache, smp_processor_id());
	for (i = 0; i < 4; i++) {
		if (enforce || (lepubkeyhash[i] != cache[i])) {
			wrmsrl(MSR_IA32_SGXLEPUBKEYHASH0 + i, lepubkeyhash[i]);
			cache[i] = lepubkeyhash[i];
		}
	}
}

static int sgx_einit(struct sgx_sigstruct *sigstruct, void *token,
		     struct sgx_epc_page *secs, u64 *lepubkeyhash)
{
	int ret;

	preempt_disable();
	sgx_update_lepubkeyhash_msrs(lepubkeyhash, false);
	ret = __einit(sigstruct, token, sgx_epc_addr(secs));
	if (ret == SGX_INVALID_EINITTOKEN) {
		sgx_update_lepubkeyhash_msrs(lepubkeyhash, true);
		ret = __einit(sigstruct, token, sgx_epc_addr(secs));
	}
	preempt_enable();
	return ret;
}

static int sgx_encl_init(struct sgx_encl *encl, struct sgx_sigstruct *sigstruct,
			 void *token)
{
	u64 mrsigner[4];
	int ret;
	int i;
	int j;

	ret = sgx_get_key_hash(sigstruct->modulus, mrsigner);
	if (ret)
		return ret;

	if((encl->secs_attributes & ~encl->allowed_attributes) && (encl->secs_attributes & SGX_ATTR_PROVISIONKEY)) {
		for(i = 0; i < (sizeof(G_SERVICE_ENCLAVE_MRSIGNER) / sizeof(G_SERVICE_ENCLAVE_MRSIGNER[0])); i++) {
			if(0 == memcmp(&G_SERVICE_ENCLAVE_MRSIGNER[i], mrsigner, sizeof(G_SERVICE_ENCLAVE_MRSIGNER[0]))) {
				encl->allowed_attributes |= SGX_ATTR_PROVISIONKEY;
				break;
			}
		}
	}

	/* Check that the required attributes have been authorized. */
	if (encl->secs_attributes & ~encl->allowed_attributes)
		return -EACCES;

	mutex_lock(&encl->lock);

	if (atomic_read(&encl->flags) & SGX_ENCL_INITIALIZED) {
		ret = -EFAULT;
		goto err_out;
	}

	for (i = 0; i < SGX_EINIT_SLEEP_COUNT; i++) {
		for (j = 0; j < SGX_EINIT_SPIN_COUNT; j++) {
			ret = sgx_einit(sigstruct, token, encl->secs.epc_page,
					mrsigner);
			if (ret == SGX_UNMASKED_EVENT)
				continue;
			else
				break;
		}

		if (ret != SGX_UNMASKED_EVENT)
			break;

		msleep_interruptible(SGX_EINIT_SLEEP_TIME);

		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			goto err_out;
		}
	}

	if (ret & ENCLS_FAULT_FLAG) {
		if (encls_failed(ret))
			ENCLS_WARN(ret, "EINIT");

		sgx_encl_destroy(encl);
		ret = -EFAULT;
	} else if (ret) {
		pr_debug("EINIT returned %d\n", ret);
		ret = -EPERM;
	} else {
		atomic_or(SGX_ENCL_INITIALIZED, &encl->flags);
	}

err_out:
	mutex_unlock(&encl->lock);
	return ret;
}

/**
 * sgx_ioc_enclave_init - handler for %SGX_IOC_ENCLAVE_INIT
 *
 * @filep:	open file to /dev/sgx
 * @arg:	userspace pointer to a struct sgx_enclave_init instance
 *
 * Flush any outstanding enqueued EADD operations and perform EINIT.  The
 * Launch Enclave Public Key Hash MSRs are rewritten as necessary to match
 * the enclave's MRSIGNER, which is caculated from the provided sigstruct.
 *
 * Return:
 *   0 on success,
 *   SGX error code on EINIT failure,
 *   -errno otherwise
 */
static long sgx_ioc_enclave_init(struct sgx_encl *encl, void __user *arg)
{
	struct sgx_sigstruct *sigstruct;
	struct sgx_enclave_init einit;
	struct page *initp_page;
	void* token;
	int ret;

	if (!(atomic_read(&encl->flags) & SGX_ENCL_CREATED))
		return -EINVAL;

	if (copy_from_user(&einit, arg, sizeof(einit)))
		return -EFAULT;

	initp_page = alloc_page(GFP_KERNEL);
	if (!initp_page)
		return -ENOMEM;

	sigstruct = kmap(initp_page);
        token = (void *)((unsigned long)sigstruct + PAGE_SIZE / 2);
        memset(token, 0, SGX_LAUNCH_TOKEN_SIZE);

	if (copy_from_user(sigstruct, (void __user *)einit.sigstruct,
			   sizeof(*sigstruct))) {
		ret = -EFAULT;
		goto out;
	}

	ret = sgx_encl_init(encl, sigstruct, token);

out:
	kunmap(initp_page);
	__free_page(initp_page);
	return ret;
}

/**
 * sgx_ioc_enclave_set_attribute - handler for %SGX_IOC_ENCLAVE_SET_ATTRIBUTE
 * @filep:	open file to /dev/sgx
 * @arg:	userspace pointer to a struct sgx_enclave_set_attribute instance
 *
 * Mark the enclave as being allowed to access a restricted attribute bit.
 * The requested attribute is specified via the attribute_fd field in the
 * provided struct sgx_enclave_set_attribute.  The attribute_fd must be a
 * handle to an SGX attribute file, e.g. “/dev/sgx/provision".
 *
 * Failure to explicitly request access to a restricted attribute will cause
 * sgx_ioc_enclave_init() to fail.  Currently, the only restricted attribute
 * is access to the PROVISION_KEY.
 *
 * Note, access to the EINITTOKEN_KEY is disallowed entirely.
 *
 * Return: 0 on success, -errno otherwise
 */
static long sgx_ioc_enclave_set_attribute(struct sgx_encl *encl,
					  void __user *arg)
{
	struct sgx_enclave_set_attribute params;
	struct file *attribute_file;
	int ret;

	if (copy_from_user(&params, arg, sizeof(params)))
		return -EFAULT;

	attribute_file = fget(params.attribute_fd);
	if (!attribute_file)
		return -EINVAL;

	if (attribute_file->f_op != &sgx_provision_fops) {
		ret = -EINVAL;
		goto out;
	}

	encl->allowed_attributes |= SGX_ATTR_PROVISIONKEY;
	ret = 0;

out:
	fput(attribute_file);
	return ret;
}

long sgx_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	struct sgx_encl *encl = filep->private_data;
	int ret, encl_flags;

	encl_flags = atomic_fetch_or(SGX_ENCL_IOCTL, &encl->flags);
	if (encl_flags & SGX_ENCL_IOCTL)
		return -EBUSY;

	if (encl_flags & SGX_ENCL_DEAD)
		return -EFAULT;

	switch (cmd) {
	case SGX_IOC_ENCLAVE_CREATE:
		ret = sgx_ioc_enclave_create(encl, (void __user *)arg);
		break;
	case SGX_IOC_ENCLAVE_ADD_PAGES:
		ret = sgx_ioc_enclave_add_pages(encl, (void __user *)arg);
		break;
	case SGX_IOC_ENCLAVE_INIT:
		ret = sgx_ioc_enclave_init(encl, (void __user *)arg);
		break;
	case SGX_IOC_ENCLAVE_SET_ATTRIBUTE:
		ret = sgx_ioc_enclave_set_attribute(encl, (void __user *)arg);
		break;
	default:
		ret = -ENOIOCTLCMD;
		break;
	}

	atomic_andnot(SGX_ENCL_IOCTL, &encl->flags);

	return ret;
}
