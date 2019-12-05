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

#include <linux/acpi.h>
#include <linux/platform_device.h>
#include <linux/suspend.h>
#include <linux/version.h>
#include <linux/mman.h>
#include <linux/cdev.h>

#include "sgx.h"
#include "sgx_version.h"
#include "sgx_driver_info.h"


MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR("Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRV_VERSION);


/*
 * Global data.
 */

struct workqueue_struct *sgx_add_page_wq;
u64 sgx_encl_size_max_32;
u64 sgx_encl_size_max_64;
u64 sgx_xfrm_mask = 0x3;
u32 sgx_misc_reserved;
u32 sgx_xsave_size_tbl[64];


// From intel_sgx.c
bool sgx_enabled = false;

static bool sgx_is_enabled(void)
{
	unsigned int eax;
	unsigned int ebx;
	unsigned int ecx;
	unsigned int edx;
	unsigned long fc;

	if (boot_cpu_data.x86_vendor != X86_VENDOR_INTEL) {
		pr_err("intel_sgx: Not an Intel CPU vendor!\n");
		return false;
	}

	if (!boot_cpu_has(X86_FEATURE_SGX)) {
		pr_err("intel_sgx: SGX is not supported on the platform!\n");
		return false;
	}

	if (!boot_cpu_has(X86_FEATURE_SGX_LC)) {
		pr_err("intel_sgx: FLC feature is not supported on the platform!\n");
		return false;
	}

	if (!boot_cpu_has(X86_FEATURE_AES)) {
		pr_err("intel_sgx: AES-NI instructions are not supported on the platform!\n");
		return false;
	}

	rdmsrl(MSR_IA32_FEATURE_CONTROL, fc);
	if (!(fc & FEATURE_CONTROL_LOCKED)) {
		pr_err("intel_sgx: FEATURE_CONTROL MSR is not locked!\n");
		return false;
	}

	if (!(fc & FEATURE_CONTROL_SGX_ENABLE)) {
		pr_err("intel_sgx: SGX is not enalbed in FEATURE_CONTROL MSR!\n");
		return false;
	}

	if (!(fc & FEATURE_CONTROL_SGX_LE_WR)) {
		pr_err("intel_sgx: FLC feature is not enalbed in FEATURE_CONTROL MSR!\n");
		return false;
	}

	cpuid(0, &eax, &ebx, &ecx, &edx);
	if (eax < SGX_CPUID) {
		pr_err("intel_sgx: SGX CPUID leaf is not supported!\n");
		return false;
	}

	cpuid_count(SGX_CPUID, SGX_CPUID_CAPABILITIES, &eax, &ebx, &ecx, &edx);

	/* The first bit indicates support for SGX1 instruction set. */
	if (!(eax & 1)) {
		pr_err("intel_sgx: Platform does not support SGX!\n");
		return false;
	}

	return true;
}

static int sgx_init(void)
{
	sgx_enabled = sgx_is_enabled();
	return 0;
}


static DECLARE_RWSEM(sgx_file_sem);


#ifdef CONFIG_COMPAT
long sgx_compat_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	return sgx_ioctl(filep, cmd, arg);
}
#endif

static int sgx_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_ops = &sgx_vm_ops;
	vma->vm_flags |= VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP | VM_IO |
			 VM_DONTCOPY;

	return 0;
}

static unsigned long sgx_get_unmapped_area(struct file *file,
					   unsigned long addr,
					   unsigned long len,
					   unsigned long pgoff,
					   unsigned long flags)
{
	if (len < 2 * PAGE_SIZE || (len & (len - 1)) || flags & MAP_PRIVATE)
		return -EINVAL;

	/* On 64-bit architecture, allow mmap() to exceed 32-bit encl
	 * limit only if the task is not running in 32-bit compatibility
	 * mode.
	 */
	if (len > sgx_encl_size_max_32)
#ifdef CONFIG_X86_64
		if (test_thread_flag(TIF_ADDR32))
			return -EINVAL;
#else
		return -EINVAL;
#endif

#ifdef CONFIG_X86_64
	if (len > sgx_encl_size_max_64)
		return -EINVAL;
#endif

	addr = current->mm->get_unmapped_area(file, addr, 2 * len, pgoff,
					      flags);
	if (IS_ERR_VALUE(addr))
		return addr;

	addr = (addr + (len - 1)) & ~(len - 1);

	return addr;
}

const struct file_operations sgx_fops = {
	.owner			= THIS_MODULE,
	.unlocked_ioctl		= sgx_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl		= sgx_compat_ioctl,
#endif
	.mmap			= sgx_mmap,
	.get_unmapped_area	= sgx_get_unmapped_area,
};

const struct file_operations sgx_provision_fops = {
	.owner			= THIS_MODULE,
};

static int sgx_pm_suspend(struct device *dev)
{
	struct sgx_encl *encl;

	list_for_each_entry(encl, &sgx_encl_list, encl_list) {
		sgx_invalidate(encl, false);
		encl->flags |= SGX_ENCL_SUSPEND;
		flush_work(&encl->add_page_work);
	}

	return 0;
}

static SIMPLE_DEV_PM_OPS(sgx_drv_pm, sgx_pm_suspend, NULL);


static struct bus_type sgx_bus_type = {
	.name	= "sgx",
};

struct sgx_context {
	struct device dev;
	struct cdev cdev;
	struct device provision_dev;
	struct cdev provision_cdev;
	struct kobject *kobj_dir;
};

static dev_t sgx_devt;

static void sgx_dev_release(struct device *dev)
{
	struct sgx_context *ctx = container_of(dev, struct sgx_context, dev);

	kfree(ctx);
}

static struct sgx_context *sgx_ctx_alloc(struct device *parent)
{
	struct sgx_context *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	// /dev/sgx
	device_initialize(&ctx->dev);

	ctx->dev.bus = &sgx_bus_type;
	ctx->dev.parent = parent;
	ctx->dev.devt = MKDEV(MAJOR(sgx_devt), 0);
	ctx->dev.release = sgx_dev_release;

	dev_set_name(&ctx->dev, "sgx");

	cdev_init(&ctx->cdev, &sgx_fops);
	ctx->cdev.owner = THIS_MODULE;

	// /dev/sgx_prv
	device_initialize(&ctx->provision_dev);

	ctx->provision_dev.bus = &sgx_bus_type;
	ctx->provision_dev.parent = parent;
	ctx->provision_dev.devt = MKDEV(MAJOR(sgx_devt), 1);
	ctx->provision_dev.release = sgx_dev_release;

	dev_set_name(&ctx->provision_dev, "sgx_prv");

	cdev_init(&ctx->provision_cdev, &sgx_provision_fops);
	ctx->provision_cdev.owner = THIS_MODULE;

	// device
	dev_set_drvdata(parent, ctx);

	return ctx;
}

static struct sgx_context *sgxm_ctx_alloc(struct device *parent)
{
	struct sgx_context *ctx;
	int rc;

	ctx = sgx_ctx_alloc(parent);
	if (IS_ERR(ctx))
		return ctx;

	rc = devm_add_action_or_reset(parent, (void (*)(void *))put_device,
				      &ctx->dev);
	if (rc) {
		kfree(ctx);
		return ERR_PTR(rc);
	}

	return ctx;
}

static ssize_t info_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "0x%08X\n", SGX_DRIVER_INFO_DCAP);
}

static ssize_t version_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "v"  DRV_VERSION "\n");
}

struct kobj_attribute info_attr = __ATTR_RO(info);
struct kobj_attribute version_attr = __ATTR_RO(version);

static int sgx_dev_init(struct device *parent)
{
	struct sgx_context *sgx_dev;
	unsigned int eax;
	unsigned int ebx;
	unsigned int ecx;
	unsigned int edx;
	int ret;
	int i;

	pr_info("intel_sgx: " DRV_DESCRIPTION " v" DRV_VERSION "\n");

	sgx_dev = sgxm_ctx_alloc(parent);

	cpuid_count(SGX_CPUID, SGX_CPUID_CAPABILITIES, &eax, &ebx, &ecx, &edx);
	/* Only allow misc bits supported by the driver. */
	sgx_misc_reserved = ~ebx | SGX_MISC_RESERVED_MASK;
#ifdef CONFIG_X86_64
	sgx_encl_size_max_64 = 1ULL << ((edx >> 8) & 0xFF);
#endif
	sgx_encl_size_max_32 = 1ULL << (edx & 0xFF);

	if (boot_cpu_has(X86_FEATURE_OSXSAVE)) {
		cpuid_count(SGX_CPUID, SGX_CPUID_ATTRIBUTES, &eax, &ebx, &ecx,
			    &edx);
		sgx_xfrm_mask = (((u64)edx) << 32) + (u64)ecx;

		for (i = 2; i < 64; i++) {
			cpuid_count(0x0D, i, &eax, &ebx, &ecx, &edx);
			if ((1ULL << i) & sgx_xfrm_mask)
				sgx_xsave_size_tbl[i] = eax + ebx;
		}
	}

	ret = sgx_page_cache_init(parent);
	if (ret)
		return ret;

	sgx_add_page_wq = alloc_workqueue("intel_sgx-add-page-wq",
					  WQ_UNBOUND | WQ_FREEZABLE, 1);
	if (!sgx_add_page_wq) {
		pr_err("intel_sgx: alloc_workqueue() failed\n");
		ret = -ENOMEM;
		goto out_page_cache;
	}

	ret = cdev_device_add(&sgx_dev->cdev, &sgx_dev->dev);
	if (ret)
		goto out_workqueue;

	ret = cdev_device_add(&sgx_dev->provision_cdev, &sgx_dev->provision_dev);
	if (ret)
		goto out_workqueue;

	sgx_dev->kobj_dir = kobject_create_and_add("sgx", kernel_kobj);
	sysfs_create_file(sgx_dev->kobj_dir, &info_attr.attr);
	sysfs_create_file(sgx_dev->kobj_dir, &version_attr.attr);

	return 0;

out_workqueue:
	destroy_workqueue(sgx_add_page_wq);
out_page_cache:
	sgx_page_cache_teardown();
	return ret;
}


static int sgx_drv_probe(struct platform_device *pdev)
{
	sgx_init();

	if (!sgx_enabled)
		return -ENODEV;

	return sgx_dev_init(&pdev->dev);
}

static int sgx_drv_remove(struct platform_device *pdev)
{
	struct sgx_context *ctx = dev_get_drvdata(&pdev->dev);

	sysfs_remove_file(ctx->kobj_dir, &info_attr.attr);
	sysfs_remove_file(ctx->kobj_dir, &version_attr.attr);
	kobject_put(ctx->kobj_dir);

	cdev_device_del(&ctx->cdev, &ctx->dev);
	cdev_device_del(&ctx->provision_cdev, &ctx->provision_dev);

	destroy_workqueue(sgx_add_page_wq);
	sgx_page_cache_teardown();

	return 0;
}

#ifdef CONFIG_ACPI
static struct acpi_device_id sgx_device_ids[] = {
	{"INT0E0C", 0},
	{"", 0},
};
MODULE_DEVICE_TABLE(acpi, sgx_device_ids);
#endif

static struct platform_driver sgx_drv = {
	.probe = sgx_drv_probe,
	.remove = sgx_drv_remove,
	.driver = {
		.name			= "intel_sgx",
		.pm			= &sgx_drv_pm,
		.acpi_match_table	= ACPI_PTR(sgx_device_ids),
	},
};

static int __init sgx_drv_subsys_init(void)
{
	int ret;

	ret = bus_register(&sgx_bus_type);
	if (ret)
		return ret;

	ret = alloc_chrdev_region(&sgx_devt, 0, 1, "sgx");
	if (ret < 0) {
		bus_unregister(&sgx_bus_type);
		return ret;
	}

	return 0;
}

static void sgx_drv_subsys_exit(void)
{
	bus_unregister(&sgx_bus_type);
	unregister_chrdev_region(sgx_devt, 1);
}

static int __init sgx_drv_init(void)
{
	int ret;

	ret = sgx_drv_subsys_init();
	if (ret)
		return ret;

	ret = platform_driver_register(&sgx_drv);
	if (ret)
		sgx_drv_subsys_exit();

	return ret;
}
module_init(sgx_drv_init);

static void __exit sgx_drv_exit(void)
{
	platform_driver_unregister(&sgx_drv);
	sgx_drv_subsys_exit();
}
module_exit(sgx_drv_exit);

