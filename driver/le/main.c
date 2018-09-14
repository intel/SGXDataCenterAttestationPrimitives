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

#include <asm/sgx.h>
#include <asm/sgx_arch.h>
#include <asm/sgx_le.h>
#include <linux/string.h>
#include <linux/types.h>
#include <uapi/asm/sgx.h>
#include "main.h"

#include "./enclave/sgx_le_blob.h"
#include "./enclave/sgx_le_ss.h"


static void *start_launch_enclave(void)
{
	struct sgx_enclave_create create_ioc;
	struct sgx_enclave_add_page add_ioc;
	struct sgx_enclave_init init_ioc;
	struct sgx_secs secs;
	struct sgx_secinfo secinfo;
	unsigned long blob_base;
	unsigned long blob_size;
	unsigned long offset;
	int rc;

	memset(&secs, 0, sizeof(secs));
	memset(&secinfo, 0, sizeof(secinfo));

	secs.ssaframesize = 1;
	secs.attributes = SGX_ATTR_MODE64BIT | SGX_ATTR_EINITTOKENKEY;
	secs.xfrm = 3;

	blob_base = (unsigned long)&sgx_le_blob;
	blob_size = (unsigned long)sgx_le_blob_length;

	for (secs.size = 4096; secs.size < blob_size; )
		secs.size <<= 1;

	secs.base = (unsigned long)sgx_sys_mmap(SGX_LE_DEV_FD, secs.size);
	if (secs.base == (unsigned long)MAP_FAILED)
		goto out;

	create_ioc.src = (unsigned long)&secs;
	rc = sgx_sys_ioctl(SGX_LE_DEV_FD, SGX_IOC_ENCLAVE_CREATE, &create_ioc);
	if (rc)
		goto out;

	add_ioc.secinfo = (unsigned long)&secinfo;
	add_ioc.mrmask = 0xFFFF;

	for (offset = 0; offset < blob_size; offset += 0x1000) {
		if (!offset)
			secinfo.flags = SGX_SECINFO_TCS;
		else
			secinfo.flags = SGX_SECINFO_REG | SGX_SECINFO_R |
					SGX_SECINFO_W | SGX_SECINFO_X;

		add_ioc.addr = secs.base + offset;
		add_ioc.src = blob_base + offset;

		rc = sgx_sys_ioctl(SGX_LE_DEV_FD, SGX_IOC_ENCLAVE_ADD_PAGE,
				   &add_ioc);
		if (rc)
			goto out;
	}

	init_ioc.addr = secs.base;
	init_ioc.sigstruct = (uint64_t)&sgx_le_ss;
	rc = sgx_sys_ioctl(SGX_LE_DEV_FD, SGX_IOC_ENCLAVE_INIT, &init_ioc);
	if (rc)
		goto out;

	return (void *)secs.base;
out:
	return NULL;
}

static int read_input(void *data, unsigned int len)
{
	uint8_t *ptr = (uint8_t *)data;
	long i;
	long ret;

	for (i = 0; i < len; ) {
		ret = sgx_sys_read(&ptr[i], len - i);
		if (ret < 0)
			return ret;

		i += ret;
	}

	return 0;
}

static int write_output(const struct sgx_le_output *output)
{
	const uint8_t *ptr = (const uint8_t *)output;
	long i;
	long ret;

	for (i = 0; i < sizeof(*output); ) {
		ret = sgx_sys_write(&ptr[i], sizeof(*output) - i);
		if (ret < 0)
			return ret;

		i += ret;
	}

	return 0;
}

void _start(void)
{
	struct sgx_launch_request req;
	void *entry;

	sgx_sys_close(SGX_LE_EXE_FD);
	entry = start_launch_enclave();
	sgx_sys_close(SGX_LE_DEV_FD);
	if (!entry)
		sgx_sys_exit(1);

	for ( ; ; ) {
		memset(&req, 0, sizeof(req));

		if (read_input(&req, sizeof(req)))
			sgx_sys_exit(1);

		sgx_get_token(&req, entry);

		if (write_output(&req.output))
			sgx_sys_exit(1);
	}

	__builtin_unreachable();
}
