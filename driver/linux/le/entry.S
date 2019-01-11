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

#include <asm/sgx_le.h>
#include <sgx_asm.h>

	.text

	.global sgx_get_token
sgx_get_token:
	push	%rbx
	mov	$0x02, %rax
	mov	%rsi, %rbx
	mov	$sgx_async_exit, %rcx
sgx_async_exit:
	ENCLU
	pop	%rbx
	ret

	.global sgx_sys_read
sgx_sys_read:
	mov	$0, %rax
	mov	%rsi, %rdx /* buf */
	mov	%rdi, %rsi /* count */
	mov	$SGX_LE_PIPE_FD, %rdi
	syscall
	ret

	.global sgx_sys_write
sgx_sys_write:
	mov	$1, %rax
	mov	%rsi, %rdx /* buf */
	mov	%rdi, %rsi /* count */
	mov	$SGX_LE_PIPE_FD, %rdi
	syscall
	ret

	.global sgx_sys_close
sgx_sys_close:
	mov	$3, %rax
	syscall
	ret

	.global sgx_sys_mmap
sgx_sys_mmap:
	mov	$9, %rax
	mov	%rdi, %r8 /* fd */
	xor	%rdi, %rdi /* any address */

	mov	$0x07, %rdx /* rwx */
	mov	$0x01, %r10 /* shared */
	mov	$0x00, %r9 /* offset */
	syscall
	ret

	.global sgx_sys_ioctl
sgx_sys_ioctl:
	mov	$16, %rax
	syscall
	ret

	.global sgx_sys_exit
sgx_sys_exit:
	mov	$60, %rax
	syscall
