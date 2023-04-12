/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "migtd_utils.h"

void abort(void) { __asm__("ud2"); }

int* get_errno_addr(void)
{
    static int l_errno = 0;
    return &l_errno;
}

extern void* heap_base;
void* get_heap_base(void) { return heap_base; }

int apply_EPC_pages(void* start_address, size_t page_count)
{
    UNUSED(start_address);
    UNUSED(page_count);
    return 0; 
}

int trim_EPC_pages(void* start_address, size_t page_count)
{
    UNUSED(start_address);
    UNUSED(page_count);
    return 0; 
}

#define RELRO_SECTION_NAME ".data.rel.ro"
uintptr_t __stack_chk_guard __attribute__((section(RELRO_SECTION_NAME))) = 0;

// add this func since rust-lld compiler_builtins didn't have this
void __attribute__((noreturn)) __stack_chk_fail(void) { abort(); }

#define __weak_alias(alias, sym)                                               \
    __asm__(".weak " __STRING(alias) " ; " __STRING(alias) " = " __STRING(sym))
__weak_alias(__intel_security_cookie, __stack_chk_guard);

int sgx_thread_set_multiple_untrusted_events_ocall(const void** waiters,
                                                   size_t total)
{
    UNUSED(waiters);
    UNUSED(total);
    return 0;
}

int sgx_thread_setwait_untrusted_events_ocall(const void* waiter,
                                              const void* self)
{
    UNUSED(waiter);
    UNUSED(self);
    return 0;
}

int sgx_thread_set_untrusted_event_ocall(const void* waiter)
{ 
    UNUSED(waiter);
    return 0; 
}

int sgx_thread_wait_untrusted_event_ocall(const void* self)
{ 
    UNUSED(self);
    return 0; 
}

extern uint64_t __ImageBase;
void* get_enclave_base(void)
{
    uint64_t ret = 0;
    __asm__ __volatile__  ( "lea __ImageBase(%%rip), %%rax;": "=a"(ret));
    return (void *)ret;
}

int mm_commit(void* addr, size_t size)
{
    UNUSED(addr);
    UNUSED(size);
    return 0;
}

int mm_uncommit(void* addr, size_t size)
{
    UNUSED(addr);
    UNUSED(size);
    return 0;
}