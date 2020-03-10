/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
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
#ifndef _THREAD_DATA_H_
#define _THREAD_DATA_H_

#include "se_types.h"
#include "se_cdefs.h"

#ifdef TD_SUPPORT_MULTI_PLATFORM
/* To enable the SignTool to sign both 32/64-bit Enclave for PE,
 * we need to make the struct `thread_data_t' have a consistent
 * definition for 32/64-bit compiler.
 *
 * We achieve it by forcing the compiler to check pre-defined macros
 *   `RTS_SYSTEM_WORDSIZE'
 *
 * | RTS_SYSTEM_WORDSIZE = 32 | PE32  |
 * |--------------------------+-------|
 * | RTS_SYSTEM_WORDSIZE = 64 | PE64  |
 *
 */
#  ifndef RTS_SYSTEM_WORDSIZE
#    error RTS_SYSTEM_WORDSIZE should be pre-defined.
#  endif

/* Avoid to use `uintptr_t' in the struct `thread_data_t' and its members. */
#  if RTS_SYSTEM_WORDSIZE == 32
typedef uint32_t sys_word_t;
#  elif RTS_SYSTEM_WORDSIZE == 64
typedef uint64_t sys_word_t;
#  else
#    error Invalid value for 'RTS_SYSTEM_WORDSIZE'.
#  endif

#else

/* For uRTS, there is no need to define the macro 'TD_SUPPORT_MULTI_PLATFORM' */
typedef size_t sys_word_t;


/* SE_32 and SE_64 are defined in "se_cdefs.h" */
#  ifdef SE_32
#    define RTS_SYSTEM_WORDSIZE 32
#  elif defined(SE_64)
#    define RTS_SYSTEM_WORDSIZE 64
#  else
#    error Unknown system word size.
#  endif

#endif /* ! TD_SUPPORT_MULTI_PLATFORM */

/* We are now defined the data structures below with fields having fixed sizes 
 * among compilers.
 */

typedef struct _cxx_ptd_t
{
    sys_word_t  terminate_handler;      // init to be 0, Used by cpp exception handling
    uint16_t    is_terminating;         // init to be 0, Used by cpp exception handling
    uint16_t    uncaught_exception;     // init to be 0, Used by cpp exception handling
} cxx_ptd_t;

#  if RTS_SYSTEM_WORDSIZE == 32
typedef struct _cxx_ptd_t_win32
{
    sys_word_t  current_exception;
} cxx_ptd_t_win32;
#  endif

/* The data structure currently is naturally aligned regardless of the value of RTS_SYSTEM_WORDSIZE.
 *
 * However, we need to take care when modifying the data structure in future.
 */

typedef struct _thread_data_t
{
#if (RTS_SYSTEM_WORDSIZE == 32)
    sys_word_t  seh_header;
#elif (RTS_SYSTEM_WORDSIZE == 64)
    sys_word_t  last_throw;
#endif
    sys_word_t  last_sp;            // set by urts, relative to TCS
    sys_word_t  stack_base_addr;    // set by urts, relative to TCS
    sys_word_t  stack_limit_addr;   // set by urts, relative to TCS
    sys_word_t  first_ssa_base;      // set by urts, relative to TCS

    sys_word_t  first_ssa_gpr;       // first ssa gpr offset, set by urts, relative to TCS
    sys_word_t  self_addr;          // set by urts, relative to TCS  // offset: 0x18(WIN32); 0x30(X64)

    uint8_t     thread_policy;      // set by urts, 1 - init thread in root call, 0 - no need to re-init thread
    uint8_t     debug_flag;         // Used by EPC measurement tool. Measurement tool can update it to get EPC usage information
    uint8_t     reserved[2];        // Reserved bytes.
#if RTS_SYSTEM_WORDSIZE == 64
    int32_t   exception_flag;
#endif

#ifdef _MSC_VER
#pragma warning( push )
#pragma warning( disable : 4201 )       // nonstandard extension used : nameless struct/union
#endif
    union
    {
        struct
        {
            sys_word_t  heap_offset;    // set by urts, relative to enclave base
            sys_word_t  enclave_size;   // set by urts
        } info;
        cxx_ptd_t   cxx_ptd;        // for C++ support
    };
#ifdef _MSC_VER
#pragma warning( pop )
#endif

    sys_word_t  last_error;             // init to be 0. Used by trts.
    sys_word_t  tls_array;              // set by urts, points to TD.self_addr relative to TCS // offset: 0x2c(WIN32); 0x58(X64)

    uint32_t    ssa_frame_size;         // set by urts, in pages (se_ptrace.c needs to know its offset).
#if (RTS_SYSTEM_WORDSIZE == 32)
    cxx_ptd_t_win32 cxx_ptd_win32;
#endif
    uint32_t heap_size;              // set by urts

#ifdef TD_SUPPORT_MULTI_PLATFORM
    sys_word_t  m_next;                 // next TD used by trusted thread library (of type "struct _thread_data *")
#else
    struct _thread_data_t *m_next;
#endif
#if RTS_SYSTEM_WORDSIZE == 32
    int32_t exception_flag;
#endif
} thread_data_t;

#ifdef __cplusplus
extern "C" {
#endif

thread_data_t *get_thread_data(void);

#ifdef __cplusplus
}
#endif

#endif
