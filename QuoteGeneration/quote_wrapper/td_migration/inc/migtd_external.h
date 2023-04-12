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

#ifndef _MIGTD_EXTERNAL_H_
#define _MIGTD_EXTERNAL_H_

#include <stdint.h>
/* Used in Get Quote request memory allocation */
#define PAGE_SIZE 0x1000
#define GET_QUOTE_MAX_SIZE (4 * PAGE_SIZE)

#define EIO 5     /* I/O error */
#define EINVAL 22 /* Invalid argument */

#if defined(__cplusplus)
extern "C"
{
#endif

/**
 *
 * Get quote interface provided by MigTD Core for MigTD Attestation
 * library use.
 *
 * @param tdquote_req_buf [in, out] the pointer to tdquote request buffer
 * @param len             [in, out] the length of request buffer, should not be larger than GET_QUOTE_MAX_SIZE
 *
 * @return 0: Successfully get quote via TDVMCALL.GET_QUOTE.
 * @return -EIO: TDVMCALL returns error failed to get quote.
 * @return -EINVAL: Invalid input argument.
 *
**/
int migtd_get_quote(const void* tdquote_req_buf, const uint64_t len);

#if defined(__cplusplus)
}
#endif

#endif