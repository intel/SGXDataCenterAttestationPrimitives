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

#ifndef _MIGTD_COMMON_H_
#define _MIGTD_COMMON_H_

#include <stdint.h>

#define PAGE_SIZE 0x1000
#define HEADER_SIZE 4

#ifndef SAFE_FREE
#define SAFE_FREE(ptr)          {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#endif

#pragma pack(push, 1)

/* TD Quote status codes */
#define GET_QUOTE_SUCCESS 0
#define GET_QUOTE_IN_FLIGHT 0xffffffffffffffff
#define GET_QUOTE_ERROR 0x8000000000000000
#define GET_QUOTE_SERVICE_UNAVAILABLE 0x8000000000000001

struct migtd_tdx_quote_hdr {
    /* Quote version, filled by TD */
    uint64_t version;
    /* Status code of Quote request, filled by VMM */
    uint64_t status;
    /* Length of TDREPORT, filled by TD */
    uint32_t in_len;
    /* Length of Quote, filled by VMM */
    uint32_t out_len;
    /* Actual Quote data or TDREPORT on input */
    uint64_t data[0];
};

static const unsigned MIGTD_HEADER_SIZE = 4;
static const uint32_t MIGTD_REQ_BUF_SIZE = 16 * 4 * 1024; // 16 pages

#pragma pack(pop)

#endif