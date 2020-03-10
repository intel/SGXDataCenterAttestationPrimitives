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

#ifndef _CREATE_PARAM_H_
#define _CREATE_PARAM_H_

#include "metadata.h"
typedef struct _create_param_t
{
    uint64_t            stack_size;
    uint64_t            stack_max_size;     //from metadata
    uint64_t            heap_size;
    uint64_t            heap_max_size;      //from metadata
    uint32_t            tcs_num;
    uint32_t            tcs_max_num;        //from metadata
    sgx_attributes_t    attr;               //from metadata, flags contain information about secs attribute
    uint32_t            tcs_policy;         //from metadata
    uint32_t            ssa_frame_size;     //from metadata, The unit in metadata of ssa_frame_size is PAGE_SIZE
    uint32_t            ssa_num;            //from metadata
    uint32_t            reserved;           //added for alignment
    uint64_t            heap_offset;
    uint64_t            preferred_base_address; //the enclave preferred base address
    enclave_css_t       *enclave_css;       //from metadata
} create_param_t;

#endif
