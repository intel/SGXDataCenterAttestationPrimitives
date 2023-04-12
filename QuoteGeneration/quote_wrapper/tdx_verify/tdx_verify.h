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
/**
 * File: tdx_verify.h
 *
 * Description: API definitions for TDX Verification library
 *
 */
#ifndef _TDX_VERIFY_H_
#define _TDX_VERIFY_H_
#include <stdint.h>
#include "sgx_ql_lib_common.h"

typedef enum _tdx_verify_error_t
{
    TDX_VERIFY_SUCCESS = 0x0000,                        ///< Success
    TDX_VERIFY_ERROR_MIN = 0x0001,                      ///< Indicate min error to allow better translation.
    TDX_VERIFY_ERROR_UNEXPECTED = 0x0001,               ///< Unexpected error
    TDX_VERIFY_ERROR_INVALID_PARAMETER = 0x0002,        ///< The parameter is incorrect
    TDX_VERIFY_ERROR_OUT_OF_MEMORY = 0x0003,            ///< Not enough memory is available to complete this operation
    TDX_VERIFY_ERROR_VSOCK_FAILURE = 0x0004,            ///< vsock related failure
    TDX_VERIFY_ERROR_REPORT_FAILURE = 0x0005,           ///< Failed to get the TD Report
    TDX_VERIFY_ERROR_EXTEND_FAILURE = 0x0006,           ///< Failed to extend rtmr 
    TDX_VERIFY_ERROR_NOT_SUPPORTED = 0x0007,            ///< Request feature is not supported
    TDX_VERIFY_ERROR_QUOTE_FAILURE = 0x0008,            ///< Failed to get the TD Quote
    TDX_VERIFY_ERROR_BUSY = 0x0009,                     ///< The device driver return busy
    TDX_VERIFY_ERROR_MAX
} tdx_verify_error_t;

#if defined(__cplusplus)
extern "C"
{
#endif
    tdx_verify_error_t tdx_att_get_collateral (
        const uint8_t *fmspc, uint16_t fmspc_size, const char *pck_ca,
        tdx_ql_qve_collateral_t **p_verification_collateral);

    tdx_verify_error_t tdx_att_free_collateral (
        tdx_ql_qve_collateral_t *p_verification_collateral);

#if defined(__cplusplus)
}
#endif

#endif
