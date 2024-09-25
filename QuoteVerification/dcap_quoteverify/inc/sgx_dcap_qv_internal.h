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
 * File: sgx_dcap_qv_internal.h
 *
 * Description: Definitions and prototypes for the DCAP Verification Library
 *
 */

#ifndef _SGX_DCAP_QV_INTERNAL_H_
#define _SGX_DCAP_QV_INTERNAL_H_

#include "sgx_qve_header.h"
#include "sgx_ql_quote.h"
#include "sgx_error.h"
#include "sgx_eid.h"
#include <atomic>

#if defined(__cplusplus)
extern "C" {
#endif

#define SGX_QUOTE_TYPE 0x0
#define TDX_QUOTE_TYPE 0x81
#define USER_DATA_MAX_LEN 128

typedef enum {
    CLASS_SGX_QVL = 0,
    CLASS_SGX_QVE,
    CLASS_TDX_QVL,
    CLASS_TDX_QVE
} tee_class_type_t;

// Default policy is SGX_QL_EPHEMERAL, which is same with legacy DCAP QVL behavior
//
extern std::atomic<sgx_ql_request_policy_t> g_qve_policy;
extern std::atomic<bool> policy_set_once;

extern sgx_enclave_id_t g_qve_eid;

//SGX&TDX untrusted quote verification related APIs
//
quote3_error_t sgx_qvl_verify_quote(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const struct _sgx_ql_qve_collateral_t *p_quote_collateral,
    const time_t expiration_check_date,
    uint32_t *p_collateral_expiration_status,
    sgx_ql_qv_result_t *p_quote_verification_result,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    uint32_t supplemental_data_size,
    uint8_t *p_supplemental_data);

quote3_error_t  tee_qvl_verify_quote_qvt(
    const uint8_t *p_quote,
    uint32_t quote_size,
    time_t current_time,
    const sgx_ql_qve_collateral_t *p_quote_collateral,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    const uint8_t *p_user_data,
    uint32_t user_data_size,
    uint32_t *verification_result_token_buffer_size,
    uint8_t **p_verification_result_token);

void ocall_qvt_token_malloc(uint64_t verification_result_token_buffer_size,
    uint8_t **p_verification_result_token);

quote3_error_t sgx_qvl_get_quote_supplemental_data_size(
    uint32_t *p_data_size);

quote3_error_t sgx_qvl_get_quote_supplemental_data_version(
    uint32_t *p_version);


quote3_error_t qvl_get_fmspc_ca_from_quote(const uint8_t* p_quote, uint32_t quote_size,
     unsigned char* p_fmsp_from_quote, uint32_t fmsp_from_quote_size,
     unsigned char* p_ca_from_quote, uint32_t ca_from_quote_size);

sgx_status_t load_qve_once(sgx_enclave_id_t *p_qve_eid);

sgx_status_t unload_qve_once(sgx_enclave_id_t *p_qve_eid);

#if defined(__cplusplus)
}
#endif

#endif /* !_SGX_DCAP_QV_INTERNAL_H_*/
