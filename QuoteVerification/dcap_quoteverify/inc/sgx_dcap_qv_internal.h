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
#define REQUEST_ID_LEN 16
#define TIME_STR_LEN 24

#define TEE_PALTFORM_TOKEN_UUID "3123ec35-8d38-4ea5-87a5-d6c48b567570"
#define TEE_ENCLAVE_TOKEN_UUID "bef7cb8c-31aa-42c1-854c-10db005d5c41"
#define TEE_PLATFORM_TOKEN_VER "1.0"
#define TEE_ENCLAVE_TOKEN_VER "1.0"

#define TEE_TDX10_PALTFORM_TOKEN_UUID "9eec018b-7481-4b1c-8e1a-9f7c0c8c777f"
#define TEE_TDX15_PALTFORM_TOKEN_UUID "f708b97f-0fb2-4e6b-8b03-8a5bcd1221d3"
#define TEE_TDX_QE_IDENTITY_TOKEN_UUID "3769258c-75e6-4bc7-8d72-d2b0e224cad2"
#define TEE_TDX_TD10_IDENTITY_TOKEN_UUID "a1e4ee9c-a12e-48ac-bed0-e3f89297f687"
#define TEE_TDX_TD15_IDENTITY_TOKEN_UUID "45b734fc-aa4e-4c3d-ad28-e43d08880e68"
#define TEE_TDX_PLATFORM_TOKEN_VER "1.0"
#define TEE_TDX_QE_IDENTITY_TOKEN_VER "1.0"
#define TEE_TDX_TD_IDENTITY_TOKEN_VER "1.0"

typedef enum {
    UNKNOWN_REPORT_TYPE = 0,
    SGX_REPORT,
    TDX10_REPORT,
    TDX15_REPORT
} tee_qv_report_type_t;

typedef enum {
    SGX_EVIDENCE = 0,
    TDX_EVIDENCE,
    UNKNOWN_QUOTE_TYPE
} tee_evidence_type_t;

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
