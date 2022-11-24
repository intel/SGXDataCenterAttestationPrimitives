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


#ifndef _JNI_NATIVE_LIB_INIT_
#define _JNI_NATIVE_LIB_INIT_
#include <sgx_dcap_quoteverify.h>

int load_lib(void);
void unload_lib(void);  

typedef quote3_error_t (*sgx_qv_free_qve_identity_t)(
    uint8_t *p_qveid, uint8_t *p_qveid_issue_chain, uint8_t *p_root_ca_crl);
extern sgx_qv_free_qve_identity_t qvl_sgx_qv_free_qve_identity;
typedef quote3_error_t (*sgx_qv_get_quote_supplemental_data_size_t)(
    uint32_t *p_data_size);
extern sgx_qv_get_quote_supplemental_data_size_t
    qvl_sgx_qv_get_quote_supplemental_data_size;
typedef quote3_error_t (*sgx_qv_get_qve_identity_t)(
    uint8_t **pp_qveid, uint32_t *p_qveid_size, uint8_t **pp_qveid_issue_chain,
    uint32_t *p_qveid_issuer_chain_size, uint8_t **pp_root_ca_crl,
    uint16_t *p_root_ca_crl_size);
extern sgx_qv_get_qve_identity_t qvl_sgx_qv_get_qve_identity;
typedef quote3_error_t (*sgx_qv_set_enclave_load_policy_t)(
    sgx_ql_request_policy_t policy);
extern sgx_qv_set_enclave_load_policy_t qvl_sgx_qv_set_enclave_load_policy;
typedef quote3_error_t (*sgx_qv_set_path_t)(sgx_qv_path_type_t path_type,
                                            const char *p_path);
extern sgx_qv_set_path_t qvl_sgx_qv_set_path;
typedef quote3_error_t (*sgx_qv_verify_quote_t)(
    const uint8_t *p_quote, uint32_t quote_size,
    const sgx_ql_qve_collateral_t *p_quote_collateral,
    const time_t expiration_check_date,
    uint32_t *p_collateral_expiration_status,
    sgx_ql_qv_result_t *p_quote_verification_result,
    sgx_ql_qe_report_info_t *p_qve_report_info, uint32_t supplemental_data_size,
    uint8_t *p_supplemental_data);
extern sgx_qv_verify_quote_t qvl_sgx_qv_verify_quote;

typedef quote3_error_t (*tee_qv_get_collateral_t)(
    const uint8_t *p_quote,
    uint32_t quote_size,
    uint8_t **pp_quote_collateral,
    uint32_t *p_collateral_size);
extern tee_qv_get_collateral_t qvl_tee_qv_get_collateral;

typedef quote3_error_t (*tee_qv_free_collateral_t)(uint8_t *p_quote_collateral);
extern tee_qv_free_collateral_t qvl_tee_qv_free_collateral;

typedef quote3_error_t (*tee_get_supplemental_data_version_and_size_t)(
    const uint8_t *p_quote,
    uint32_t quote_size,
    uint32_t *p_version,
    uint32_t *p_data_size);
extern tee_get_supplemental_data_version_and_size_t qvl_tee_get_supplemental_data_version_and_size;

typedef quote3_error_t (*tee_tee_verify_quote_t)(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const uint8_t *p_quote_collateral,
    const time_t expiration_check_date,
    uint32_t *p_collateral_expiration_status,
    sgx_ql_qv_result_t *p_quote_verification_result,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    tee_supp_data_descriptor_t *p_supp_data_descriptor);
extern tee_tee_verify_quote_t qvl_tee_verify_quote;
#endif
