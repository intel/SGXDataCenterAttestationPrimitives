/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
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

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include "sgx_utils.h"
#include "sgx_tcrypto.h"
#include "../../QvE/Include/qve_header.h"

sgx_status_t ecall_get_target_info(sgx_target_info_t* target_info) {
    return sgx_self_target(target_info);
}

sgx_status_t ecall_verify_report(sgx_ql_qe_report_info_t* p_report,
                                uint8_t* p_quote, 
                                uint64_t quote_size, 
                                time_t expiration_check_date,
                                uint32_t collateral_expiration_status, 
                                sgx_ql_qv_result_t verification_result, 
                                uint8_t* p_supplemental_data, 
                                uint32_t supplemental_data_size) {
    if (p_report == NULL || p_quote == NULL || quote_size == 0 || (p_supplemental_data != NULL && supplemental_data_size == 0)) {
        return SGX_ERROR_UNEXPECTED;
    }
    sgx_status_t sgx_status = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_sha_state_handle_t sha_handle = NULL;
    sgx_report_data_t report_data = { 0 };



    do {
        ret = sgx_verify_report(&p_report->qe_report);
        if (ret != SGX_SUCCESS) {
            break;
        }
        //report_data = SHA256([nonce || quote || expiration_check_date || expiration_status || verification_result || supplemental_data] || 32 - 0x00<92>s)
        //
        sgx_status = sgx_sha256_init(&sha_handle);
        SGX_ERR_BREAK(sgx_status);

        //nonce
        //
        sgx_status = sgx_sha256_update((p_report->nonce.rand), sizeof(p_report->nonce.rand), sha_handle);
        SGX_ERR_BREAK(sgx_status);

        //quote
        //
        sgx_status = sgx_sha256_update(p_quote, quote_size, sha_handle);
        SGX_ERR_BREAK(sgx_status);

        //expiration_check_date
        //
        sgx_status = sgx_sha256_update((const uint8_t*)&expiration_check_date, sizeof(expiration_check_date), sha_handle);
        SGX_ERR_BREAK(sgx_status);

        //collateral_expiration_status
        //
        sgx_status = sgx_sha256_update((uint8_t*)&collateral_expiration_status, sizeof(collateral_expiration_status), sha_handle);
        SGX_ERR_BREAK(sgx_status);

        //verification_result
        //
        sgx_status = sgx_sha256_update((uint8_t*)&verification_result, sizeof(verification_result), sha_handle);
        SGX_ERR_BREAK(sgx_status);


        //p_supplemental_data
        //
        if (p_supplemental_data) {
            sgx_status = sgx_sha256_update(p_supplemental_data, supplemental_data_size, sha_handle);
            SGX_ERR_BREAK(sgx_status);
        }

        //get the hashed report_data
        //
        sgx_status = sgx_sha256_get_hash(sha_handle, reinterpret_cast<sgx_sha256_hash_t *>(&report_data));
        SGX_ERR_BREAK(sgx_status);

        if (memcmp(&p_report->qe_report.body.report_data, &report_data, sizeof(report_data)) != 0) {
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }

        ret = SGX_SUCCESS;
    } while (0);

    return ret;
}

