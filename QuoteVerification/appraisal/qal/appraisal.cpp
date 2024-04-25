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

#include "sgx_dcap_qal.h"
#include <stdlib.h>
#include <string>
#include <sstream>
#include "opa_wasm.h"
#include "se_thread.h"
#include "se_trace.h"
#include "qal_json.h"

quote3_error_t tee_appraise_verification_token(
    const uint8_t *p_verification_result_token,
    uint8_t **p_qaps,
    uint8_t qaps_count,
    const time_t appraisal_check_date,
    sgx_ql_qe_report_info_t *p_qae_report_info,
    uint32_t *p_appraisal_result_token_buffer_size,
    uint8_t **p_appraisal_result_token)
{
    if (p_verification_result_token == NULL ||
        appraisal_check_date == 0 ||
        p_qae_report_info != NULL)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    if (p_appraisal_result_token_buffer_size == NULL || p_appraisal_result_token == NULL)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    if (p_qaps == NULL || qaps_count == 0)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    quote3_error_t ret = SGX_QL_ERROR_UNEXPECTED;

    std::string json_str = "";
    try
    {
        ret = construct_complete_json(p_verification_result_token, p_qaps, qaps_count, json_str);

        if (ret != SGX_QL_SUCCESS)
        {
            return ret;
        }
    }
    catch (...)
    {
        ret = SGX_QL_ERROR_INVALID_PARAMETER;
        return ret;
    }
    OPAEvaluateEngine instance;
    if((ret = instance.prepare_wasm()) != SGX_QL_SUCCESS)
    {
        return ret;
    }
    ret = instance.start_eval(reinterpret_cast<const uint8_t *>(json_str.c_str()), (uint32_t)(json_str.length() + 1), appraisal_check_date,
                              p_appraisal_result_token_buffer_size, p_appraisal_result_token);

    return ret;
}

quote3_error_t tee_free_appraisal_token(uint8_t *p_appraisal_result_token)
{
    if(p_appraisal_result_token == NULL)
        return SGX_QL_ERROR_INVALID_PARAMETER;
    free(p_appraisal_result_token);
    return SGX_QL_SUCCESS;
}


quote3_error_t tee_authenticate_appraisal_result(const uint8_t *p_appraisal_result_token, const tee_policy_bundle_t *p_policies, tee_policy_auth_result_t *result)
{
    quote3_error_t ret = SGX_QL_ERROR_UNEXPECTED;

    if(p_appraisal_result_token == NULL || p_policies == NULL || result == NULL)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    if ((p_policies->platform_policy.pt == CUSTOMIZED && p_policies->platform_policy.p_policy == NULL) ||
        (p_policies->platform_policy.pt == DEFAULT_STRICT && p_policies->platform_policy.p_policy != NULL) ||
        (p_policies->tdqe_policy.pt == CUSTOMIZED && p_policies->tdqe_policy.p_policy == NULL) ||
        (p_policies->tdqe_policy.pt == DEFAULT_STRICT && p_policies->tdqe_policy.p_policy != NULL))
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    for(size_t i = 0; i< sizeof(p_policies->reserved)/sizeof(p_policies->reserved[0]); i++)
    {
        if(p_policies->reserved[i].pt != 0 || p_policies->reserved[i].p_policy != NULL)
        {
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
    }

    ret = authenticate_appraisal_result_internal(p_appraisal_result_token, p_policies, result);
    return ret;
}

