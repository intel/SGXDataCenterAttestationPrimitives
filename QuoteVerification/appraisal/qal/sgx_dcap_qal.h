/**
* Copyright (c) 2017-2022, Intel Corporation
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
*    * Redistributions of source code must retain the above copyright notice,
*      this list of conditions and the following disclaimer.
*    * Redistributions in binary form must reproduce the above copyright
*      notice, this list of conditions and the following disclaimer in the
*      documentation and/or other materials provided with the distribution.
*    * Neither the name of Intel Corporation nor the names of its contributors
*      may be used to endorse or promote products derived from this software
*      without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE

* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _SGX_DCAP_QAL_H_
#define _SGX_DCAP_QAL_H_

#include "sgx_report.h"
#include "sgx_ql_lib_common.h"
#include "sgx_ql_quote.h"
#include <time.h>

typedef enum _tee_platform_policy_type_t
{
    DEFAULT_STRICT = 0,
    CUSTOMIZED
} tee_platform_policy_type_t;

typedef struct _tee_platform_policy_t
{
    tee_platform_policy_type_t pt;
    const uint8_t* p_policy;
} tee_platform_policy_t;

typedef struct _tee_policy_bundle_t
{
    const uint8_t *p_tenant_identity_policy;
    tee_platform_policy_t platform_policy;

    tee_platform_policy_t tdqe_policy;  /* For tdqe. Only for TDX and only need to be set when user uses a seperate tdqe_policy
                                         * instead of an integrated platform_policy including both TDX platform policy and TDQE. */

    tee_platform_policy_t reserved[2];  /* Reserved for future usage */
} tee_policy_bundle_t;

typedef enum _tee_policy_auth_result_t
{
    TEE_AUTH_INCOMPLET = -1,    /* Only part of the policies are provided and authenticated successfully. For example, you only input
                                 * SGX platform policy for an SGX appraisal token, and the platform policy is authenticated successfully */
    TEE_AUTH_SUCCESS = 0,       /* All the policies are authenticated successfully. For SGX, both SGX platform policies are provided and successfully */
    TEE_AUTH_FAILURE = 1,       /* At least one of the input policies are authenticated failed */
} tee_policy_auth_result_t;

#if defined(__cplusplus)
extern "C" {
#endif


/**
 * Appraise a Verification Result JWT against one or more Quote Appraisal Policies
 *
 * @param p_verification_result_token[IN] - Points to a null-terminated string containing the input Verification Result JWT.
 * @param p_qaps[IN] - Points to an array of pointers, with each pointer pointing to a buffer holding a quote appraisal policy JWT token. 
 *                     Each token is a null-terminated string holding a JWT.
 * @param qaps_count[IN] - The number of pointers in the p_qaps array.
 * @param appraisal_check_date[IN] - -	User input, used by the appraisal engine as its “current time” for expiration dates check.
 * @param p_qae_report_info[IN, OUT] - The parameter is optional. If not NULL, QAE is used in the appraisal process. It holds the QvE report and
 *                                     the ISV Enclave's target info as input. A QAE report will be returnted after this function completes.
 * @param p_appraisal_result_token_buffer_size[OUT] - Points to hold the size of the p_appraisal_result_token buffer.
 * @param p_appraisal_result_token[OUT] - Points to the output Appraisal result JWT.
 *
 * @return Status code of the operation. SGX_QL_SUCCESS or failure as defined in sgx_ql_lib_common.h
 **/
quote3_error_t tee_appraise_verification_token(
    const uint8_t *p_verification_result_token,
    uint8_t **p_qaps,
    uint8_t qaps_count,
    const time_t appraisal_check_date,
    sgx_ql_qe_report_info_t *p_qae_report_info,
    uint32_t *p_appraisal_result_token_buffer_size,
    uint8_t **p_appraisal_result_token);

/**
 * Free the appraisal result token that allocated in the "tee_appraise_verification_token" API
 * @param p_appraisal_result_token[IN] - Points to the output Appraisal result JWT.
 *
 * @return Status code of the operation. SGX_QL_SUCCESS or failure as defined in sgx_ql_lib_common.h
**/
quote3_error_t tee_free_appraisal_token(uint8_t *p_appraisal_result_token);

/**
 * Check whether the input policies are used in the appraisal process by comparing the policies with the appraisal result
 *
 * @param p_appraisal_result_token[IN] - Points to the Appraisal result JWT that generated by the "tee_appraise_verification_token" API
 * @param p_policies[IN] - A structure that contains the target policies
 * @param result[OUT] - the authentication result
 *
 * @return Status code of the operation. SGX_QL_SUCCESS or failure as defined in sgx_ql_lib_common.h
**/
quote3_error_t tee_authenticate_appraisal_result(const uint8_t *p_appraisal_result_token, const tee_policy_bundle_t *p_policies, tee_policy_auth_result_t *result);


/**
 * An expert implememntation to check whether the input policies are used in the appraisal process by comparing the policies with the appraisal result.
 *
 * @param p_quote[IN] - Optional. If not NULL, QAL will validate the quote hash in appraisal result with this input quote
 * @param quote_size[IN] - Quote size. If p_quote is NULL, quote_size should be 0
 * @param p_appraisal_result_token[IN] - Points to the Appraisal result JWT that generated by the "tee_appraise_verification_token" API
 * @param p_policies[IN] - A structure that contains the target policies
 * @param p_td_identity[IN] - Optional. Pointer to tenant TD identity structure. It's a placeholder to support self signed TD identity in future.
 * @param p_td_tcb_mapping_table[IN] - Optional. Pointer to tenant TD TCB mapping table. It's a placeholder to support self signed TD TCB mapping table in future.
 * @param result[OUT] - the authentication result
 * @param p_qae_report_info[IN, OUT] - The parameter is optional. If not NULL, QAE is used to authenticate the policies and a QAE report will be returned.
 *
 * @return Status code of the operation. SGX_QL_SUCCESS or failure as defined in sgx_ql_lib_common.h
**/
quote3_error_t tee_authenticate_appraisal_result_ex(const uint8_t *p_quote,
                                                    uint32_t quote_size,
                                                    const uint8_t *p_appraisal_result_token,
                                                    const tee_policy_bundle_t *p_policies,
                                                    const uint8_t *p_td_identity,
                                                    const uint8_t *p_td_tcb_mapping_table,
                                                    tee_policy_auth_result_t *result,
                                                    sgx_ql_qe_report_info_t *p_qae_report_info);

/**
 * Check whether the input policies that are used in the appraisal process are signed by the specific owners.
 *
 * @param p_quote[IN] - Optional. If not NULL, QAL will validate the quote hash in appraisal result with this input quote
 * @param quote_size[IN] - Quote size. If p_quote is NULL, quote_size should be 0
 * @param p_appraisal_result_token[IN] - Points to the Appraisal result JWT that generated by the "tee_appraise_verification_token" API
 * @param policy_key_list[IN] - Points to an array of pointers, with each pointer pointing to a buffer holding a policy signing key.
 * @param list_size[IN]  - The policy signing key number.
 * @param p_td_identity[IN] - Optional. Pointer to tenant TD identity structure. It's a placeholder to support self signed TD identity in future.
 * @param p_td_tcb_mapping_table[IN] - Optional. Pointer to tenant TD TCB mapping table. It's a placeholder to support self signed TD TCB mapping table in future.
 * @param result[OUT] - the authentication result
 * @param p_qae_report_info[IN/OUT] - This parameter can be used in 2 ways:
 *        If p_qae_report_info is NOT NULL, the API will use Intel QAE to check the policies owner and appraisal result, and QAE will generate a report
 *           using the target_info in sgx_ql_qe_report_info_t structure. You should verify the report and QAE identity by using API in Intel TVL library.
 *        If p_qae_report_info is NULL, the API will use QVL library to check the policies owner and appraisal result, note that the results cannot be
 *           cryptographically authenticated in this mode.
 *
 * @return Status code of the operation. SGX_QL_SUCCESS or failure as defined in sgx_ql_lib_common.h
 **/
quote3_error_t tee_authenticate_policy_owner(const uint8_t *p_quote,
                                             uint32_t quote_size,
                                             const uint8_t *p_appraisal_result_token,
                                             const uint8_t **policy_key_list,
                                             uint32_t list_size,
                                             const uint8_t *p_td_identity,
                                             const uint8_t *p_td_tcb_mapping_table,
                                             tee_policy_auth_result_t *result,
                                             sgx_ql_qe_report_info_t *p_qae_report_info);

/**
 * Set QAE's loading policy.
 * Supported policies:
 *    SGX_QL_EPHEMERAL -  QAE is initialized and terminated on every appraisal function call.
 *    SGX_QL_PERSISTENT - Default policy. The process will share one single QAE instance.
 *                        QAE is initialized on first use and reused until process ends.
 * @param policy[in] - The enclave loading policy to be set.
 *
 * @return Status code of the operation. SGX_QL_SUCCESS or failure as defined in sgx_ql_lib_common.h
 *
 **/
quote3_error_t sgx_qae_set_enclave_load_policy(sgx_ql_request_policy_t policy);

#if defined(__cplusplus)
}
#endif

#endif