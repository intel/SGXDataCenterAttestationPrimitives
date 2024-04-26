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
  * File: sgx_dcap_quoteverify.cpp
  *
  * Description: Quote Verification Library
  */

#include "sgx_dcap_quoteverify.h"
#include "sgx_dcap_pcs_com.h"
#include "sgx_dcap_qv_internal.h"
#include "sgx_qve_def.h"
#include "tee_qv_class.h"
#include <stdlib.h>
#include <stdio.h>
#include <new>
#include <memory>
#include <mutex>
#include "se_trace.h"
#include "se_thread.h"
#include "se_memcpy.h"
#include "sgx_urts_wrapper.h"

thread_local std::shared_ptr<tee_qv_base> p_tee_qv = NULL;
std::shared_ptr<tee_qv_base> global_tee_qv = NULL;
sgx_enclave_id_t g_qve_eid = 0;
std::mutex qve_mutex;

// Default policy is SGX_QL_EPHEMERAL, which is same with legacy DCAP QVL behavior
//
std::atomic<sgx_ql_request_policy_t> g_qve_policy(SGX_QL_EPHEMERAL);
std::atomic<bool> policy_set_once(false);

thread_local tee_class_type_t current_class_type = CLASS_SGX_QVL;

//redefine uRTS functions to remove sgx_urts library dependency during compilcation
//
extern "C" sgx_status_t SGXAPI sgx_ecall(const sgx_enclave_id_t eid,
                              const int index,
                              const void* ocall_table,
                              void* ms)
{
    if (!sgx_dcap_load_urts()) {
        return SGX_ERROR_FEATURE_NOT_SUPPORTED;
    }

    return p_sgx_urts_ecall(eid, index, ocall_table, ms);
}


extern "C" void sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
    if (!sgx_dcap_load_urts()) {
        return;
    }

    return p_sgx_oc_cpuidex(cpuinfo, leaf, subleaf);
}

extern "C" int sgx_thread_wait_untrusted_event_ocall(const void *self)
{
    if (!sgx_dcap_load_urts()) {
        return SGX_ERROR_UNEXPECTED;
    }

    return p_sgx_thread_wait_untrusted_event_ocall(self);
}

extern "C" int sgx_thread_set_untrusted_event_ocall(const void *waiter)
{
    if (!sgx_dcap_load_urts()) {
        return SGX_ERROR_UNEXPECTED;
    }

    return p_sgx_thread_set_untrusted_event_ocall(waiter);
}

extern "C" int sgx_thread_setwait_untrusted_events_ocall(const void *waiter, const void *self)
{
    if (!sgx_dcap_load_urts()) {
        return SGX_ERROR_UNEXPECTED;
    }

    return p_sgx_thread_setwait_untrusted_events_ocall(waiter, self);
}

extern "C" int sgx_thread_set_multiple_untrusted_events_ocall(const void **waiters, size_t total)
{
    if (!sgx_dcap_load_urts()) {
        return SGX_ERROR_UNEXPECTED;
    }

    return p_sgx_thread_set_multiple_untrusted_events_ocall(waiters, total);
}


#ifdef __GNUC__
extern "C" int pthread_create_ocall(unsigned long long self)
{
    if (!sgx_dcap_load_urts()) {
        return SGX_ERROR_UNEXPECTED;
    }

    return p_pthread_create_ocall(self);
}

extern "C" int pthread_wait_timeout_ocall(unsigned long long waiter, unsigned long long timeout)
{
    if (!sgx_dcap_load_urts()) {
        return SGX_ERROR_UNEXPECTED;
    }

    return p_pthread_wait_timeout_ocall(waiter, timeout);
}

extern "C" int pthread_wakeup_ocall(unsigned long long waiter)
{
    if (!sgx_dcap_load_urts()) {
        return SGX_ERROR_UNEXPECTED;
    }

    return p_pthread_wakeup_ocall_func(waiter);
}
#endif

static quote3_error_t sgx_error_to_quote3_error(sgx_status_t err)
{
    switch (err)
    {
    case SGX_SUCCESS:
        return SGX_QL_SUCCESS;
    case SGX_ERROR_OUT_OF_EPC:
        return SGX_QL_OUT_OF_EPC;
    case SGX_ERROR_OUT_OF_MEMORY:
        return SGX_QL_ERROR_OUT_OF_MEMORY;
    case SGX_ERROR_INVALID_PARAMETER:
        return SGX_QL_ERROR_INVALID_PARAMETER;
    default:
        return SGX_QL_ERROR_UNEXPECTED;
    }
}

std::unique_ptr<tee_qv_base> create_instance(tee_class_type_t type)
{
    switch(type) {
        case CLASS_SGX_QVL:
            return std::make_unique<sgx_qv>();

        case CLASS_SGX_QVE:
            return std::make_unique<sgx_qv_trusted>();

        case CLASS_TDX_QVL:
            return std::make_unique<tdx_qv>();

        case CLASS_TDX_QVE:
            return std::make_unique<tdx_qv_trusted>();

        default:
            return nullptr;
    }
}

/**
 * Internal function - get supplemental data size and version.
 **/
static quote3_error_t get_verification_supplemental_data_size_and_version(
    uint32_t *p_data_size,
    uint32_t *p_version) {

    if (NULL_POINTER(p_data_size)) {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    supp_ver_t untrusted_version;
    untrusted_version.version = 0;
    uint32_t untrusted_size = 0;
    quote3_error_t qve_ret = SGX_QL_ERROR_INVALID_PARAMETER;

    do {
        //call untrusted API to get supplemental data version
        //
        qve_ret = sgx_qvl_get_quote_supplemental_data_version(&untrusted_version.version);
        if (qve_ret != SGX_QL_SUCCESS) {
            SE_TRACE(SE_TRACE_DEBUG, "Error: untrusted API qvl_get_quote_supplemental_data_version failed: 0x%04x\n", qve_ret);
            *p_data_size = 0;
            break;
        }

        //call untrusted API to get supplemental data size
        //
        qve_ret = sgx_qvl_get_quote_supplemental_data_size(&untrusted_size);
        if (qve_ret != SGX_QL_SUCCESS) {
            SE_TRACE(SE_TRACE_DEBUG, "Error: untrusted API qvl_get_quote_supplemental_data_size failed: 0x%04x\n", qve_ret);
            *p_data_size = 0;
            break;
        }

        if (p_data_size != NULL)
            *p_data_size = untrusted_size;
        if (p_version != NULL)
            *p_version = untrusted_version.version;

    } while (0) ;

    return qve_ret;
}

quote3_error_t sgx_qv_set_enclave_load_policy(
    sgx_ql_request_policy_t policy)
{
    std::lock_guard<std::mutex> lock(qve_mutex);

    if (policy < SGX_QL_PERSISTENT || policy > SGX_QL_PERSISTENT_QVE_MULTI_THREAD)
        return SGX_QL_UNSUPPORTED_LOADING_POLICY;

    if (policy_set_once) {
        SE_TRACE(SE_TRACE_ERROR, "Err: QvE load policy has already been set once in current process.\n");
        return SGX_QL_UNSUPPORTED_LOADING_POLICY;
    }

    g_qve_policy = policy;
    policy_set_once = true;

    return SGX_QL_SUCCESS;
}

/**
 * Get supplemental data latest version and required size.
 **/
quote3_error_t tee_get_supplemental_data_version_and_size(
    const uint8_t *p_quote,
    uint32_t quote_size,
    uint32_t *p_version,
    uint32_t *p_data_size) {

    if (CHECK_MANDATORY_PARAMS(p_quote, quote_size) ||
        quote_size < QUOTE_MIN_SIZE ||
        (p_version == NULL && p_data_size == NULL))
        return SGX_QL_ERROR_INVALID_PARAMETER;

    return get_verification_supplemental_data_size_and_version(p_data_size, p_version);
}

void unload_persistent_qve()
{
    //Try to unload QvE only when use legacy PERSISTENT policy
    //All the threads will share single QvE instance in this mode
    //
    if (g_qve_policy == SGX_QL_PERSISTENT) {
        if (g_qve_eid != 0) {
            //ignore the return error
            unload_qve_once(&g_qve_eid);
            g_qve_eid = 0;
        }
    }
}

static quote3_error_t tee_verify_evidence_internal(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const sgx_ql_qve_collateral_t *p_quote_collateral,
    const time_t expiration_check_date,
    uint32_t *p_collateral_expiration_status,
    sgx_ql_qv_result_t *p_quote_verification_result,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    uint32_t supplemental_data_size,
    uint8_t *p_supplemental_data,
    std::shared_ptr<tee_qv_base> p_qv)
{

    quote3_error_t qve_ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_status_t sgx_ret = SGX_SUCCESS;
    unsigned char fmspc_from_quote[FMSPC_SIZE] = { 0 };
    unsigned char ca_from_quote[CA_SIZE] = { 0 };
    struct _sgx_ql_qve_collateral_t* qve_collaterals_from_qp = NULL;

    if (!p_qv)
        return SGX_QL_ERROR_UNEXPECTED;

    do {
        //try to load QvE if user wants to use trusted quote verification
        //
        if (current_class_type == CLASS_SGX_QVE || current_class_type == CLASS_TDX_QVE) {
            if (g_qve_policy == SGX_QL_PERSISTENT || g_qve_policy == SGX_QL_EPHEMERAL) {

                if (g_qve_eid == 0) {
                    sgx_ret = load_qve_once(&g_qve_eid);

                    if (g_qve_policy == SGX_QL_PERSISTENT) {
                        //register the termination function
                        //only used for QvE persistent mode
                        //Don't treat the atexit error as critical error, because it will not block any functionality
                        if (0 != (atexit(unload_persistent_qve))) {
                            SE_TRACE(SE_TRACE_ERROR, "Err: Register 'unload_persistent_qve' failed.\n");
                        }
                    }
                }

                p_qv->set_eid(g_qve_eid);
            }

            //Only legacy mode share single QvE in multi-threads, other modes load QvE per thread
            //
            else {
                sgx_ret = p_qv->load_qve();
            }

            if (sgx_ret != SGX_SUCCESS) {
                qve_ret = sgx_error_to_quote3_error(sgx_ret);
                break;
            }
        }

        //validate supplemental data size if using QvE
        //
        if (p_supplemental_data && p_qve_report_info) {
            quote3_error_t tmp_ret = SGX_QL_ERROR_UNEXPECTED;
            uint32_t tmp_size = 0;

            //supplemental size from QvE
            tmp_ret = p_qv->tee_get_supplemental_data_size(&tmp_size);

            if (tmp_ret != SGX_QL_SUCCESS) {

                if (p_quote_verification_result) {
                    *p_quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
                }

                qve_ret = SGX_QL_ERROR_UNEXPECTED;
                break;
            }

            if (tmp_size != supplemental_data_size) {
                if (p_quote_verification_result) {
                    *p_quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
                }

                qve_ret = SGX_QL_ERROR_QVL_QVE_MISMATCH;
                break;
            }
        }

        //in case input collateral is NULL, dynamically load and call QPL to retrieve verification collateral
        //
        if (NULL_POINTER(p_quote_collateral)) {

            //extract fmspc and CA from the quote, these values are required inorder to query collateral from QPL
            //
            qve_ret = p_qv->tee_get_fmspc_ca_from_quote(p_quote, quote_size, fmspc_from_quote, FMSPC_SIZE, ca_from_quote, CA_SIZE);
            if (qve_ret == SGX_QL_SUCCESS) {
                SE_TRACE(SE_TRACE_DEBUG, "Info: get_fmspc_ca_from_quote successfully returned.\n");
            }
            else {
                SE_TRACE(SE_TRACE_DEBUG, "Error: get_fmspc_ca_from_quote failed: 0x%04x\n", qve_ret);
                break;
            }

            //retrieve verification collateral using QPL
            //
            qve_ret = p_qv->tee_get_verification_endorsement(
                (const char *)fmspc_from_quote,
                FMSPC_SIZE,
                (const char *)ca_from_quote,
                &qve_collaterals_from_qp);
            if (qve_ret == SGX_QL_SUCCESS) {
                SE_TRACE(SE_TRACE_DEBUG, "Info: dcap_retrieve_verification_collateral successfully returned.\n");
            }
            else {
                SE_TRACE(SE_TRACE_DEBUG, "Error: dcap_retrieve_verification_collateral failed: 0x%04x\n", qve_ret);
                break;
            }
            p_quote_collateral = qve_collaterals_from_qp;
        }

        qve_ret = p_qv->tee_verify_evidence(
            p_quote, quote_size,
            p_quote_collateral,
            expiration_check_date,
            p_collateral_expiration_status,
            p_quote_verification_result,
            p_qve_report_info,
            supplemental_data_size,
            p_supplemental_data);
        if (qve_ret == SGX_QL_SUCCESS) {
            SE_TRACE(SE_TRACE_DEBUG, "Info: verify_quote successfully returned.\n");
        }
        else {
            SE_TRACE(SE_TRACE_DEBUG, "Error: verify_quote failed: 0x%04x\n", qve_ret);
            break;
        }

    } while (0);

    //free verification collateral using QPL
    //
    if (qve_collaterals_from_qp) {
        p_qv->tee_free_verification_endorsement(qve_collaterals_from_qp);
    }

    //unload QvE if set policy to ephemeral
    //
    if (g_qve_policy == SGX_QL_EPHEMERAL ||
        g_qve_policy == SGX_QL_EPHEMERAL_QVE_MULTI_THREAD) {

        sgx_ret = p_qv->unload_qve();
        g_qve_eid = 0;

        if (sgx_ret != SGX_SUCCESS) {
            qve_ret = sgx_error_to_quote3_error(sgx_ret);
        }
    }

    return qve_ret;
}

/**
 * Perform ECDSA quote verification
 **/
quote3_error_t tee_verify_evidence(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const sgx_ql_qve_collateral_t *p_quote_collateral,
    const time_t expiration_check_date,
    uint32_t *p_collateral_expiration_status,
    sgx_ql_qv_result_t *p_quote_verification_result,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    uint32_t supplemental_data_size,
    uint8_t *p_supplemental_data) {

    //validate input parameters
    //
    if (CHECK_MANDATORY_PARAMS(p_quote, quote_size) ||
        quote_size < QUOTE_MIN_SIZE ||
        NULL_POINTER(p_collateral_expiration_status) ||
        expiration_check_date == 0 ||
        NULL_POINTER(p_quote_verification_result) ||
        CHECK_OPT_PARAMS(p_supplemental_data, supplemental_data_size)) {
        //one or more invalid parameters
        //
        if (p_quote_verification_result) {
            *p_quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
        }
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    //parse quote header to get tee type, only support SGX and TDX by now
    tee_evidence_type_t tee_type = UNKNOWN_QUOTE_TYPE;

    //check quote type
    uint32_t *p_type = (uint32_t *) (p_quote + sizeof(uint16_t) * 2);

    if (*p_type == SGX_QUOTE_TYPE) {
        SE_TRACE(SE_TRACE_DEBUG, "Info: Quote type - SGX quote.\n");
        tee_type = SGX_EVIDENCE;
    }
    else if (*p_type == TDX_QUOTE_TYPE) {
        SE_TRACE(SE_TRACE_DEBUG, "Info: Quote type - TDX quote.\n");
        tee_type = TDX_EVIDENCE;
    }
    else {
        SE_TRACE(SE_TRACE_ERROR, "Err: Unsupported quote type.\n");
        //quote type is not supported
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    quote3_error_t qve_ret = SGX_QL_ERROR_UNEXPECTED;
    tee_class_type_t class_type = CLASS_SGX_QVL;

    if (p_qve_report_info) {
        if (tee_type == SGX_EVIDENCE)
            class_type = CLASS_SGX_QVE;
        if (tee_type == TDX_EVIDENCE)
            class_type = CLASS_TDX_QVE;
    }

    //untrsuted quote verification
    //
    else {
        if (tee_type == SGX_EVIDENCE)
            class_type = CLASS_SGX_QVL;
        if (tee_type == TDX_EVIDENCE)
            class_type = CLASS_TDX_QVL;
    }

    if (g_qve_policy == SGX_QL_PERSISTENT || g_qve_policy == SGX_QL_EPHEMERAL) {

        std::lock_guard<std::mutex> lock(qve_mutex);

        if (global_tee_qv || class_type != current_class_type) {
            //reset the object if the type change in next thread
            global_tee_qv.reset();
            global_tee_qv = NULL;

            SE_TRACE(SE_TRACE_DEBUG, "Info: Reset global tee qve instance.\n");
        }

        if (!global_tee_qv) {
            global_tee_qv = create_instance(class_type);
            if (global_tee_qv == nullptr) {
                SE_TRACE(SE_TRACE_ERROR, "Error: cannot create tee qv instance.\n");
                goto end;
            }
        }

        current_class_type = class_type;

        qve_ret = tee_verify_evidence_internal(
            p_quote,
            quote_size,
            p_quote_collateral,
            expiration_check_date,
            p_collateral_expiration_status,
            p_quote_verification_result,
            p_qve_report_info,
            supplemental_data_size,
            p_supplemental_data,
            global_tee_qv);
    }

    else if (g_qve_policy == SGX_QL_EPHEMERAL_QVE_MULTI_THREAD || g_qve_policy == SGX_QL_PERSISTENT_QVE_MULTI_THREAD) {

        if (p_tee_qv && class_type != current_class_type) {
            //reset the object if the type change in next thread
            //
            p_tee_qv.reset();
        }

        if (!p_tee_qv) {
            p_tee_qv = create_instance(class_type);
            if (p_tee_qv == nullptr) {
                SE_TRACE(SE_TRACE_ERROR, "Error: cannot create tee qv instance.\n");
                goto end;
            }
        }

        current_class_type = class_type;

        qve_ret = tee_verify_evidence_internal(
            p_quote,
            quote_size,
            p_quote_collateral,
            expiration_check_date,
            p_collateral_expiration_status,
            p_quote_verification_result,
            p_qve_report_info,
            supplemental_data_size,
            p_supplemental_data,
            p_tee_qv);
    }

    else {
        //invalid policy
        //
        qve_ret = SGX_QL_UNSUPPORTED_LOADING_POLICY;
        goto end;
    }

end:
    return qve_ret;
}

/**
 * Get SGX QvE identity and Root CA CRL
 **/
quote3_error_t sgx_qv_get_qve_identity(
         uint8_t **pp_qveid,
         uint32_t *p_qveid_size,
         uint8_t **pp_qveid_issue_chain,
         uint32_t *p_qveid_issue_chain_size,
         uint8_t **pp_root_ca_crl,
         uint16_t *p_root_ca_crl_size) {

    return sgx_dcap_retrieve_qve_identity(pp_qveid,
                                          p_qveid_size,
                                          pp_qveid_issue_chain,
                                          p_qveid_issue_chain_size,
                                          pp_root_ca_crl,
                                          p_root_ca_crl_size);
}


/**
 * Free SGX QvE identity and Root CA CRL
 **/
quote3_error_t sgx_qv_free_qve_identity(
        uint8_t *p_qveid,
        uint8_t *p_qveid_issue_chain,
        uint8_t *p_root_ca_crl) {

    return sgx_dcap_free_qve_identity(p_qveid,
                                      p_qveid_issue_chain,
                                      p_root_ca_crl);
}

/**
 * Get SGX supplemental data required size.
 **/
quote3_error_t sgx_qv_get_quote_supplemental_data_size(uint32_t *p_data_size)
{
    return get_verification_supplemental_data_size_and_version(p_data_size, NULL);
}

/**
 * Perform SGX ECDSA quote verification
 **/
quote3_error_t sgx_qv_verify_quote(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const sgx_ql_qve_collateral_t *p_quote_collateral,
    const time_t expiration_check_date,
    uint32_t *p_collateral_expiration_status,
    sgx_ql_qv_result_t *p_quote_verification_result,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    uint32_t supplemental_data_size,
    uint8_t *p_supplemental_data)
{
    quote3_error_t ret = SGX_QL_SUCCESS;

    // set supplemental version if necessary
    if (p_supplemental_data != NULL && supplemental_data_size > 0) {
        try {
            reinterpret_cast<sgx_ql_qv_supplemental_t*> (p_supplemental_data)->version = SUPPLEMENTAL_DATA_VERSION;
        }

        catch(...) {
            // cannot access p_supplemental_data field
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
    }

    ret = tee_verify_evidence(
        p_quote,
        quote_size,
        p_quote_collateral,
        expiration_check_date,
        p_collateral_expiration_status,
        p_quote_verification_result,
        p_qve_report_info,
        supplemental_data_size,
        p_supplemental_data);

    // clear version info
    if (ret != SGX_QL_SUCCESS && p_supplemental_data != NULL) {
        memset(p_supplemental_data, 0, sizeof(*p_supplemental_data));
    }

    return ret;
}

/**
 * Get TDX supplemental data required size.
 **/
quote3_error_t tdx_qv_get_quote_supplemental_data_size(uint32_t *p_data_size)
{
    return get_verification_supplemental_data_size_and_version(p_data_size, NULL);
}

/**
 * Perform TDX ECDSA quote verification
 **/
quote3_error_t tdx_qv_verify_quote(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const tdx_ql_qv_collateral_t *p_quote_collateral,
    const time_t expiration_check_date,
    uint32_t *p_collateral_expiration_status,
    sgx_ql_qv_result_t *p_quote_verification_result,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    uint32_t supplemental_data_size,
    uint8_t *p_supplemental_data)
{
    quote3_error_t ret = SGX_QL_SUCCESS;

    // set supplemental version if necessary
    if (p_supplemental_data != NULL && supplemental_data_size > 0) {
        try {
            reinterpret_cast<sgx_ql_qv_supplemental_t*> (p_supplemental_data)->version = SUPPLEMENTAL_DATA_VERSION;
        }

        catch(...) {
            // cannot access p_supplemental_data field
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
    }

    ret = tee_verify_evidence(
       p_quote,
       quote_size,
       p_quote_collateral,
       expiration_check_date,
       p_collateral_expiration_status,
       p_quote_verification_result,
       p_qve_report_info,
        supplemental_data_size,
        p_supplemental_data);

    // clear version info
    if (ret != SGX_QL_SUCCESS && p_supplemental_data != NULL) {
        memset(p_supplemental_data, 0, sizeof(*p_supplemental_data));
    }

    return ret;
}


/**
 * @brief retrieve verification colloateral
 *
 */
quote3_error_t tee_qv_get_collateral(
    const uint8_t *p_quote,
    uint32_t quote_size,
    uint8_t **pp_quote_collateral,
    uint32_t *p_collateral_size)
{
    quote3_error_t ret = SGX_QL_SUCCESS;
    unsigned char fmspc_from_quote[FMSPC_SIZE] = {0};
    unsigned char ca_from_quote[CA_SIZE] = {0};
    if (CHECK_MANDATORY_PARAMS(p_quote, quote_size) ||
         quote_size < QUOTE_MIN_SIZE ||
         pp_quote_collateral == NULL ||
         *pp_quote_collateral != NULL ||
         p_collateral_size == NULL)
        return SGX_QL_ERROR_INVALID_PARAMETER;
    // skip version and att_key_type in SGX or TDX quote
    uint32_t quote_type = *((uint32_t *)(p_quote + sizeof(uint16_t) + sizeof(uint16_t)));
    *p_collateral_size = 0;

    ret = qvl_get_fmspc_ca_from_quote(
        p_quote,
        quote_size,
        fmspc_from_quote,
        FMSPC_SIZE,
        ca_from_quote,
        CA_SIZE);
    if (ret != SGX_QL_SUCCESS)
    {
        return ret;
    }
    if (quote_type == SGX_QUOTE_TYPE)
    { // little endian 0x0 means SGX
        ret = sgx_dcap_retrieve_verification_collateral((const char *)fmspc_from_quote,
                                                        FMSPC_SIZE,
                                                        (const char *)ca_from_quote,
                                                        (sgx_ql_qve_collateral_t **)pp_quote_collateral);
        if (ret == SGX_QL_SUCCESS)
        {
		 *p_collateral_size =
                (uint32_t)sizeof(sgx_ql_qve_collateral_t) +
                ((sgx_ql_qve_collateral_t *)(*pp_quote_collateral))
                    ->pck_crl_issuer_chain_size +
                ((sgx_ql_qve_collateral_t *)(*pp_quote_collateral))
                    ->root_ca_crl_size +
                ((sgx_ql_qve_collateral_t *)(*pp_quote_collateral))
                    ->pck_crl_size +
                ((sgx_ql_qve_collateral_t *)(*pp_quote_collateral))
                    ->tcb_info_issuer_chain_size +
                ((sgx_ql_qve_collateral_t *)(*pp_quote_collateral))
                    ->qe_identity_issuer_chain_size +
                ((sgx_ql_qve_collateral_t *)(*pp_quote_collateral))
                    ->qe_identity_size +
                ((sgx_ql_qve_collateral_t *)(*pp_quote_collateral))
                    ->tcb_info_size;
	    }
    }
    else if (quote_type == TDX_QUOTE_TYPE)
    { // little endian 0x81 means TDX
        ret = tdx_dcap_retrieve_verification_collateral((const char *)fmspc_from_quote,
                                                        FMSPC_SIZE,
                                                        (const char *)ca_from_quote,
                                                        (tdx_ql_qv_collateral_t **)pp_quote_collateral);
        if (ret == SGX_QL_SUCCESS)
        {
		 *p_collateral_size =
                (uint32_t)sizeof(tdx_ql_qv_collateral_t) +
                ((tdx_ql_qv_collateral_t *)(*pp_quote_collateral))
                    ->pck_crl_issuer_chain_size +
                ((tdx_ql_qv_collateral_t *)(*pp_quote_collateral))
                    ->root_ca_crl_size +
                ((tdx_ql_qv_collateral_t *)(*pp_quote_collateral))
                    ->pck_crl_size +
                ((tdx_ql_qv_collateral_t *)(*pp_quote_collateral))
                    ->tcb_info_issuer_chain_size +
                ((tdx_ql_qv_collateral_t *)(*pp_quote_collateral))
                    ->qe_identity_issuer_chain_size +
                ((tdx_ql_qv_collateral_t *)(*pp_quote_collateral))
                    ->qe_identity_size +
                ((tdx_ql_qv_collateral_t *)(*pp_quote_collateral))
                    ->tcb_info_size;
	    }
    }
    else
    {
        // quote type is not supported
        ret = SGX_QL_ERROR_INVALID_PARAMETER;
    }

    return ret;
}


/**
 * @brief free verification colloateral
 *
 */
quote3_error_t tee_qv_free_collateral(uint8_t *p_quote_collateral)
{
    quote3_error_t ret = SGX_QL_SUCCESS;
    if (p_quote_collateral == NULL)

        return SGX_QL_ERROR_INVALID_PARAMETER;

    const sgx_ql_qve_collateral_t *p_collater =
        reinterpret_cast<const sgx_ql_qve_collateral_t *>(p_quote_collateral);
    if (p_collater->tee_type == SGX_QUOTE_TYPE)
    {
        ret = sgx_dcap_free_verification_collateral((sgx_ql_qve_collateral_t *)p_quote_collateral);
    }
    else if (p_collater->tee_type == TDX_QUOTE_TYPE)
    {
        ret = tdx_dcap_free_verification_collateral((tdx_ql_qv_collateral_t *)p_quote_collateral);
    }
    else
    {
        // quote type is not supported
        ret = SGX_QL_ERROR_INVALID_PARAMETER;
    }
    return ret;
}


/**
 * Perform quote verification for SGX and TDX
 * This API works the same as the old one, but takes a new parameter to describe the supplemental data (p_supp_data_descriptor)
 **/
quote3_error_t tee_verify_quote(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const uint8_t *p_quote_collateral,
    const time_t expiration_check_date,
    uint32_t *p_collateral_expiration_status,
    sgx_ql_qv_result_t *p_quote_verification_result,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    tee_supp_data_descriptor_t *p_supp_data_descriptor)
{
    quote3_error_t ret = SGX_QL_SUCCESS;
    supp_ver_t latest_version;
    uint32_t supp_data_size = 0;
    uint32_t tmp_size = 0;
    uint8_t *p_supp_data = NULL;

    // only check quote, other parameters will be checked in internal functions
    if (CHECK_MANDATORY_PARAMS(p_quote, quote_size) ||
         quote_size < QUOTE_MIN_SIZE)
        return SGX_QL_ERROR_INVALID_PARAMETER;

    ret = tee_get_supplemental_data_version_and_size(p_quote, quote_size, &latest_version.version, &tmp_size);

    if (ret != SGX_QL_SUCCESS)
        return ret;

    try {
        // check supplemental descriptor
        if (p_supp_data_descriptor != NULL) {

            if (p_supp_data_descriptor->p_data == NULL)
                return SGX_QL_ERROR_INVALID_PARAMETER;

            if (p_supp_data_descriptor->major_version > latest_version.major_version)
                return SGX_QL_SUPPLEMENTAL_DATA_VERSION_NOT_SUPPORTED;

            // major version <= latest support version
            else {
                // Only support major version 0 and 3 in current stage
                if ((p_supp_data_descriptor->major_version != 0 && p_supp_data_descriptor->major_version != SUPPLEMENTAL_DATA_VERSION) ||
                        p_supp_data_descriptor->data_size != tmp_size)
                    return SGX_QL_ERROR_INVALID_PARAMETER;

                // only support version 3 by now, may add additional logic to match major version and minor version in future
                memset(p_supp_data_descriptor->p_data, 0, p_supp_data_descriptor->data_size);

                // set version in supplemental data
                reinterpret_cast<sgx_ql_qv_supplemental_t*> (p_supp_data_descriptor->p_data)->major_version = SUPPLEMENTAL_DATA_VERSION;
                reinterpret_cast<sgx_ql_qv_supplemental_t*> (p_supp_data_descriptor->p_data)->minor_version = SUPPLEMENTAL_V3_LATEST_MINOR_VERSION;

                // size will be checked in internal logic
                supp_data_size = p_supp_data_descriptor->data_size;
                p_supp_data = p_supp_data_descriptor->p_data;
            }
        }
    }

    catch (...) {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    ret = tee_verify_evidence(
        p_quote,
        quote_size,
        reinterpret_cast<const sgx_ql_qve_collateral_t*> (p_quote_collateral),
        expiration_check_date,
        p_collateral_expiration_status,
        p_quote_verification_result,
        p_qve_report_info,
        supp_data_size,
        p_supp_data);

    if (ret != SGX_QL_SUCCESS && p_supp_data_descriptor != NULL && p_supp_data_descriptor->p_data != NULL) {
        // defense in depth
        memset(p_supp_data_descriptor->p_data, 0, sizeof(sgx_ql_qve_collateral_t));
    }

    return ret;
}

/**
 * @brief Extrace FMSPC from a given quote with cert type 5
 * @param p_quote[IN] - Pointer to a quote buffer.
 * @param quote_size[IN] - Size of input quote buffer.
 * @param p_fmspc_from_quote[IN/OUT] - Pointer to a buffer to write fmspc to.
 * @param fmspc_from_quote_size[IN] - Size of fmspc buffer.
 *
 * @return Status code of the operation, one of:
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_ERROR_INVALID_PARAMETER
 *      - SGX_QL_ERROR_UNEXPECTED
 *      - SGX_QL_PCK_CERT_CHAIN_ERROR
 *      - SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED
 */
quote3_error_t tee_get_fmspc_from_quote(const uint8_t *p_quote,
                                        uint32_t quote_size,
                                        uint8_t *p_fmspc_from_quote,
                                        uint32_t fmspc_from_quote_size) {
  if (CHECK_MANDATORY_PARAMS(p_quote, quote_size) ||
       quote_size < QUOTE_MIN_SIZE ||
       p_fmspc_from_quote == NULL ||
       fmspc_from_quote_size < FMSPC_SIZE) {
    return SGX_QL_ERROR_INVALID_PARAMETER;
  }

  unsigned char ca_from_quote[CA_SIZE] = {0};
  return qvl_get_fmspc_ca_from_quote(
        p_quote,
        quote_size,
        p_fmspc_from_quote,
        FMSPC_SIZE,
        ca_from_quote,
        CA_SIZE);
}


#ifndef _MSC_VER

#include <sys/types.h>
#include <sys/stat.h>

/**
 * This API can be used to set the full path of QVE and QPL library.
 *
 * The function takes the enum and the corresponding full path.
 *
 * @param path_type The type of binary being passed in.
 * @param p_path It should be a valid full path.
 *
 * @return SGX_QL_SUCCESS  Successfully set the full path.
 * @return SGX_QL_ERROR_INVALID_PARAMETER p_path is not a valid full path or the path is too long.
 */

quote3_error_t sgx_qv_set_path(
        sgx_qv_path_type_t path_type,
        const char *p_path)
{
    quote3_error_t ret = SGX_QL_SUCCESS;
    bool temp_ret = false;

    struct stat info;

    if (!p_path){
        return(SGX_QL_ERROR_INVALID_PARAMETER);
    }

    if(stat(p_path, &info) != 0){
        return(SGX_QL_ERROR_INVALID_PARAMETER);
    }
    else if((info.st_mode & S_IFREG) == 0){
        return(SGX_QL_ERROR_INVALID_PARAMETER);
    }

    switch(path_type)
    {
        case SGX_QV_QVE_PATH:
            temp_ret = sgx_qv_set_qve_path(p_path);
            ret = temp_ret ? SGX_QL_SUCCESS : SGX_QL_ERROR_INVALID_PARAMETER;
            break;
        case SGX_QV_QPL_PATH:
            temp_ret = sgx_qv_set_qpl_path(p_path);
            ret = temp_ret ? SGX_QL_SUCCESS : SGX_QL_ERROR_INVALID_PARAMETER;
            break;
    default:
        ret = SGX_QL_ERROR_INVALID_PARAMETER;
        break;
    }
    return(ret);
}


#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "rapidjson/document.h"
#include "jwt-cpp/jwt.h"
#include "openssl/rand.h"
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <time.h>

#include "QuoteVerification/Quote.h"
#include "sgx_quote_4.h"
#include "sgx_quote_5.h"
#include "OpensslHelpers/Bytes.h"
#include "sgx_base64.h"

/*
•	SGX_QL_QV_RESULT_OK: “UpToDate”
•	SGX_QL_QV_RESULT_SW_HARDENING_NEEDED: “UpToDate”, “SWHardeningNeeded”
•	SGX_QL_QV_RESULT_CONFIG_NEEDED: “UpToDate”, “ConfigurationNeeded”
•	SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED: “UpToDate”, “SWHardeningNeeded”, “ConfigurationNeeded”
•	SGX_QL_QV_RESULT_OUT_OF_DATE: “OutOfDate”
•	SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED: “OutOfDate”, “ConfigurationNeeded”
•	SGX_QL_QV_RESULT_INVALID_SIGNATURE: No Platform TCB Report Generated
•	SGX_QL_QV_RESULT_REVOKED: “Revoked”
•	SGX_QL_QV_RESULT_UNSPECIFIED: No Platform TCB Report Generated
*/

static void qv_result_tcb_status_map(std::vector<std::string>& tcb_status, sgx_ql_qv_result_t qv_result){
    switch (qv_result){
    case TEE_QV_RESULT_OK:
        tcb_status.push_back("UpToDate");
        break;
    case TEE_QV_RESULT_SW_HARDENING_NEEDED:
        tcb_status.push_back("UpToDate");
        tcb_status.push_back("SWHardeningNeeded");
        break;
    case TEE_QV_RESULT_CONFIG_NEEDED:
        tcb_status.push_back("UpToDate");
        tcb_status.push_back("ConfigurationNeeded");
        break;
    case TEE_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
        tcb_status.push_back("UpToDate");
        tcb_status.push_back("SWHardeningNeeded");
        tcb_status.push_back("ConfigurationNeeded");
        break;
    case TEE_QV_RESULT_OUT_OF_DATE:
        tcb_status.push_back("OutOfDate");
        break;
    case TEE_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        tcb_status.push_back("OutOfDate");
        tcb_status.push_back("ConfigurationNeeded");
        break;
    case TEE_QV_RESULT_TD_RELAUNCH_ADVISED:
        tcb_status.push_back("TDRelaunchAdvised");
        break;
    case TEE_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED:
        tcb_status.push_back("TDRelaunchAdvised");
        tcb_status.push_back("ConfigurationNeeded");
        break;
    case TEE_QV_RESULT_INVALID_SIGNATURE:
        break;
    case TEE_QV_RESULT_REVOKED:
        tcb_status.push_back("Revoked");
        break;
    case TEE_QV_RESULT_UNSPECIFIED:
        break;
    default:
        break;
}
    return;
}

static void advisory_id_vec(std::vector<std::string>& vec_ad_id, std::string s_ad_id)
{
    std::stringstream stream_ad;
    stream_ad << s_ad_id;
    std::string temp;
    
    while(getline(stream_ad, temp, ','))
    {
        vec_ad_id.push_back(temp);
    }
    return;
}

//transfer Byte to hex string
static std::string byte_to_hexstring(const uint8_t* data, size_t len)
{
    if(data == NULL){
       return {};
    }
    std::vector<uint8_t> tmp_vec(data, data + len);
    reverse(tmp_vec.begin(), tmp_vec.end());    //align the endian in the appraisal
    return intel::sgx::dcap::bytesToHexString(tmp_vec);

}

//TO DO in Enclave
//time transfer to ISO 8601 standard (YYYY-MM-DDThh:mm:ssZ)
static void time_to_string(time_t time_before, char* time_str, size_t len)
{
    if(time_str==NULL){
        return;
    }
    struct tm *nowtm;
    //transfer UTC to gmtime
    nowtm = gmtime(&time_before);
    //transfer to ISO 8601 standard (YYYY-MM-DDThh:mm:ssZ)
    if(nowtm==NULL){
        return;
    }
    strftime(time_str, len,"%Y-%m-%dT%H:%M:%SZ", nowtm);
    return;
}

static std::string char_to_base64(unsigned char const* raw_char, size_t len)
{
    if(raw_char == NULL){
       return {};
    }

    std::string s_ret;
    
    //remove '\0'
    if(len == strlen(reinterpret_cast<const char *>(raw_char)) + 1){
        len--;
    }
    char* tmp_str = base64_encode(reinterpret_cast<const char *>(raw_char), len);
    if(tmp_str == NULL)
    {
        return {};
    }
    s_ret = tmp_str;
    return s_ret;
}

static quote3_error_t sgx_jwt_generator_internal(const char *plat_type,
    const char *plat_version,
    const char *enclave_type,
    const char *enclave_version,
    uint16_t quote_ver,
    const char *request_id,
    sgx_ql_qv_result_t qv_result,
    time_t verification_date,
    const sgx_ql_qv_supplemental_t *p_supplemental_data,
    const uint8_t *p_quote,
    const uint32_t quote_size,
    const sgx_ql_qve_collateral_t *p_quote_collateral,
    uint32_t *jwt_size,
    uint8_t **jwt_data
    )
{
    if(CHECK_MANDATORY_PARAMS(p_quote, quote_size) || quote_size < QUOTE_MIN_SIZE ||
    plat_version == NULL || enclave_type == NULL || enclave_version == NULL ||
    request_id == NULL || p_quote_collateral == NULL || p_supplemental_data == NULL)
    {
        return TEE_ERROR_INVALID_PARAMETER;
    }
    if(quote_ver != intel::sgx::dcap::constants::QUOTE_VERSION_5 && quote_ver != intel::sgx::dcap::constants::QUOTE_VERSION_3)
    {
        return TEE_ERROR_INVALID_PARAMETER;
    }
    using namespace rapidjson;
    Document JWT;
    JWT.SetObject();

    Document::AllocatorType &allocator = JWT.GetAllocator();
    if(&allocator == NULL)
    {
        return TEE_ERROR_UNEXPECTED;
    }

    Value obj_platform(kObjectType);
    Value obj_plat_header(kObjectType);
    Value sgx_jwt_array(kArrayType);
    std::string platform_desc = "SGX Platform TCB";

    //Generate platform_tcb
    Value str_type_val(kStringType);
    str_type_val.SetString(plat_type, (unsigned int)strlen(plat_type), allocator);
    if(str_type_val.GetStringLength() != 0){
        obj_plat_header.AddMember("class_id", str_type_val, allocator);
    }
    str_type_val.SetString(platform_desc.c_str(), (unsigned int)(platform_desc.length()), allocator);
    if(str_type_val.GetStringLength() != 0){
        obj_plat_header.AddMember("description", str_type_val, allocator);
    }
    
    obj_platform.AddMember("environment", obj_plat_header, allocator);

    Value obj_plat_tcb(kObjectType);
    Value tcb_status_array(kArrayType);
    Value str_tcb_status(kStringType);

    std::vector<std::string> tcb_status;
    qv_result_tcb_status_map(tcb_status, qv_result);
    if(!tcb_status.empty())
    {
        for(size_t i=0; i<tcb_status.size(); i++){
            str_tcb_status.SetString(tcb_status[i].c_str(), (unsigned int)(tcb_status[i].length()), allocator);
            tcb_status_array.PushBack(str_tcb_status, allocator);
        }
        obj_plat_tcb.AddMember("tcb_status", tcb_status_array, allocator);
    }

    if(p_supplemental_data != NULL){
        char time_str[TIME_STR_LEN] = {0};
        Value str_date(kStringType);
        auto Add_Mem = [&](char *str_m, rapidjson::GenericValue<rapidjson::UTF8<> >::StringRefType mem_name){str_date.SetString(str_m, (unsigned int)strlen(str_m), allocator);
                            if(str_date.GetStringLength() != 0){obj_plat_tcb.AddMember(mem_name, str_date, allocator);}};

        time_to_string(p_supplemental_data->earliest_issue_date, time_str, sizeof(time_str));
        Add_Mem(time_str, "earliest_issue_date");

        time_to_string(p_supplemental_data->latest_issue_date, time_str, sizeof(time_str));
        Add_Mem(time_str, "latest_issue_date");

        time_to_string(p_supplemental_data->earliest_expiration_date, time_str, sizeof(time_str));
        Add_Mem(time_str, "earliest_expiration_date");
        
        time_to_string(p_supplemental_data->tcb_level_date_tag, time_str, sizeof(time_str));
        Add_Mem(time_str, "tcb_level_date_tag");

        obj_plat_tcb.AddMember("pck_crl_num", p_supplemental_data->pck_crl_num, allocator);
        obj_plat_tcb.AddMember("root_ca_crl_num", p_supplemental_data->root_ca_crl_num, allocator);
        obj_plat_tcb.AddMember("tcb_eval_num", p_supplemental_data->tcb_eval_ref_num, allocator);

        //TODO
        //obj_plat_tcb.AddMember("platform_provider_id", , allocator);

        obj_plat_tcb.AddMember("sgx_types", p_supplemental_data->sgx_type, allocator);

        if(p_supplemental_data->dynamic_platform != PCK_FLAG_UNDEFINED){
            Value dynamic_plat;
            dynamic_plat.SetBool(p_supplemental_data->dynamic_platform);
            obj_plat_tcb.AddMember("is_dynamic_platform", dynamic_plat, allocator);
        }


        if(p_supplemental_data->cached_keys != PCK_FLAG_UNDEFINED){
            Value cached_keys;
            cached_keys.SetBool(p_supplemental_data->cached_keys);
            obj_plat_tcb.AddMember("is_cached_keys_policy", cached_keys, allocator);
        }

        if(p_supplemental_data->smt_enabled != PCK_FLAG_UNDEFINED){
            Value smt_enabled;
            smt_enabled.SetBool(p_supplemental_data->smt_enabled);
            obj_plat_tcb.AddMember("is_smt_enabled", smt_enabled, allocator);
        }

        Value advisory_id_array(kArrayType);
        Value str_advisory_id(kStringType);
        if (p_supplemental_data->version > 3 && strlen(p_supplemental_data->sa_list) > 0) {
            std::string s_ad_id(p_supplemental_data->sa_list);
            std::vector<std::string> vec_ad_id;
            advisory_id_vec(vec_ad_id, s_ad_id);
            if(!vec_ad_id.empty())
            {
                for(size_t i=0; i<vec_ad_id.size(); i++){
                    str_advisory_id.SetString(vec_ad_id[i].c_str(), (unsigned int)(vec_ad_id[i].length()), allocator);
                    advisory_id_array.PushBack(str_advisory_id, allocator);
                }
            obj_plat_tcb.AddMember("advisory_ids", advisory_id_array, allocator);
            }
        }
        Value str_keyid(kStringType);
        std::string s_root_key_id = byte_to_hexstring(p_supplemental_data->root_key_id, ROOT_KEY_ID_SIZE);
        str_keyid.SetString(s_root_key_id.c_str(), (unsigned int)(s_root_key_id.length()), allocator);
        if(str_keyid.GetStringLength() != 0){
            obj_plat_tcb.AddMember("root_key_id", str_keyid, allocator);
        }
    }

    //get fmpsc from quote
    quote3_error_t ret = TEE_SUCCESS;
    unsigned char fmspc_from_quote[FMSPC_SIZE] = {0};
    unsigned char ca_from_quote[CA_SIZE] = {0};

    ret = qvl_get_fmspc_ca_from_quote(
        p_quote,
        quote_size,
        fmspc_from_quote,
        FMSPC_SIZE,
        ca_from_quote,
        CA_SIZE);
    if(ret == TEE_SUCCESS)
    {
        Value str_fmspc(kStringType);
        std::string sfmspc((char* )fmspc_from_quote, FMSPC_SIZE);
        std::reverse(sfmspc.begin(), sfmspc.end()); //endian align
        std::string s_fmspc = byte_to_hexstring((const uint8_t *)sfmspc.c_str(), FMSPC_SIZE);
        str_fmspc.SetString(s_fmspc.c_str(), (unsigned int)s_fmspc.length(), allocator);
        if(str_fmspc.GetStringLength() != 0)
        {
            obj_plat_tcb.AddMember("fmspc", str_fmspc, allocator);
        }
    }

    obj_platform.AddMember("measurement", obj_plat_tcb, allocator);

    /*
    "pck_crl_issuer_chain" : base64 encoding,
    "root_ca_crl" : base64 encoding,
    "pck_crl" : base64 encoding,
    "tcb_info_issuer_chain" : base64 encoding,
    "tcb_info" : base64 encoding,
    "qe_identity_issuer_chain" : base64 encoding,
    "qe_identity" : base64 encoding
    */
   
    //Generate endorsement
    if(p_quote_collateral != NULL){
        Value obj_collateral(kObjectType);
        Value str_collateral(kStringType);
        auto Add_Mem = [&](std::string str_m, rapidjson::GenericValue<rapidjson::UTF8<> >::StringRefType mem_name){str_collateral.SetString(str_m.c_str(), (unsigned int)(str_m.length()), allocator);
                            if(str_collateral.GetStringLength() != 0){obj_collateral.AddMember(mem_name, str_collateral, allocator);}};
        if(p_quote_collateral->pck_crl_issuer_chain != NULL && p_quote_collateral->pck_crl_issuer_chain_size > 0){
            std::string s_pck_crl_issue_chain = char_to_base64((reinterpret_cast<unsigned char const*>(p_quote_collateral->pck_crl_issuer_chain)), p_quote_collateral->pck_crl_issuer_chain_size);
            Add_Mem(s_pck_crl_issue_chain, "pck_crl_issuer_chain");
        }

        if(p_quote_collateral->root_ca_crl != NULL && p_quote_collateral->root_ca_crl_size > 0){
            std::string s_root_ca_crl = char_to_base64((reinterpret_cast<unsigned char const*>(p_quote_collateral->root_ca_crl)), p_quote_collateral->root_ca_crl_size);
            Add_Mem(s_root_ca_crl, "root_ca_crl");
        }

        if(p_quote_collateral->pck_crl != NULL && p_quote_collateral->pck_crl_size > 0){
            std::string s_pck_crl = char_to_base64((reinterpret_cast<unsigned char const*>(p_quote_collateral->pck_crl)), p_quote_collateral->pck_crl_size);
            Add_Mem(s_pck_crl, "pck_crl");
        }

        if(p_quote_collateral->tcb_info_issuer_chain != NULL && p_quote_collateral->tcb_info_issuer_chain_size > 0){
            std::string s_tcb_info_issuer_chain = char_to_base64((reinterpret_cast<unsigned char const*>(p_quote_collateral->tcb_info_issuer_chain)), p_quote_collateral->tcb_info_issuer_chain_size);
            Add_Mem(s_tcb_info_issuer_chain, "tcb_info_issuer_chain");
        }

        if(p_quote_collateral->tcb_info != NULL && p_quote_collateral->tcb_info_size > 0){
            std::string s_tcb_info = char_to_base64((reinterpret_cast<unsigned char const*>(p_quote_collateral->tcb_info)), p_quote_collateral->tcb_info_size);
            Add_Mem(s_tcb_info, "tcb_info");
        }

        if(p_quote_collateral->qe_identity_issuer_chain != NULL && p_quote_collateral->qe_identity_issuer_chain_size > 0){
            std::string s_qe_identity_issuer_chain = char_to_base64((reinterpret_cast<unsigned char const*>(p_quote_collateral->qe_identity_issuer_chain)), p_quote_collateral->qe_identity_issuer_chain_size);
            Add_Mem(s_qe_identity_issuer_chain, "qe_identity_issuer_chain");
        }

        if(p_quote_collateral->qe_identity != NULL && p_quote_collateral->qe_identity_size > 0){
            std::string s_qe_identity = char_to_base64((reinterpret_cast<unsigned char const*>(p_quote_collateral->qe_identity)), p_quote_collateral->qe_identity_size);
            Add_Mem(s_qe_identity, "qe_identity");
        }

        obj_platform.AddMember("certification_data", obj_collateral, allocator);
    }


    Value obj_plat_audit(kObjectType);
    Value str_requestid(kStringType);

    std::string s_request_id = char_to_base64((reinterpret_cast<unsigned char const*>(request_id)), strlen(request_id));
    str_requestid.SetString(s_request_id.c_str(), (unsigned int)(s_request_id.length()), allocator);
    if(str_requestid.GetStringLength() != 0){
        obj_plat_audit.AddMember("request_id", str_requestid, allocator);
    }

    char verifytime_str[TIME_STR_LEN] = {0};
    time_to_string(verification_date, verifytime_str, sizeof(verifytime_str));
    Value str_ver_date(kStringType);
    str_ver_date.SetString(verifytime_str, (unsigned int)strlen(verifytime_str), allocator);
    if(str_ver_date.GetStringLength() != 0){
        obj_plat_audit.AddMember("verification_time", str_ver_date, allocator);
    }

    obj_platform.AddMember("audit", obj_plat_audit, allocator);

    sgx_jwt_array.PushBack(obj_platform, allocator);

    //Generate enclave_tcb
    Value obj_enclave(kObjectType);
    Value obj_enclave_header(kObjectType);
    Value obj_enclave_tcb(kObjectType);
    std::string enclave_desc = "SGX Enclave TCB";

    Value str_enclave_type_val(kStringType);
    str_enclave_type_val.SetString(enclave_type, (unsigned int)strlen(enclave_type), allocator);
    if(str_enclave_type_val.GetStringLength() != 0){
        obj_enclave_header.AddMember("class_id", str_enclave_type_val, allocator);
    }
    str_enclave_type_val.SetString(enclave_desc.c_str(), (unsigned int)(enclave_desc.length()), allocator);
    if(str_enclave_type_val.GetStringLength() != 0){
        obj_enclave_header.AddMember("description", str_enclave_type_val, allocator);
    }

    obj_enclave.AddMember("environment", obj_enclave_header, allocator);

    if(p_quote != NULL){
        sgx_report_body_t sgx_report;
        memset(&sgx_report, 0, sizeof(sgx_report_body_t));
        if(quote_ver == intel::sgx::dcap::constants::QUOTE_VERSION_3)
        {
            const sgx_quote3_t *p_tmp_quote3 = reinterpret_cast<const sgx_quote3_t *> (p_quote);
            memcpy(&sgx_report, (void *)&(p_tmp_quote3->report_body), sizeof(sgx_report_body_t));
        }
        else if(quote_ver == intel::sgx::dcap::constants::QUOTE_VERSION_5)
        {
            const sgx_quote5_t *p_tmp_quote5 = reinterpret_cast<const sgx_quote5_t *> (p_quote);
            memcpy(&sgx_report, p_tmp_quote5->body, sizeof(sgx_report_body_t));
        }
        else {
            return TEE_ERROR_INVALID_PARAMETER;
        }
        
        Value str_encl(kStringType);
        auto Add_Mem = [&](std::string str_m, rapidjson::GenericValue<rapidjson::UTF8<> >::StringRefType mem_name){str_encl.SetString(str_m.c_str(), (unsigned int)(str_m.length()), allocator);
                            if(str_encl.GetStringLength() != 0){obj_enclave_tcb.AddMember(mem_name, str_encl, allocator);}};

        std::string s_miscselect = byte_to_hexstring((uint8_t *) &(sgx_report.misc_select), sizeof(sgx_misc_select_t));
        Add_Mem(s_miscselect, "sgx_miscselect");

        std::string s_attributes = byte_to_hexstring((uint8_t *) &(sgx_report.attributes), sizeof(sgx_attributes_t));
        Add_Mem(s_attributes, "sgx_attributes");

        //TO DO
        //writer.Key("ce_attributes");
        
        std::string s_mrenclave = byte_to_hexstring((uint8_t *) &(sgx_report.mr_enclave.m), sizeof(sgx_measurement_t));
        Add_Mem(s_mrenclave, "sgx_mrenclave");

        std::string s_mrsigner = byte_to_hexstring(sgx_report.mr_signer.m, sizeof(sgx_measurement_t));
        Add_Mem(s_mrsigner, "sgx_mrsigner");

        obj_enclave_tcb.AddMember("sgx_isvprodid", sgx_report.isv_prod_id, allocator);
        obj_enclave_tcb.AddMember("sgx_isvsvn", sgx_report.isv_svn, allocator);

        std::string s_configid = byte_to_hexstring(sgx_report.config_id, SGX_CONFIGID_SIZE);
        Add_Mem(s_configid, "sgx_configid");

        obj_enclave_tcb.AddMember("sgx_configsvn", sgx_report.config_svn, allocator);
        
        std::string s_isvexprodid = byte_to_hexstring(sgx_report.isv_ext_prod_id, SGX_ISVEXT_PROD_ID_SIZE);
        Add_Mem(s_isvexprodid, "sgx_isvextprodid");

        std::string s_isvfamilyid = byte_to_hexstring(sgx_report.isv_family_id, SGX_ISV_FAMILY_ID_SIZE);
        Add_Mem(s_isvfamilyid, "sgx_isvfamilyid");

        std::string s_reportdata = byte_to_hexstring(sgx_report.report_data.d, sizeof(sgx_report_data_t));
        Add_Mem(s_reportdata, "sgx_reportdata");

        obj_enclave.AddMember("measurement", obj_enclave_tcb, allocator);
    }

    Value obj_enclave_audit(kObjectType);
    Value str_enc_request_id(kStringType);

    std::string s_enc_request_id = char_to_base64((reinterpret_cast<unsigned char const*>(request_id)), REQUEST_ID_LEN);
    str_enc_request_id.SetString(s_enc_request_id.c_str(), (unsigned int)(s_enc_request_id.length()), allocator);
    if(str_enc_request_id.GetStringLength() != 0){
        obj_enclave_audit.AddMember("request_id", str_enc_request_id, allocator);
    }

    char enc_verifytime_str[TIME_STR_LEN] = {0};
    time_to_string(verification_date, enc_verifytime_str, sizeof(enc_verifytime_str));
    Value str_enc_ver_date(kStringType);
    str_enc_ver_date.SetString(enc_verifytime_str, (unsigned int)strlen(enc_verifytime_str), allocator);
    if(str_enc_ver_date.GetStringLength() != 0){
        obj_enclave_audit.AddMember("verification_time", str_enc_ver_date, allocator);
    }

    obj_enclave.AddMember("audit", obj_enclave_audit, allocator);

    sgx_jwt_array.PushBack(obj_enclave, allocator);
    JWT.AddMember("qvl_result", sgx_jwt_array, allocator);

    rapidjson::StringBuffer str_buff;
    rapidjson::Writer<rapidjson::StringBuffer> writer(str_buff);
    JWT.Accept(writer);

    std::string raw_data = str_buff.GetString();
    if(raw_data.empty())
    {
        return TEE_ERROR_UNEXPECTED;
    }

	auto qal_token = jwt::create()
					 .set_issuer("qal")
					 .set_type("JWT")
					 .set_payload_claim("qvl_result", jwt::claim(raw_data))
					 .sign(jwt::algorithm::none());

    if(qal_token.empty())
    {
        return TEE_ERROR_UNEXPECTED;
    }

    *jwt_data = (uint8_t*)malloc(qal_token.length() + 1);
    if (*jwt_data == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    memset(*jwt_data, 0, qal_token.length() + 1);
    memcpy_s(*jwt_data, qal_token.length() + 1, qal_token.c_str(), qal_token.length());
    *jwt_size = (uint32_t)qal_token.length();
    return TEE_SUCCESS;
}

static quote3_error_t tdx_jwt_generator_internal(uint16_t quote_ver,
    uint16_t report_type,
    const char *plat_version,
    const char *qe_identity_version,
    const char *td_identity_version,
    const uint8_t *p_user_data,
    const char *request_id,
    sgx_ql_qv_result_t qv_result,
    time_t verification_date,
    const sgx_ql_qv_supplemental_t *p_supplemental_data,
    const uint8_t *p_quote,
    const uint32_t quote_size,
    const sgx_ql_qve_collateral_t *p_quote_collateral,
    uint32_t *jwt_size,
    uint8_t **jwt_data
    )
{
    if(CHECK_MANDATORY_PARAMS(p_quote, quote_size) || quote_size < QUOTE_MIN_SIZE ||
    plat_version == NULL || qe_identity_version == NULL || td_identity_version == NULL || 
    request_id == NULL || p_supplemental_data == NULL || p_quote_collateral == NULL){
        return TEE_ERROR_INVALID_PARAMETER;
    }
    if(report_type != TDX10_REPORT && report_type != TDX15_REPORT){
        return TEE_ERROR_INVALID_PARAMETER;
    }
    const sgx_quote4_t *quote4 = reinterpret_cast<const sgx_quote4_t *> (p_quote);
    if(quote4->header.tee_type != intel::sgx::dcap::constants::TEE_TYPE_TDX){
        return TEE_ERROR_INVALID_PARAMETER;
    }
    using namespace rapidjson;
    Document JWT;
    JWT.SetObject();

    Document::AllocatorType &allocator = JWT.GetAllocator();
    if(&allocator == NULL)
    {
        return TEE_ERROR_UNEXPECTED;
    }


    Value tdx_jwt_array(kArrayType); 

    Value obj_platform(kObjectType);
    Value obj_plat_header(kObjectType);
    std::string platform_desc = "TDX Platform TCB";

    //Generate platform_tcb
    Value str_type_val(kStringType);
    if(report_type == TDX10_REPORT)
        str_type_val.SetString(TEE_TDX10_PALTFORM_TOKEN_UUID, (unsigned int)strlen(TEE_TDX10_PALTFORM_TOKEN_UUID), allocator);
    else
        str_type_val.SetString(TEE_TDX15_PALTFORM_TOKEN_UUID, (unsigned int)strlen(TEE_TDX15_PALTFORM_TOKEN_UUID), allocator);
    if(str_type_val.GetStringLength() != 0){
        obj_plat_header.AddMember("class_id", str_type_val, allocator);
    }
    str_type_val.SetString(platform_desc.c_str(), (unsigned int)(platform_desc.length()), allocator);
    if(str_type_val.GetStringLength() != 0){
        obj_plat_header.AddMember("description", str_type_val, allocator);
    }
    
    obj_platform.AddMember("environment", obj_plat_header, allocator);

    Value obj_plat_tcb(kObjectType);
    Value tcb_status_array(kArrayType);
    Value str_tcb_status(kStringType);

    std::vector<std::string> tcb_status;
    qv_result_tcb_status_map(tcb_status, qv_result);
    if(!tcb_status.empty())
    {
        for(size_t i=0; i<tcb_status.size(); i++){
            str_tcb_status.SetString(tcb_status[i].c_str(), (unsigned int)(tcb_status[i].length()), allocator);
            tcb_status_array.PushBack(str_tcb_status, allocator);
        }
        obj_plat_tcb.AddMember("tcb_status", tcb_status_array, allocator);
    }

    if(p_supplemental_data != NULL){
        char time_str[TIME_STR_LEN] = {0};
        Value str_date(kStringType);
        auto Add_Mem = [&](char *str_m, rapidjson::GenericValue<rapidjson::UTF8<> >::StringRefType mem_name){str_date.SetString(str_m, (unsigned int)strlen(str_m), allocator);
                            if(str_date.GetStringLength() != 0){obj_plat_tcb.AddMember(mem_name, str_date, allocator);}};

        time_to_string(p_supplemental_data->earliest_issue_date, time_str, sizeof(time_str));
        Add_Mem(time_str, "earliest_issue_date");

        time_to_string(p_supplemental_data->latest_issue_date, time_str, sizeof(time_str));
        Add_Mem(time_str, "latest_issue_date");

        time_to_string(p_supplemental_data->earliest_expiration_date, time_str, sizeof(time_str));
        Add_Mem(time_str, "earliest_expiration_date");
        
        time_to_string(p_supplemental_data->tcb_level_date_tag, time_str, sizeof(time_str));
        Add_Mem(time_str, "tcb_level_date_tag");

        obj_plat_tcb.AddMember("pck_crl_num", p_supplemental_data->pck_crl_num, allocator);
        obj_plat_tcb.AddMember("root_ca_crl_num", p_supplemental_data->root_ca_crl_num, allocator);
        obj_plat_tcb.AddMember("tcb_eval_num", p_supplemental_data->tcb_eval_ref_num, allocator);

        //TODO
        //obj_plat_tcb.AddMember("platform_provider_id", , allocator);

        obj_plat_tcb.AddMember("sgx_types", p_supplemental_data->sgx_type, allocator);

        if(p_supplemental_data->dynamic_platform != PCK_FLAG_UNDEFINED){
            Value dynamic_plat;
            dynamic_plat.SetBool(p_supplemental_data->dynamic_platform);
            obj_plat_tcb.AddMember("is_dynamic_platform", dynamic_plat, allocator);
        }


        if(p_supplemental_data->cached_keys != PCK_FLAG_UNDEFINED){
            Value cached_keys;
            cached_keys.SetBool(p_supplemental_data->cached_keys);
            obj_plat_tcb.AddMember("is_cached_keys_policy", cached_keys, allocator);
        }

        if(p_supplemental_data->smt_enabled != PCK_FLAG_UNDEFINED){
            Value smt_enabled;
            smt_enabled.SetBool(p_supplemental_data->smt_enabled);
            obj_plat_tcb.AddMember("is_smt_enabled", smt_enabled, allocator);
        }

        Value advisory_id_array(kArrayType);
        Value str_advisory_id(kStringType);

        if (p_supplemental_data->version > 3 && strlen(p_supplemental_data->sa_list) > 0) {
            std::string s_ad_id(p_supplemental_data->sa_list);
            std::vector<std::string> vec_ad_id;
            advisory_id_vec(vec_ad_id, s_ad_id);
            if(!vec_ad_id.empty())
            {
                for(size_t i=0; i<vec_ad_id.size(); i++){
                    str_advisory_id.SetString(vec_ad_id[i].c_str(), (unsigned int)(vec_ad_id[i].length()), allocator);
                    advisory_id_array.PushBack(str_advisory_id, allocator);
                }
            obj_plat_tcb.AddMember("advisory_ids", advisory_id_array, allocator);
            }
        }

        Value str_keyid(kStringType);
        std::string s_root_key_id = byte_to_hexstring(p_supplemental_data->root_key_id, ROOT_KEY_ID_SIZE);
        str_keyid.SetString(s_root_key_id.c_str(), (unsigned int)(s_root_key_id.length()), allocator);
        if(str_keyid.GetStringLength() != 0){
            obj_plat_tcb.AddMember("root_key_id", str_keyid, allocator);
        }
    }

    //get fmpsc from quote
    quote3_error_t ret = TEE_SUCCESS;
    unsigned char fmspc_from_quote[FMSPC_SIZE] = {0};
    unsigned char ca_from_quote[CA_SIZE] = {0};

    ret = qvl_get_fmspc_ca_from_quote(
        p_quote,
        quote_size,
        fmspc_from_quote,
        FMSPC_SIZE,
        ca_from_quote,
        CA_SIZE);
    if(ret == TEE_SUCCESS)
    {
        Value str_fmspc(kStringType);
        std::string sfmspc((char* )fmspc_from_quote, FMSPC_SIZE);
        std::reverse(sfmspc.begin(), sfmspc.end()); //endian align
        std::string s_fmspc = byte_to_hexstring((const uint8_t *)sfmspc.c_str(), FMSPC_SIZE);
        str_fmspc.SetString(s_fmspc.c_str(), (unsigned int)s_fmspc.length(), allocator);
        if(str_fmspc.GetStringLength() != 0)
        {
            obj_plat_tcb.AddMember("fmspc", str_fmspc, allocator);
        }
    }

    obj_platform.AddMember("measurement", obj_plat_tcb, allocator);

    /*
    "pck_crl_issuer_chain" : base64 encoding,
    "root_ca_crl" : base64 encoding,
    "pck_crl" : base64 encoding,
    "tcb_info_issuer_chain" : base64 encoding,
    "tcb_info" : base64 encoding,
    "qe_identity_issuer_chain" : base64 encoding,
    "qe_identity" : base64 encoding
    */
   
    //Generate endorsement
    if(p_quote_collateral != NULL){
        Value obj_collateral(kObjectType);
        Value str_collateral(kStringType);
        auto Add_Mem = [&](std::string str_m, rapidjson::GenericValue<rapidjson::UTF8<> >::StringRefType mem_name){str_collateral.SetString(str_m.c_str(), (unsigned int)(str_m.length()), allocator);
                            if(str_collateral.GetStringLength() != 0){obj_collateral.AddMember(mem_name, str_collateral, allocator);}};
        if(p_quote_collateral->pck_crl_issuer_chain != NULL && p_quote_collateral->pck_crl_issuer_chain_size > 0){
            std::string s_pck_crl_issue_chain = char_to_base64((reinterpret_cast<unsigned char const*>(p_quote_collateral->pck_crl_issuer_chain)), p_quote_collateral->pck_crl_issuer_chain_size);
            Add_Mem(s_pck_crl_issue_chain, "pck_crl_issuer_chain");
        }

        if(p_quote_collateral->root_ca_crl != NULL && p_quote_collateral->root_ca_crl_size > 0){
            std::string s_root_ca_crl = char_to_base64((reinterpret_cast<unsigned char const*>(p_quote_collateral->root_ca_crl)), p_quote_collateral->root_ca_crl_size);
            Add_Mem(s_root_ca_crl, "root_ca_crl");
        }

        if(p_quote_collateral->pck_crl != NULL && p_quote_collateral->pck_crl_size > 0){
            std::string s_pck_crl = char_to_base64((reinterpret_cast<unsigned char const*>(p_quote_collateral->pck_crl)), p_quote_collateral->pck_crl_size);
            Add_Mem(s_pck_crl, "pck_crl");
        }

        if(p_quote_collateral->tcb_info_issuer_chain != NULL && p_quote_collateral->tcb_info_issuer_chain_size > 0){
            std::string s_tcb_info_issuer_chain = char_to_base64((reinterpret_cast<unsigned char const*>(p_quote_collateral->tcb_info_issuer_chain)), p_quote_collateral->tcb_info_issuer_chain_size);
            Add_Mem(s_tcb_info_issuer_chain, "tcb_info_issuer_chain");
        }

        if(p_quote_collateral->tcb_info != NULL && p_quote_collateral->tcb_info_size > 0){
            std::string s_tcb_info = char_to_base64((reinterpret_cast<unsigned char const*>(p_quote_collateral->tcb_info)), p_quote_collateral->tcb_info_size);
            Add_Mem(s_tcb_info, "tcb_info");
        }

        if(p_quote_collateral->qe_identity_issuer_chain != NULL && p_quote_collateral->qe_identity_issuer_chain_size > 0){
            std::string s_qe_identity_issuer_chain = char_to_base64((reinterpret_cast<unsigned char const*>(p_quote_collateral->qe_identity_issuer_chain)), p_quote_collateral->qe_identity_issuer_chain_size);
            Add_Mem(s_qe_identity_issuer_chain, "qe_identity_issuer_chain");
        }

        if(p_quote_collateral->qe_identity != NULL && p_quote_collateral->qe_identity_size > 0){
            std::string s_qe_identity = char_to_base64((reinterpret_cast<unsigned char const*>(p_quote_collateral->qe_identity)), p_quote_collateral->qe_identity_size);
            Add_Mem(s_qe_identity, "qe_identity");
        }

        obj_platform.AddMember("certification_data", obj_collateral, allocator);
    }

    Value obj_plat_audit(kObjectType);
    Value str_requestid(kStringType);

    std::string s_request_id = char_to_base64((reinterpret_cast<unsigned char const*>(request_id)), REQUEST_ID_LEN);
    str_requestid.SetString(s_request_id.c_str(), (unsigned int)(s_request_id.length()), allocator);
    if(str_requestid.GetStringLength() != 0){
        obj_plat_audit.AddMember("request_id", str_requestid, allocator);
    }

    char verifytime_str[TIME_STR_LEN] = {0};
    time_to_string(verification_date, verifytime_str, sizeof(verifytime_str));
    Value str_ver_date(kStringType);
    str_ver_date.SetString(verifytime_str, (unsigned int)strlen(verifytime_str), allocator);
    if(str_ver_date.GetStringLength() != 0){
        obj_plat_audit.AddMember("verification_time", str_ver_date, allocator);
    }

    obj_platform.AddMember("audit", obj_plat_audit, allocator);
    tdx_jwt_array.PushBack(obj_platform, allocator);


    //Generate QE Identity
    Value obj_qe_identity(kObjectType);
    Value obj_qe_iden_header(kObjectType);
    Value obj_qe_iden_tcb(kObjectType);
    Value str_qe_type_val(kStringType);
    std::string identity_desc = "RAW TDX QE Report";
    str_qe_type_val.SetString(TEE_TDX_QE_IDENTITY_TOKEN_UUID, (unsigned int)strlen(TEE_TDX_QE_IDENTITY_TOKEN_UUID));
    if(str_qe_type_val.GetStringLength() != 0){
        obj_qe_iden_header.AddMember("class_id", str_qe_type_val, allocator);
    }
    str_qe_type_val.SetString(identity_desc.c_str(), (unsigned int)(identity_desc.length()), allocator);
    if(str_qe_type_val.GetStringLength() != 0){
        obj_qe_iden_header.AddMember("Description", str_qe_type_val, allocator);
    }

    obj_qe_identity.AddMember("environment", obj_qe_iden_header, allocator);



    if(p_supplemental_data != NULL){
        Value qe_tcb_status_array(kArrayType);
        Value qe_str_tcb_status(kStringType);
        std::vector<std::string> qe_tcb_status;
        qv_result_tcb_status_map(qe_tcb_status, p_supplemental_data->qe_iden_status);
        if(!qe_tcb_status.empty())
        {
            for(size_t i=0; i<qe_tcb_status.size(); i++){
                qe_str_tcb_status.SetString(qe_tcb_status[i].c_str(), (unsigned int)(qe_tcb_status[i].length()), allocator);
                qe_tcb_status_array.PushBack(qe_str_tcb_status, allocator);
            }
            obj_qe_iden_tcb.AddMember("tcb_status", qe_tcb_status_array, allocator);
        }

        char time_str[TIME_STR_LEN] = {0};
        Value str_date(kStringType);

        auto Add_Mem = [&](char *str_m, rapidjson::GenericValue<rapidjson::UTF8<> >::StringRefType mem_name){str_date.SetString(str_m, (unsigned int)strlen(str_m), allocator);
                            if(str_date.GetStringLength() != 0){obj_qe_iden_tcb.AddMember(mem_name, str_date, allocator);}};

        time_to_string(p_supplemental_data->qe_iden_tcb_level_date_tag, time_str, sizeof(time_str));
        Add_Mem(time_str, "tcb_level_date_tag");
    
        time_to_string(p_supplemental_data->qe_iden_earliest_issue_date, time_str, sizeof(time_str));
        Add_Mem(time_str, "earliest_issue_date");

        time_to_string(p_supplemental_data->qe_iden_latest_issue_date, time_str, sizeof(time_str));
        Add_Mem(time_str, "latest_issue_date");

        time_to_string(p_supplemental_data->qe_iden_earliest_expiration_date, time_str, sizeof(time_str));
        Add_Mem(time_str, "earliest_expiration_date");

        obj_qe_iden_tcb.AddMember("tcb_eval_num", p_supplemental_data->qe_iden_tcb_eval_ref_num, allocator);

        Value str_keyid(kStringType);
        std::string s_root_key_id = byte_to_hexstring(p_supplemental_data->root_key_id, ROOT_KEY_ID_SIZE);
        str_keyid.SetString(s_root_key_id.c_str(), (unsigned int)(s_root_key_id.length()), allocator);
        if(str_keyid.GetStringLength() != 0){
            obj_qe_iden_tcb.AddMember("root_key_id", str_keyid, allocator);
        }
        //root key id, SHA-384 hash of CERT chain root CA's public key
    }

    obj_qe_identity.AddMember("measurement", obj_qe_iden_tcb, allocator);
    tdx_jwt_array.PushBack(obj_qe_identity, allocator);


    //Generate TD report
    Value obj_td_report(kObjectType);
    Value obj_td_rep_header(kObjectType);
    Value obj_td_rep_tcb(kObjectType);

    Value str_td_type_val(kStringType);
    std::string tdtcb_desc = "Application TD TCB";
    if(report_type == TDX10_REPORT)
        str_td_type_val.SetString(TEE_TDX_TD10_IDENTITY_TOKEN_UUID, (unsigned int)strlen(TEE_TDX_TD10_IDENTITY_TOKEN_UUID), allocator);
    else
        str_td_type_val.SetString(TEE_TDX_TD15_IDENTITY_TOKEN_UUID, (unsigned int)strlen(TEE_TDX_TD15_IDENTITY_TOKEN_UUID), allocator);
    if(str_td_type_val.GetStringLength() != 0){
        obj_td_rep_header.AddMember("class_id", str_td_type_val, allocator);
    }
    str_td_type_val.SetString(tdtcb_desc.c_str(), (unsigned int)(tdtcb_desc.length()), allocator);
    if(str_td_type_val.GetStringLength() != 0){
        obj_td_rep_header.AddMember("Description", str_td_type_val, allocator);
    }

    obj_td_report.AddMember("environment", obj_td_rep_header, allocator);

    if(p_quote != NULL){
        sgx_report2_body_v1_5_t tmp_report;     //always transfer to tdx1.5 report
        memset(&tmp_report, 0, sizeof(sgx_report2_body_v1_5_t));
        if(quote_ver == intel::sgx::dcap::constants::QUOTE_VERSION_4)
        {
            const sgx_quote4_t *tmp_quote4 = reinterpret_cast<const sgx_quote4_t *> (p_quote);
            memcpy(&tmp_report, (void *)&(tmp_quote4->report_body), sizeof(sgx_report2_body_t));
        }
        if(quote_ver == intel::sgx::dcap::constants::QUOTE_VERSION_5)
        {
            const sgx_quote5_t *tmp_quote5 = reinterpret_cast<const sgx_quote5_t *> (p_quote);
            memcpy(&tmp_report, tmp_quote5->body, sizeof(sgx_report2_body_v1_5_t));
        }

        Value str_td(kStringType);
        auto Add_Mem = [&](std::string str_m, rapidjson::GenericValue<rapidjson::UTF8<> >::StringRefType mem_name){str_td.SetString(str_m.c_str(), (unsigned int)(str_m.length()), allocator);
                            if(str_td.GetStringLength() != 0){obj_td_rep_tcb.AddMember(mem_name, str_td, allocator);}};
        
        std::string s_td_attributes = byte_to_hexstring((uint8_t *) &(tmp_report.td_attributes), sizeof(tee_attributes_t));
        Add_Mem(s_td_attributes, "tdx_attributes");

        std::string s_tdx_xfam = byte_to_hexstring((uint8_t *) &(tmp_report.xfam), sizeof(tee_attributes_t));
        Add_Mem(s_tdx_xfam, "tdx_xfam");

        std::string s_tdx_mrconfigid = byte_to_hexstring((uint8_t *) &(tmp_report.mr_config_id), sizeof(tee_measurement_t));
        Add_Mem(s_tdx_mrconfigid, "tdx_mrconfigid");

        std::string s_tdx_mrowner = byte_to_hexstring((uint8_t *) &(tmp_report.mr_owner), sizeof(tee_measurement_t));
        Add_Mem(s_tdx_mrowner, "tdx_mrowner");
        
        std::string s_tdx_mrownerconfig = byte_to_hexstring((uint8_t *) &(tmp_report.mr_owner_config), sizeof(tee_measurement_t));
        Add_Mem(s_tdx_mrownerconfig, "tdx_mrownerconfig");
        
        std::string s_tdx_mrtd = byte_to_hexstring((uint8_t *) &(tmp_report.mr_td), sizeof(tee_measurement_t));
        Add_Mem(s_tdx_mrtd, "tdx_mrtd");

        std::string s_tdx_rtmr0 = byte_to_hexstring((uint8_t *) &(tmp_report.rt_mr[0]), sizeof(tee_measurement_t));
        Add_Mem(s_tdx_rtmr0, "tdx_rtmr0");

        std::string s_tdx_rtmr1 = byte_to_hexstring((uint8_t *) &(tmp_report.rt_mr[1]), sizeof(tee_measurement_t));
        Add_Mem(s_tdx_rtmr1, "tdx_rtmr1");

        std::string s_tdx_rtmr2 = byte_to_hexstring((uint8_t *) &(tmp_report.rt_mr[2]), sizeof(tee_measurement_t));
        Add_Mem(s_tdx_rtmr2, "tdx_rtmr2");

        std::string s_tdx_rtmr3 = byte_to_hexstring((uint8_t *) &(tmp_report.rt_mr[3]), sizeof(tee_measurement_t));
        Add_Mem(s_tdx_rtmr3, "tdx_rtmr3");

        std::string s_tdx_reportdata  = byte_to_hexstring((uint8_t *) &(tmp_report.report_data), sizeof(tee_report_data_t));
        Add_Mem(s_tdx_reportdata, "tdx_reportdata");
        //only quote version 5: tdx_mrservicetd
        if(quote_ver == intel::sgx::dcap::constants::QUOTE_VERSION_5)
        {
            std::string s_mr_servicetd  = byte_to_hexstring((uint8_t *) &(tmp_report.mr_servicetd), sizeof(tee_measurement_t));
            Add_Mem(s_mr_servicetd, "tdx_mrservicetd");
        }
    }
    obj_td_report.AddMember("measurement", obj_td_rep_tcb, allocator);
    tdx_jwt_array.PushBack(obj_td_report, allocator);

    JWT.AddMember("qvl_result", tdx_jwt_array, allocator);

    rapidjson::StringBuffer str_buff;
    rapidjson::Writer<rapidjson::StringBuffer> writer(str_buff);
    JWT.Accept(writer);

    std::string raw_data = str_buff.GetString();
    if(raw_data.empty())
    {
        return TEE_ERROR_UNEXPECTED;
    }

	auto qal_token = jwt::create()
					 .set_issuer("qal")
					 .set_type("JWT")
					 .set_payload_claim("qvl_result", jwt::claim(raw_data))
					 .sign(jwt::algorithm::none());

    if(qal_token.empty())
    {
        return TEE_ERROR_UNEXPECTED;
    }

    *jwt_data = (uint8_t*)malloc(qal_token.length() + 1);
    if (*jwt_data == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    memset(*jwt_data, 0, qal_token.length() + 1);
    memcpy_s(*jwt_data, qal_token.length() + 1, qal_token.c_str(), qal_token.length());
    *jwt_size = (uint32_t)qal_token.length();
    return TEE_SUCCESS;
}

quote3_error_t  tee_verify_quote_qvt(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const sgx_ql_qve_collateral_t *p_quote_collateral,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    const uint8_t *p_user_data,
    uint32_t *p_verification_result_token_buffer_size,
    uint8_t **p_verification_result_token
)
{
    if(CHECK_MANDATORY_PARAMS(p_quote, quote_size) || quote_size < QUOTE_MIN_SIZE ||
        p_verification_result_token_buffer_size == NULL || p_verification_result_token == NULL)
    {
        return TEE_ERROR_INVALID_PARAMETER;
    }
    time_t current_time = time(NULL);
    uint32_t collateral_expiration_status = 1;

    supp_ver_t latest_ver;
    latest_ver.major_version = 3;

    tee_supp_data_descriptor_t supp_data;
    memset(&supp_data, 0, sizeof(tee_supp_data_descriptor_t));
    sgx_ql_qv_result_t quote_verification_result = TEE_QV_RESULT_UNSPECIFIED;
    quote3_error_t dcap_ret = TEE_ERROR_UNEXPECTED;
    sgx_ql_qve_collateral_t *p_tmp_quote_collateral = NULL;

    //get supplemental data size
    dcap_ret = tee_get_supplemental_data_version_and_size(p_quote,
                                            quote_size,
                                            &latest_ver.version,
                                            &supp_data.data_size);
    if (dcap_ret == TEE_SUCCESS && supp_data.data_size == sizeof(sgx_ql_qv_supplemental_t)) {
        SE_TRACE(SE_TRACE_DEBUG,"\tInfo: tee_get_quote_supplemental_data_version_and_size successfully returned.\n");
        SE_TRACE(SE_TRACE_DEBUG,"\tInfo: latest supplemental data major version: %d, minor version: %d, size: %d\n", latest_ver.major_version, latest_ver.minor_version, supp_data.data_size);
        supp_data.p_data = (uint8_t*)malloc(supp_data.data_size);
        if (supp_data.p_data != NULL) {
            memset(supp_data.p_data, 0, supp_data.data_size);
        }
        else {
            SE_TRACE(SE_TRACE_DEBUG,"\tError: Cannot allocate memory for supplemental data.\n");
            return TEE_ERROR_OUT_OF_MEMORY;
        }
    }
    else {
        if (dcap_ret != TEE_SUCCESS)
            SE_TRACE(SE_TRACE_DEBUG,"\tError: tee_get_supplemental_data_version_and_size failed: 0x%04x\n", dcap_ret);

        if (supp_data.data_size != sizeof(sgx_ql_qv_supplemental_t))
            SE_TRACE(SE_TRACE_DEBUG,"\tWarning: Quote supplemental data size is different between DCAP QVL and QvE, please make sure you installed DCAP QVL and QvE from same release.\n");

        supp_data.data_size = 0;
    }

 if (p_quote_collateral == NULL)
    {
        uint32_t p_collateral_size = 0;
        dcap_ret = tee_qv_get_collateral(
            p_quote,
            quote_size,
            reinterpret_cast<uint8_t **>(&p_tmp_quote_collateral),
            &p_collateral_size);
          
        if (dcap_ret == TEE_SUCCESS) {
            SE_TRACE(SE_TRACE_DEBUG,"\tInfo: tee_qv_get_collateral successfully returned.\n");
            p_quote_collateral = reinterpret_cast<const sgx_ql_qve_collateral_t *>(p_tmp_quote_collateral);
        }
        else {
            SE_TRACE(SE_TRACE_DEBUG,"\tError: tee_qv_get_collateral failed: 0x%04x\n", dcap_ret);
        }
    } 

    dcap_ret = tee_verify_quote(
            p_quote, quote_size,
            reinterpret_cast<const uint8_t *>(p_quote_collateral),
            current_time,
            &collateral_expiration_status,
            &quote_verification_result,
            p_qve_report_info,
            &supp_data);
    if (dcap_ret == TEE_SUCCESS) {
        switch (quote_verification_result)
        {
        case TEE_QV_RESULT_OK:
            break;
        case TEE_QV_RESULT_CONFIG_NEEDED:
        case TEE_QV_RESULT_OUT_OF_DATE:
        case TEE_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        case TEE_QV_RESULT_SW_HARDENING_NEEDED:
        case TEE_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
        case TEE_QV_RESULT_TD_RELAUNCH_ADVISED:
        case TEE_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED:
            SE_TRACE(SE_TRACE_DEBUG,"\tWarning: Verification completed with Non-terminal result: 0x%04x\n", quote_verification_result);
            break;
        //Will not generate JWT when critical error occurred
        case TEE_QV_RESULT_INVALID_SIGNATURE:
        case TEE_QV_RESULT_REVOKED:
        case TEE_QV_RESULT_UNSPECIFIED:
        default:
            SE_TRACE(SE_TRACE_DEBUG,"\tError: Verification completed with Terminal result: 0x%04x\n", quote_verification_result);
            if(p_tmp_quote_collateral != NULL){
                tee_qv_free_collateral(reinterpret_cast<uint8_t *>(p_tmp_quote_collateral));
            }
            if(supp_data.p_data != NULL){
                free(supp_data.p_data);
            }
            return TEE_ERROR_UNEXPECTED;
        }
    }
    else {
        SE_TRACE(SE_TRACE_DEBUG,"\tError: tee_verify_quote failed: 0x%04x\n", dcap_ret);
        if(p_tmp_quote_collateral != NULL){
            tee_qv_free_collateral(reinterpret_cast<uint8_t *>(p_tmp_quote_collateral));
        }
        if(supp_data.p_data != NULL){
            free(supp_data.p_data);
        }
        return dcap_ret;
    }


    unsigned char rand_nonce[REQUEST_ID_LEN] = {0};
    if(!RAND_bytes(rand_nonce, REQUEST_ID_LEN))
    {
        SE_TRACE(SE_TRACE_ERROR,"\tError: Failed to generate random request_id.\n");
        return TEE_ERROR_UNEXPECTED;
    }

    //parse quote header to get tee type, only support SGX and TDX by now
    tee_evidence_type_t tee_type = UNKNOWN_QUOTE_TYPE;

    // check quote type
    uint32_t *p_type = (uint32_t *) (p_quote + sizeof(uint16_t) * 2);
    if (*p_type == SGX_QUOTE_TYPE)
        tee_type = SGX_EVIDENCE;
    else if (*p_type == TDX_QUOTE_TYPE)
        tee_type = TDX_EVIDENCE;
    else{
        if(p_tmp_quote_collateral != NULL){
            tee_qv_free_collateral(reinterpret_cast<uint8_t *>(p_tmp_quote_collateral));
        }
        if(supp_data.p_data != NULL){
            free(supp_data.p_data);
        }
        //quote type is not supported
        return TEE_ERROR_INVALID_PARAMETER;
    }
    uint16_t quote_ver = 0;
    uint16_t report_type = 0;
    const uint8_t *p_tmp_quote = p_quote;
    memcpy(&quote_ver, p_tmp_quote, sizeof(uint16_t));
    if(quote_ver == intel::sgx::dcap::constants::QUOTE_VERSION_4){
        sgx_quote4_t *p_tmp_quote4 = (sgx_quote4_t *)p_tmp_quote;
        uint16_t major_ver = p_tmp_quote4->report_body.tee_tcb_svn.tcb_svn[1];
        switch (major_ver)
        {
            case 0:
                report_type = TDX10_REPORT;
                break;
            case 1:
                report_type = TDX15_REPORT;
                break;
            default:    //tdx2.0 not support yet
                report_type = UNKNOWN_REPORT_TYPE;
                break;
        }
    }
    if(quote_ver == intel::sgx::dcap::constants::QUOTE_VERSION_5)
    {
        sgx_quote5_t *p_tmp_quote_5 = (sgx_quote5_t *)p_tmp_quote;
        report_type = p_tmp_quote_5->type;
    }

    try
    {
        if(tee_type == SGX_EVIDENCE){
            dcap_ret = sgx_jwt_generator_internal(
                TEE_PALTFORM_TOKEN_UUID, TEE_PLATFORM_TOKEN_VER,
                TEE_ENCLAVE_TOKEN_UUID, TEE_ENCLAVE_TOKEN_VER,
                quote_ver,
                reinterpret_cast<const char*>(rand_nonce),
                quote_verification_result,
                current_time,
                reinterpret_cast<const sgx_ql_qv_supplemental_t*>(supp_data.p_data),
                p_quote,
                quote_size,
                p_quote_collateral,
                p_verification_result_token_buffer_size,                           
                p_verification_result_token);
        }
        else if(tee_type == TDX_EVIDENCE){
            dcap_ret = tdx_jwt_generator_internal(
                quote_ver, report_type,
                TEE_TDX_PLATFORM_TOKEN_VER,
                TEE_TDX_QE_IDENTITY_TOKEN_VER,
                TEE_TDX_TD_IDENTITY_TOKEN_VER,
                p_user_data,
                reinterpret_cast<const char*>(rand_nonce),
                quote_verification_result,
                current_time,
                reinterpret_cast<const sgx_ql_qv_supplemental_t*>(supp_data.p_data),
                p_quote,
                quote_size,
                p_quote_collateral,
                p_verification_result_token_buffer_size,
                p_verification_result_token);
        }
    }
    catch (...)
    {
        dcap_ret = TEE_ERROR_UNEXPECTED;
        SE_TRACE(SE_TRACE_ERROR,"\tError: Failed to generate JWT.\n");
    }

    if(p_tmp_quote_collateral != NULL){
        tee_qv_free_collateral(reinterpret_cast<uint8_t *>(p_tmp_quote_collateral));
    }
    if(supp_data.p_data != NULL){
        free(supp_data.p_data);
    }
    return dcap_ret;
}

quote3_error_t tee_free_verify_quote_qvt(uint8_t *p_verification_result_token, uint32_t *p_verification_result_token_buffer_size)
{
    if(p_verification_result_token == NULL || p_verification_result_token_buffer_size == NULL)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    free(p_verification_result_token);
    p_verification_result_token = NULL;
    *p_verification_result_token_buffer_size = 0;
    return SGX_QL_SUCCESS;
}
#endif