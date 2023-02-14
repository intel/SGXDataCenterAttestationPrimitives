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
#include "se_trace.h"
#include "se_thread.h"
#include "se_memcpy.h"
#include "sgx_urts_wrapper.h"

sgx_create_enclave_func_t p_sgx_urts_create_enclave = NULL;
sgx_destroy_enclave_func_t p_sgx_urts_destroy_enclave = NULL;
sgx_ecall_func_t p_sgx_urts_ecall = NULL;
sgx_oc_cpuidex_func_t p_sgx_oc_cpuidex = NULL;
sgx_thread_wait_untrusted_event_ocall_func_t p_sgx_thread_wait_untrusted_event_ocall = NULL;
sgx_thread_set_untrusted_event_ocall_func_t p_sgx_thread_set_untrusted_event_ocall = NULL;
sgx_thread_setwait_untrusted_events_ocall_func_t p_sgx_thread_setwait_untrusted_events_ocall = NULL;
sgx_thread_set_multiple_untrusted_events_ocall_func_t p_sgx_thread_set_multiple_untrusted_events_ocall = NULL;

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


#if defined(_MSC_VER)
#include <tchar.h>
bool get_qve_path(TCHAR *p_file_path, size_t buf_size);
#else
#include <limits.h>
#define MAX_PATH PATH_MAX
bool get_qve_path(char *p_file_path, size_t buf_size);

#endif

#ifdef __GNUC__
pthread_create_ocall_func_t p_pthread_create_ocall = NULL;
pthread_wait_timeout_ocall_func_t p_pthread_wait_timeout_ocall = NULL;
pthread_wakeup_ocall_func_t p_pthread_wakeup_ocall_func = NULL;

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

struct QvE_status {
    se_mutex_t m_qve_mutex;
    sgx_ql_request_policy_t m_qve_enclave_load_policy;
    sgx_enclave_id_t m_qve_eid;
    sgx_misc_attribute_t m_qve_attributes;

    QvE_status() :
        m_qve_enclave_load_policy(SGX_QL_DEFAULT),
        m_qve_eid(0)
    {
        se_mutex_init(&m_qve_mutex);
        //should be replaced with memset_s, but currently can't find proper header file for it
        //
        memset(&m_qve_attributes, 0, sizeof(m_qve_attributes));
    }
    ~QvE_status() {
        se_mutex_destroy(&m_qve_mutex);
    }
};

static QvE_status g_qve_status;

static sgx_status_t load_qve(sgx_enclave_id_t *p_qve_eid,
    sgx_misc_attribute_t *p_qve_attributes,
    sgx_launch_token_t *p_launch_token)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    int enclave_lost_retry_time = 1;
    int launch_token_updated = 0;
#if defined(_MSC_VER)
    TCHAR qve_enclave_path[MAX_PATH] = _T("");
#else
    char qve_enclave_path[MAX_PATH] = "";
#endif
    //should be replaced with memset_s, but currently can't find proper header file for it
    //
    memset(p_launch_token, 0, sizeof(*p_launch_token));

    // Try to load urts lib first
    //
    if (!sgx_dcap_load_urts()) {
        return SGX_ERROR_FEATURE_NOT_SUPPORTED;
    }

    int rc = se_mutex_lock(&g_qve_status.m_qve_mutex);
    if (rc != 1)
    {
        SE_TRACE(SE_TRACE_ERROR, "Failed to lock mutex\n");
        return SGX_ERROR_UNEXPECTED; // SGX_QvE_INTERFACE_UNAVAILABLE;
    }

    // Load the QvE
    if (g_qve_status.m_qve_eid == 0)
    {
        if (!get_qve_path(qve_enclave_path, MAX_PATH)) {
            rc = se_mutex_unlock(&g_qve_status.m_qve_mutex);
            if (rc != 1)
            {
                SE_TRACE(SE_TRACE_ERROR, "Failed to unlock mutex\n");
            }
            return SGX_ERROR_UNEXPECTED; //SGX_QvE_INTERFACE_UNAVAILABLE;
        }
        do
        {
            SE_TRACE(SE_TRACE_DEBUG, "Call sgx_create_enclave for QvE. %s\n", qve_enclave_path);
            if (p_sgx_urts_create_enclave) {
                sgx_status = p_sgx_urts_create_enclave(qve_enclave_path,
                    0, // Don't support debug load QvE by default
                    p_launch_token,
                    &launch_token_updated,
                    p_qve_eid,
                    p_qve_attributes);
                if (SGX_SUCCESS != sgx_status) {
                    SE_TRACE(SE_TRACE_DEBUG, "Info, call sgx_create_enclave for QvE fail [%s], SGXError:%04x.\n", __FUNCTION__, sgx_status);
                }
                else {
                    break;
                }
            }
            else
                return SGX_ERROR_UNEXPECTED; //urts handle has been closed;

            // Retry in case there was a power transition that resulted is losing the enclave.
        } while (SGX_ERROR_ENCLAVE_LOST == sgx_status && enclave_lost_retry_time--);
        if (sgx_status != SGX_SUCCESS)
        {
            rc = se_mutex_unlock(&g_qve_status.m_qve_mutex);
            if (rc != 1)
            {
                SE_TRACE(SE_TRACE_ERROR, "Failed to unlock mutex\n");
                return SGX_ERROR_UNEXPECTED;
            }
            if (sgx_status == SGX_ERROR_OUT_OF_EPC)
                return SGX_ERROR_OUT_OF_EPC;
            else
                return SGX_ERROR_UNEXPECTED;
        }
        g_qve_status.m_qve_eid = *p_qve_eid;
        memcpy_s(&g_qve_status.m_qve_attributes, sizeof(sgx_misc_attribute_t), p_qve_attributes, sizeof(sgx_misc_attribute_t));
    }
    else {
        *p_qve_eid = g_qve_status.m_qve_eid;
        memcpy_s(p_qve_attributes, sizeof(sgx_misc_attribute_t), &g_qve_status.m_qve_attributes, sizeof(sgx_misc_attribute_t));
    }
    rc = se_mutex_unlock(&g_qve_status.m_qve_mutex);
    if (rc != 1)
    {
        SE_TRACE(SE_TRACE_ERROR, "Failed to unlock mutex\n");
        return SGX_ERROR_UNEXPECTED;
    }
    return SGX_SUCCESS;
}

static void unload_qve(bool force = false)
{
    // Try to load urts lib first
    //
    if (!sgx_dcap_load_urts()) {
        SE_TRACE(SE_TRACE_ERROR, "Error, failed to load SGX uRTS library\n");
        return;
    }

    int rc = se_mutex_lock(&g_qve_status.m_qve_mutex);
    if (rc != 1)
    {
        SE_TRACE(SE_TRACE_ERROR, "Failed to lock mutex\n");
        return;
    }

    // Unload the QvE enclave
    if (g_qve_status.m_qve_eid &&
        (force || g_qve_status.m_qve_enclave_load_policy != SGX_QL_PERSISTENT)
        )
    {
        SE_TRACE(SE_TRACE_DEBUG, "unload qve enclave 0X%llX\n", g_qve_status.m_qve_eid);
        if (p_sgx_urts_destroy_enclave) {
            p_sgx_urts_destroy_enclave(g_qve_status.m_qve_eid);
        }
        g_qve_status.m_qve_eid = 0;
        memset(&g_qve_status.m_qve_attributes, 0, sizeof(g_qve_status.m_qve_attributes));
    }

    rc = se_mutex_unlock(&g_qve_status.m_qve_mutex);
    if (rc != 1)
    {
        SE_TRACE(SE_TRACE_ERROR, "Failed to unlock mutex\n");
        return;
    }
}

quote3_error_t sgx_qv_set_enclave_load_policy(
    sgx_ql_request_policy_t policy)
{
    if (policy > SGX_QL_EPHEMERAL)
        return SGX_QL_UNSUPPORTED_LOADING_POLICY;
    g_qve_status.m_qve_enclave_load_policy = policy;
    if (policy == SGX_QL_EPHEMERAL)
        unload_qve(true);
    return SGX_QL_SUCCESS;
}


/* Initialize the enclave:
 * Call sgx_create_enclave to initialize an enclave instance
 **/
static sgx_status_t initialize_enclave(sgx_enclave_id_t* eid)
{
    sgx_launch_token_t token = { 0 };
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_misc_attribute_t p_mist_attribute;

    ret = load_qve(eid, &p_mist_attribute, &token);

    return ret;
}

/**
 * Internal function - get supplemental data size and version.
 **/
static quote3_error_t get_verification_supplemental_data_size_and_version(
    uint32_t *p_data_size,
    uint32_t *p_version,
    tee_evidence_type_t tee_type) {

    if (NULL_POINTER(p_data_size)) {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    //only support SGX and TDX
    if (tee_type != SGX_EVIDENCE && tee_type != TDX_EVIDENCE)
        return SGX_QL_ERROR_INVALID_PARAMETER;

    supp_ver_t trusted_version;
    supp_ver_t untrusted_version;
    trusted_version.version = 0;
    untrusted_version.version = 0;
    uint32_t trusted_size = 0, untrusted_size = 0;
    bool VerNumMismatch = false;
    sgx_status_t load_ret = SGX_ERROR_UNEXPECTED;
    sgx_enclave_id_t qve_eid = 0;
    quote3_error_t qve_ret = SGX_QL_ERROR_INVALID_PARAMETER;
    tee_qv_base *p_trusted_qv = NULL;
    tee_qv_base *p_untrusted_qv = NULL;

    do {
        //create and initialize QvE
        //
        load_ret = initialize_enclave(&qve_eid);

        if (tee_type == SGX_EVIDENCE) {
            p_trusted_qv = new sgx_qv_trusted(qve_eid);
            p_untrusted_qv = new sgx_qv();
        }
        else if (tee_type == TDX_EVIDENCE) {
            p_trusted_qv = new tdx_qv_trusted(qve_eid);
            p_untrusted_qv = new tdx_qv();
        }

        if (load_ret != SGX_SUCCESS) {
            SE_TRACE(SE_TRACE_DEBUG, "Warning: failed to load QvE.\n");
            break;
        }

        //if QvE has been loaded, any ECALL failure would treat as an error
        //
        VerNumMismatch = true;

        //call SGX QvE ECALL to get supplemental data version
        //
        qve_ret = p_trusted_qv->tee_get_supplemental_data_version(&trusted_version.version);
        if (qve_ret != SGX_QL_SUCCESS) {
            trusted_version.version = 0;
            break;
        }

        qve_ret = p_trusted_qv->tee_get_supplemental_data_size(&trusted_size);
        if (qve_ret != SGX_QL_SUCCESS) {
            trusted_size = 0;
            break;
        }

    } while (0);

    do {
        //call untrusted API to get supplemental data version
        //
        qve_ret = p_untrusted_qv->tee_get_supplemental_data_version(&untrusted_version.version);
        if (qve_ret != SGX_QL_SUCCESS) {
            SE_TRACE(SE_TRACE_DEBUG, "Error: untrusted API qvl_get_quote_supplemental_data_version failed: 0x%04x\n", qve_ret);
            *p_data_size = 0;
            break;
        }

        //call untrusted API to get supplemental data size
        //
        qve_ret = p_untrusted_qv->tee_get_supplemental_data_size(&untrusted_size);
        if (qve_ret != SGX_QL_SUCCESS) {
            SE_TRACE(SE_TRACE_DEBUG, "Error: untrusted API qvl_get_quote_supplemental_data_size failed: 0x%04x\n", qve_ret);
            *p_data_size = 0;
            break;
        }

        if (VerNumMismatch) {
            if (trusted_version.version != untrusted_version.version || trusted_size != untrusted_size) {
                SE_TRACE(SE_TRACE_DEBUG, "Error: Quote supplemental data version is different between trusted QvE and untrusted QVL.\n");
                SE_TRACE(SE_TRACE_DEBUG, "Supplemental version from QvE, major version: %d, minor version: %d,\t size: %d\n",
                                            trusted_version.major_version, trusted_version.minor_version, trusted_size);
                SE_TRACE(SE_TRACE_DEBUG, "Supplemental version from QVL, major version: %d, minor version: %d,\t size: %d\n",
                                            untrusted_version.major_version, untrusted_version.minor_version, untrusted_size);
                *p_data_size = 0;
                qve_ret = SGX_QL_ERROR_QVL_QVE_MISMATCH;
                break;
            }
        }

        if (p_data_size != NULL)
            *p_data_size = untrusted_size;
        if (p_version != NULL)
            *p_version = untrusted_version.version;

    } while (0) ;


    //destroy QvE enclave
    //
    if (qve_eid != 0) {
        unload_qve(true);
    }

    delete p_trusted_qv;
    delete p_untrusted_qv;

    return qve_ret;
}


/**
 * Get supplemental data latest version and required size.
 **/
quote3_error_t tee_get_supplemental_data_version_and_size(
    const uint8_t *p_quote,
    uint32_t quote_size,
    uint32_t *p_version,
    uint32_t *p_data_size) {

    if (p_quote == NULL || quote_size == 0 ||
        (p_version == NULL && p_data_size == NULL))
        return SGX_QL_ERROR_INVALID_PARAMETER;

    tee_evidence_type_t tee_type = UNKNOWN_QUOTE_TYPE;
    // check quote type
    uint32_t *p_type = (uint32_t *) (p_quote + sizeof(uint16_t) * 2);

    if (*p_type == SGX_QUOTE_TYPE)
        tee_type = SGX_EVIDENCE;
    else if (*p_type == TDX_QUOTE_TYPE)
        tee_type = TDX_EVIDENCE;
    else
        return SGX_QL_ERROR_INVALID_PARAMETER;

    return get_verification_supplemental_data_size_and_version(p_data_size, p_version, tee_type);

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

    // check quote type
    uint32_t *p_type = (uint32_t *) (p_quote + sizeof(uint16_t) * 2);

    if (*p_type == SGX_QUOTE_TYPE)
        tee_type = SGX_EVIDENCE;
    else if (*p_type == TDX_QUOTE_TYPE)
        tee_type = TDX_EVIDENCE;
    else
        //quote type is not supported
        return SGX_QL_ERROR_INVALID_PARAMETER;

    //validate supplemental data size
    //
    if (p_supplemental_data) {
        quote3_error_t tmp_ret = SGX_QL_ERROR_UNEXPECTED;
        uint32_t tmp_size = 0;
        tmp_ret = get_verification_supplemental_data_size_and_version(&tmp_size, NULL, tee_type);

        if (tmp_ret != SGX_QL_SUCCESS || tmp_size != supplemental_data_size) {

            if (p_quote_verification_result) {
                *p_quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
            }
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
    }

    sgx_enclave_id_t qve_eid = 0;
    quote3_error_t qve_ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_status_t load_ret = SGX_ERROR_UNEXPECTED;
    unsigned char fmspc_from_quote[FMSPC_SIZE] = { 0 };
    unsigned char ca_from_quote[CA_SIZE] = { 0 };
    struct _sgx_ql_qve_collateral_t* qve_collaterals_from_qp = NULL;
    tee_qv_base *p_tee_qv = NULL;

    do {
        if (p_qve_report_info) {
            //try to load QvE for trusted quote verification
            //
            load_ret = initialize_enclave(&qve_eid);
            if (load_ret != SGX_SUCCESS) {
                if (load_ret == SGX_ERROR_FEATURE_NOT_SUPPORTED) {
                    SE_TRACE(SE_TRACE_DEBUG, "Info, cannot load SGX PSW libs in [%s], SGX error:%04x.\n", __FUNCTION__, load_ret);
                    qve_ret = SGX_QL_PSW_NOT_AVAILABLE;
                }
                else {
                    SE_TRACE(SE_TRACE_DEBUG, "Info, failed to load QvE.\n");
                    qve_ret = SGX_QL_ENCLAVE_LOAD_ERROR;
                }

                break;
            }

            try {
                if (tee_type == SGX_EVIDENCE)
                    p_tee_qv = new sgx_qv_trusted(qve_eid);
                if (tee_type == TDX_EVIDENCE)
                    p_tee_qv = new tdx_qv_trusted(qve_eid);
            }

            catch (std::bad_alloc&) {
                qve_ret = SGX_QL_ERROR_OUT_OF_MEMORY;
                break;
            }
        }

        //untrsuted quote verification
        //
        else {
            try {
                if (tee_type == SGX_EVIDENCE)
                    p_tee_qv = new sgx_qv();
                if (tee_type == TDX_EVIDENCE)
                    p_tee_qv = new tdx_qv();
            }

            catch (std::bad_alloc&) {
                qve_ret = SGX_QL_ERROR_OUT_OF_MEMORY;
                break;
            }
        }

        //in case input collateral is NULL, dynamically load and call QPL to retrieve verification collateral
        //
        if (NULL_POINTER(p_quote_collateral)) {

            //extract fmspc and CA from the quote, these values are required inorder to query collateral from QPL
            //
            qve_ret = p_tee_qv->tee_get_fmspc_ca_from_quote(p_quote, quote_size, fmspc_from_quote, FMSPC_SIZE, ca_from_quote, CA_SIZE);
            if (qve_ret == SGX_QL_SUCCESS) {
                SE_TRACE(SE_TRACE_DEBUG, "Info: get_fmspc_ca_from_quote successfully returned.\n");
            }
            else {
                SE_TRACE(SE_TRACE_DEBUG, "Error: get_fmspc_ca_from_quote failed: 0x%04x\n", qve_ret);
                break;
            }

            //retrieve verification collateral using QPL
            //
            qve_ret = p_tee_qv->tee_get_verification_endorsement(
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

        qve_ret = p_tee_qv->tee_verify_evidence(
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

    //destroy QvE enclave
    //
    if (qve_eid != 0) {
        unload_qve(true);
    }

    //free verification collateral using QPL
    //
    if (qve_collaterals_from_qp) {
        p_tee_qv->tee_free_verification_endorsement(qve_collaterals_from_qp);
    }

    //delete qv class object
    //
    if (p_tee_qv)
        delete p_tee_qv;

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
    return get_verification_supplemental_data_size_and_version(p_data_size, NULL, SGX_EVIDENCE);
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
    return get_verification_supplemental_data_size_and_version(p_data_size, NULL, TDX_EVIDENCE);
}

/**
 * Perform TDX ECDSA quote verification
 **/
quote3_error_t tdx_qv_verify_quote(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const tdx_ql_qve_collateral_t *p_quote_collateral,
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
    if (p_quote == NULL || quote_size < QUOTE_MIN_SIZE || pp_quote_collateral == NULL || *pp_quote_collateral != NULL || p_collateral_size == NULL)
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
                                                        (tdx_ql_qve_collateral_t **)pp_quote_collateral);
        if (ret == SGX_QL_SUCCESS)
        {
		 *p_collateral_size =
                (uint32_t)sizeof(tdx_ql_qve_collateral_t) +
                ((tdx_ql_qve_collateral_t *)(*pp_quote_collateral))
                    ->pck_crl_issuer_chain_size +
                ((tdx_ql_qve_collateral_t *)(*pp_quote_collateral))
                    ->root_ca_crl_size +
                ((tdx_ql_qve_collateral_t *)(*pp_quote_collateral))
                    ->pck_crl_size +
                ((tdx_ql_qve_collateral_t *)(*pp_quote_collateral))
                    ->tcb_info_issuer_chain_size +
                ((tdx_ql_qve_collateral_t *)(*pp_quote_collateral))
                    ->qe_identity_issuer_chain_size +
                ((tdx_ql_qve_collateral_t *)(*pp_quote_collateral))
                    ->qe_identity_size +
                ((tdx_ql_qve_collateral_t *)(*pp_quote_collateral))
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
        ret = tdx_dcap_free_verification_collateral((tdx_ql_qve_collateral_t *)p_quote_collateral);
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
    if (p_quote == NULL || quote_size == 0)
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
#endif


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
    case SGX_QL_QV_RESULT_OK:
        tcb_status.push_back("UpToDate");
        break;
    case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
        tcb_status.push_back("UpToDate");
        tcb_status.push_back("SWHardeningNeeded");
        break;
    case SGX_QL_QV_RESULT_CONFIG_NEEDED:
        tcb_status.push_back("UpToDate");
        tcb_status.push_back("ConfigurationNeeded");
        break;
    case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
        tcb_status.push_back("UpToDate");
        tcb_status.push_back("SWHardeningNeeded");
        tcb_status.push_back("ConfigurationNeeded");
        break;
    case SGX_QL_QV_RESULT_OUT_OF_DATE:
        tcb_status.push_back("OutOfDate");
        break;
    case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        tcb_status.push_back("OutOfDate");
        tcb_status.push_back("ConfigurationNeeded");
        break;
    case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
        break;
    case SGX_QL_QV_RESULT_REVOKED:
        tcb_status.push_back("Revoked");
        break;
    case SGX_QL_QV_RESULT_UNSPECIFIED:
        break;
    default:
        break;
}
    return;
}

/*
sgx_type: is defined as scalable (“ConfidentialityProtected”),
scalable with integrity (“ConfidentialityProtected”, “IntegrityProtected”),
and standard (“ConfidentialityProtected”, “IntegrityProtected”, “ReplayProtected”).
*/
static void sgx_type_map(std::vector<std::string>& type_arr, uint8_t sgx_type)
{
    switch (sgx_type){
        //standard (0)
        case 0:
            type_arr.push_back("ConfidentialityProtected");
            type_arr.push_back("IntegrityProtected");
            type_arr.push_back("ReplayProtected");
            break;
        //Scalable (1)
        case 1:
            type_arr.push_back("ConfidentialityProtected");
            break;
        //Scalable with Integrity (2)
        case 2:
            type_arr.push_back("ConfidentialityProtected");
            type_arr.push_back("IntegrityProtected");
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
static std::string ByteStringToHexString(const uint8_t* data, size_t len)
{
    std::string result;
    result.reserve(len * 2);   // two digits per character

    static constexpr char hex[] = "0123456789ABCDEF";

    for (; len > 1; len--)
    {
        result.push_back(hex[data[len-1] / 16]);
        result.push_back(hex[data[len-1] % 16]);
    }

    return result;
}

//TO DO in Enclave
//time transfer to ISO 8601 standard (YYYY-MM-DDThh:mm:ssZ)
static void TimeToString(time_t time_before, char* time_str, size_t len)
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

static std::string CharToBase64(unsigned char const* raw_char, size_t len)
{
    if(raw_char == NULL){
       return {};
    }

    std::string s_ret;
    unsigned int input_char[3] = {0};
    unsigned int out_char[4] = {0};
    static const std::string base64_tmp =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";
    int i = 0;
    int j = 0;
    //remove '\0'
    if(len == strlen(reinterpret_cast<const char *>(raw_char)) + 1){
        len--;
    }

    while (len--) {
        input_char[i++] = *(raw_char++);
        
        if (i == 3) {
            out_char[0] = (input_char[0] & 0xfc) >> 2;
            out_char[1] = ((input_char[0] & 0x03) << 4) + ((input_char[1] & 0xf0) >> 4);
            out_char[2] = ((input_char[1] & 0x0f) << 2) + ((input_char[2] & 0xc0) >> 6);
            out_char[3] = input_char[2] & 0x3f;
            
            for(i = 0; (i <4) ; i++)
                s_ret += base64_tmp[out_char[i]];
            i = 0;
        }
    }
    
    if (i)
    {
        for(j = i; j < 3; j++)
            input_char[j] = '\0';
    
        out_char[0] = (input_char[0] & 0xfc) >> 2;
        out_char[1] = ((input_char[0] & 0x03) << 4) + ((input_char[1] & 0xf0) >> 4);
        out_char[2] = ((input_char[1] & 0x0f) << 2) + ((input_char[2] & 0xc0) >> 6);
        out_char[3] = input_char[2] & 0x3f;
        
        for (j = 0; (j < i + 1); j++)
            s_ret += base64_tmp[out_char[j]];
        
        while((i++ < 3))
            s_ret += '=';
    }
    return s_ret;
}

static quote3_error_t JWTJsonGenerator(const char *plat_type,
    const char *plat_version,
    const char *enclave_type,
    const char *enclave_version,
    const char *request_id,
    sgx_ql_qv_result_t qv_result,
    time_t verification_date,
    const sgx_ql_qv_supplemental_t *p_supplemental_data,
    const uint8_t *p_quote,
    const sgx_ql_qve_collateral_t *p_quote_collateral,
    uint32_t *jwt_size,
    uint8_t **jwt_data
    )
{
    if(plat_version == NULL || enclave_type == NULL || enclave_version == NULL || request_id == NULL)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    using namespace rapidjson;
    Document JWT;
    JWT.SetObject();

    Document::AllocatorType &allocator = JWT.GetAllocator();
    if(&allocator == NULL)
    {
        return SGX_QL_ERROR_UNEXPECTED;
    }

    Value obj_platform(kObjectType);
    Value obj_plat_header(kObjectType);

    //Generate platform_tcb
    Value str_type_val(kStringType);
    str_type_val.SetString(plat_type, (unsigned int)strlen(plat_type));
    if(!str_type_val.IsNull()){
        obj_plat_header.AddMember("type", str_type_val, allocator);
    }

    std::string s_request_id = CharToBase64((reinterpret_cast<unsigned char const*>(request_id)), strlen(request_id));
    str_type_val.SetString(s_request_id.c_str(), (unsigned int)(s_request_id.length()), allocator);
    if(!str_type_val.IsNull()){
        obj_plat_header.AddMember("request_id", str_type_val, allocator);
    }

    char verifytime_str[24] = {0};
    TimeToString(verification_date, verifytime_str, sizeof(verifytime_str));
    Value str_ver_date(kStringType);
    str_ver_date.SetString(verifytime_str, (unsigned int)strlen(verifytime_str));
    if(!str_ver_date.IsNull()){
        obj_plat_header.AddMember("verification_time", str_ver_date, allocator);
    }

    Value str_version_val(kStringType);
    str_version_val.SetString(plat_version, (unsigned int)strlen(plat_version));
    if(!str_version_val.IsNull()){
        obj_plat_header.AddMember("version", str_version_val, allocator);
    }
    
    obj_platform.AddMember("header", obj_plat_header, allocator);

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
        char time_str[24] = {0};
        Value str_date(kStringType);

        TimeToString(p_supplemental_data->earliest_issue_date, time_str, sizeof(time_str));
        str_date.SetString(time_str, (unsigned int)strlen(time_str), allocator);
        if(!str_date.IsNull()){
            obj_plat_tcb.AddMember("earliest_issue_date", str_date, allocator);
        }

        TimeToString(p_supplemental_data->latest_issue_date, time_str, sizeof(time_str));
        str_date.SetString(time_str, (unsigned int)strlen(time_str), allocator);
        if(!str_date.IsNull()){
            obj_plat_tcb.AddMember("latest_issue_date", str_date, allocator);
        }

        TimeToString(p_supplemental_data->earliest_expiration_date, time_str, sizeof(time_str));
        str_date.SetString(time_str, (unsigned int)strlen(time_str), allocator);
        if(!str_date.IsNull()){
            obj_plat_tcb.AddMember("earliest_expiration_date", str_date, allocator);
        }
        
        TimeToString(p_supplemental_data->tcb_level_date_tag, time_str, sizeof(time_str));
        str_date.SetString(time_str, (unsigned int)strlen(time_str), allocator);
        if(!str_date.IsNull()){
            obj_plat_tcb.AddMember("tcb_level_date_tag", str_date, allocator);
        }

        obj_plat_tcb.AddMember("tcb_eval_num", p_supplemental_data->tcb_eval_ref_num, allocator);

        //TODO
        //obj_plat_tcb.AddMember("platform_provider_id", , allocator);

        Value sgx_type_array(kArrayType);
        Value str_sgx_type(kStringType);
        std::vector<std::string> sgx_type_vec;
        sgx_type_map(sgx_type_vec, p_supplemental_data->sgx_type);
        if(!sgx_type_vec.empty())
        {
            for(size_t i=0; i<sgx_type_vec.size(); i++){
                str_sgx_type.SetString(sgx_type_vec[i].c_str(), (unsigned int)(sgx_type_vec[i].size()), allocator);
                sgx_type_array.PushBack(str_sgx_type, allocator);
            }
            obj_plat_tcb.AddMember("sgx_types", sgx_type_array, allocator);
        }

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
    }

    obj_platform.AddMember("tcb", obj_plat_tcb, allocator);
    JWT.AddMember("platform_tcb", obj_platform, allocator);

    //Generate enclave_tcb
    Value obj_enclave(kObjectType);
    Value obj_enclave_header(kObjectType);
    Value obj_enclave_tcb(kObjectType);

    Value str_enclave_type_val(kStringType);
    str_enclave_type_val.SetString(enclave_type, (unsigned int)strlen(enclave_type));
    if(!str_enclave_type_val.IsNull()){
        obj_enclave_header.AddMember("type", str_enclave_type_val, allocator);
    }

    Value str_enclave_version_val(kStringType);
    str_enclave_version_val.SetString(enclave_version, (unsigned int)strlen(enclave_version));
    if(!str_enclave_version_val.IsNull()){
        obj_enclave_header.AddMember("version", str_enclave_version_val, allocator);
    }

    Value str_enclave_request_id_val(kStringType);
    std::string s_enclave_request_id = CharToBase64((reinterpret_cast<unsigned char const*>(request_id)), strlen(request_id));
    str_enclave_request_id_val.SetString(s_enclave_request_id.c_str(), (unsigned int)(s_enclave_request_id.length()), allocator);
    if(!str_enclave_request_id_val.IsNull()){
        obj_enclave_header.AddMember("request_id", str_enclave_request_id_val, allocator);
    }

    obj_enclave.AddMember("header", obj_enclave_header, allocator);

    if(p_quote != NULL){
        
        const sgx_quote3_t *quote3 = reinterpret_cast<const sgx_quote3_t *> (p_quote);
        
        Value str_encl(kStringType);
        std::string s_miscselect = ByteStringToHexString((uint8_t *) &(quote3->report_body.misc_select), sizeof(sgx_misc_select_t));
        str_encl.SetString(s_miscselect.c_str(), (unsigned int)(s_miscselect.length()), allocator);
        if(!str_encl.IsNull()){
            obj_enclave_tcb.AddMember("miscselect", str_encl, allocator);
        }

        std::string s_attributes = ByteStringToHexString((uint8_t *) &(quote3->report_body.attributes), sizeof(sgx_attributes_t));
        str_encl.SetString(s_attributes.c_str(), (unsigned int)(s_attributes.length()), allocator);
        if(!str_encl.IsNull()){
            obj_enclave_tcb.AddMember("attributes", str_encl, allocator);
        }

        //TO DO
        //writer.Key("ce_attributes");
        
        std::string s_mrenclave = ByteStringToHexString((uint8_t *) &(quote3->report_body.mr_enclave.m), sizeof(sgx_measurement_t));
        str_encl.SetString(s_mrenclave.c_str(), (unsigned int)(s_mrenclave.length()), allocator);
        if(!str_encl.IsNull()){
            obj_enclave_tcb.AddMember("mrenclave", str_encl, allocator);
        }

        std::string s_mrsigner = ByteStringToHexString(quote3->report_body.mr_signer.m, sizeof(sgx_measurement_t));
        str_encl.SetString(s_mrsigner.c_str(), (unsigned int)(s_mrsigner.length()), allocator);
        if(!str_encl.IsNull()){
            obj_enclave_tcb.AddMember("mrsigner", str_encl, allocator);
        }

        obj_enclave_tcb.AddMember("isvprodid", quote3->report_body.isv_prod_id, allocator);
        obj_enclave_tcb.AddMember("isvsvn", quote3->report_body.isv_svn, allocator);

        std::string s_configid = ByteStringToHexString(quote3->report_body.config_id, SGX_CONFIGID_SIZE);
        str_encl.SetString(s_configid.c_str(), (unsigned int)(s_configid.length()), allocator);
        if(!str_encl.IsNull()){
            obj_enclave_tcb.AddMember("configid", str_encl, allocator);
        }

        obj_enclave_tcb.AddMember("configSVN", quote3->report_body.config_svn, allocator);
        
        std::string s_isvexprodid = ByteStringToHexString(quote3->report_body.isv_ext_prod_id, SGX_ISVEXT_PROD_ID_SIZE);
        str_encl.SetString(s_isvexprodid.c_str(), (unsigned int)(s_isvexprodid.length()), allocator);
        if(!str_encl.IsNull()){
            obj_enclave_tcb.AddMember("isvExtProdId", str_encl, allocator);
        }

        std::string s_isvfamilyid = ByteStringToHexString(quote3->report_body.isv_family_id, SGX_ISV_FAMILY_ID_SIZE);
        str_encl.SetString(s_isvfamilyid.c_str(), (unsigned int)(s_isvfamilyid.length()), allocator);
        if(!str_encl.IsNull()){
            obj_enclave_tcb.AddMember("isvFamilyId", str_encl, allocator);
        }

        std::string s_reportdata = ByteStringToHexString(quote3->report_body.report_data.d, sizeof(sgx_report_data_t));
        str_encl.SetString(s_reportdata.c_str(), (unsigned int)(s_reportdata.length()), allocator);
        if(!str_encl.IsNull()){
            obj_enclave_tcb.AddMember("reportData", str_encl, allocator);
        }

        obj_enclave.AddMember("tcb", obj_enclave_tcb, allocator);
    }
    JWT.AddMember("enclave_tcb", obj_enclave, allocator);

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
        if(p_quote_collateral->pck_crl_issuer_chain != NULL && p_quote_collateral->pck_crl_issuer_chain_size > 0){
            std::string s_pck_crl_issue_chain = CharToBase64((reinterpret_cast<unsigned char const*>(p_quote_collateral->pck_crl_issuer_chain)), p_quote_collateral->pck_crl_issuer_chain_size);
            str_collateral.SetString(s_pck_crl_issue_chain.c_str(), (unsigned int)(s_pck_crl_issue_chain.length()), allocator);
            if(!str_collateral.IsNull()){
                obj_collateral.AddMember("pck_crl_issuer_chain", str_collateral, allocator);
            }
        }

        if(p_quote_collateral->root_ca_crl != NULL && p_quote_collateral->root_ca_crl_size > 0){
            std::string s_root_ca_crl = CharToBase64((reinterpret_cast<unsigned char const*>(p_quote_collateral->root_ca_crl)), p_quote_collateral->root_ca_crl_size);
            str_collateral.SetString(s_root_ca_crl.c_str(), (unsigned int)(s_root_ca_crl.length()), allocator);
            if(!str_collateral.IsNull()){
                obj_collateral.AddMember("root_ca_crl", str_collateral, allocator);
            }
        }

        if(p_quote_collateral->pck_crl != NULL && p_quote_collateral->pck_crl_size > 0){
            std::string s_pck_crl = CharToBase64((reinterpret_cast<unsigned char const*>(p_quote_collateral->pck_crl)), p_quote_collateral->pck_crl_size);
            str_collateral.SetString(s_pck_crl.c_str(), (unsigned int)(s_pck_crl.length()), allocator);
            if(!str_collateral.IsNull()){
                obj_collateral.AddMember("pck_crl", str_collateral, allocator);
            }
        }

        if(p_quote_collateral->tcb_info_issuer_chain != NULL && p_quote_collateral->tcb_info_issuer_chain_size > 0){
            std::string s_tcb_info_issuer_chain = CharToBase64((reinterpret_cast<unsigned char const*>(p_quote_collateral->tcb_info_issuer_chain)), p_quote_collateral->tcb_info_issuer_chain_size);
            str_collateral.SetString(s_tcb_info_issuer_chain.c_str(), (unsigned int)(s_tcb_info_issuer_chain.length()), allocator);
            if(!str_collateral.IsNull()){
                obj_collateral.AddMember("tcb_info_issuer_chain", str_collateral, allocator);
            }
        }

        if(p_quote_collateral->tcb_info != NULL && p_quote_collateral->tcb_info_size > 0){
            std::string s_tcb_info = CharToBase64((reinterpret_cast<unsigned char const*>(p_quote_collateral->tcb_info)), p_quote_collateral->tcb_info_size);
            str_collateral.SetString(s_tcb_info.c_str(), (unsigned int)(s_tcb_info.length()), allocator);
            if(!str_collateral.IsNull()){
                obj_collateral.AddMember("tcb_info", str_collateral, allocator);
            }
        }

        if(p_quote_collateral->qe_identity_issuer_chain != NULL && p_quote_collateral->qe_identity_issuer_chain_size > 0){
            std::string s_qe_identity_issuer_chain = CharToBase64((reinterpret_cast<unsigned char const*>(p_quote_collateral->qe_identity_issuer_chain)), p_quote_collateral->qe_identity_issuer_chain_size);
            str_collateral.SetString(s_qe_identity_issuer_chain.c_str(), (unsigned int)(s_qe_identity_issuer_chain.length()), allocator);
            if(!str_collateral.IsNull()){
                obj_collateral.AddMember("qe_identity_issuer_chain", str_collateral, allocator);
            }
        }

        if(p_quote_collateral->qe_identity != NULL && p_quote_collateral->qe_identity_size > 0){
            std::string s_qe_identity = CharToBase64((reinterpret_cast<unsigned char const*>(p_quote_collateral->qe_identity)), p_quote_collateral->qe_identity_size);
            str_collateral.SetString(s_qe_identity.c_str(), (unsigned int)(s_qe_identity.length()), allocator);
            if(!str_collateral.IsNull()){
                obj_collateral.AddMember("qe_identity", str_collateral, allocator);
            }
        }

        JWT.AddMember("endorsement", obj_collateral, allocator);
    }

    rapidjson::StringBuffer str_buff;
    rapidjson::Writer<rapidjson::StringBuffer> writer(str_buff);
    JWT.Accept(writer);

    std::string raw_data = str_buff.GetString();
    if(raw_data.empty())
    {
        return SGX_QL_ERROR_UNEXPECTED;
    }

	auto qal_token = jwt::create()
					 .set_issuer("qal")
					 .set_type("JWT")
					 .set_payload_claim("qvl_result", jwt::claim(raw_data))
					 .sign(jwt::algorithm::none());

    if(qal_token.empty())
    {
        return SGX_QL_ERROR_UNEXPECTED;
    }

    *jwt_data = (uint8_t*)malloc(qal_token.length() + 1);
        if (*jwt_data == NULL) {
            return SGX_QL_ERROR_OUT_OF_MEMORY;
        }
    memset(*jwt_data, 0, qal_token.length() + 1);
    memcpy_s(*jwt_data, qal_token.length() + 1, qal_token.c_str(), qal_token.length());
    *jwt_size = (uint32_t)qal_token.length();
    return SGX_QL_SUCCESS;
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
    time_t current_time = time(NULL);
    uint32_t collateral_expiration_status = 1;

    supp_ver_t latest_ver;
    latest_ver.major_version = 3;

    tee_supp_data_descriptor_t supp_data;
    memset(&supp_data, 0, sizeof(tee_supp_data_descriptor_t));
    sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
    bool free_quote_collateral = false;
    sgx_ql_qve_collateral_t *p_tmp_quote_collateral = NULL;

    //get supplemental data size
    dcap_ret = tee_get_supplemental_data_version_and_size(p_quote,
                                            quote_size,
                                            &latest_ver.version,
                                            &supp_data.data_size);
    if (dcap_ret == SGX_QL_SUCCESS) {
        SE_TRACE(SE_TRACE_DEBUG,"\tInfo: tee_get_quote_supplemental_data_version_and_size successfully returned.\n");
        SE_TRACE(SE_TRACE_DEBUG,"\tInfo: latest supplemental data major version: %d, minor version: %d, size: %d\n", latest_ver.major_version, latest_ver.minor_version, supp_data.data_size);
        supp_data.p_data = (uint8_t*)malloc(supp_data.data_size);
        if (supp_data.p_data != NULL) {
            memset(supp_data.p_data, 0, supp_data.data_size);
        }
        else {
            SE_TRACE(SE_TRACE_DEBUG,"\tError: Cannot allocate memory for supplemental data.\n");
        }
    }
    else {
        SE_TRACE(SE_TRACE_DEBUG,"\tError: tee_get_supplemental_data_version_and_size failed: 0x%04x\n", dcap_ret);
        supp_data.data_size = 0;
    }

 
    dcap_ret = tee_verify_quote(
            p_quote, quote_size,
            NULL,
            current_time,
            &collateral_expiration_status,
            &quote_verification_result,
            p_qve_report_info,
            &supp_data);
    if (dcap_ret == SGX_QL_SUCCESS) {
        switch (quote_verification_result)
        {
        case SGX_QL_QV_RESULT_OK:
            break;
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            SE_TRACE(SE_TRACE_DEBUG,"\tWarning: Verification completed with Non-terminal result: 0x%04x\n", quote_verification_result);
            break;
        //Will not generate JWT when critical error occurred
        case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
        case SGX_QL_QV_RESULT_REVOKED:
        case SGX_QL_QV_RESULT_UNSPECIFIED:
        default:
            SE_TRACE(SE_TRACE_DEBUG,"\tError: Verification completed with Terminal result: 0x%04x\n", quote_verification_result);
            return SGX_QL_ERROR_UNEXPECTED;
        }
    }
    else {
        SE_TRACE(SE_TRACE_DEBUG,"\tError: tee_verify_quote failed: 0x%04x\n", dcap_ret);
        return dcap_ret;
    }

    if (p_quote_collateral == NULL)
    {
        uint32_t p_collateral_size = 0;
        free_quote_collateral = true;
        dcap_ret = tee_qv_get_collateral(
            p_quote,
            quote_size,
            reinterpret_cast<uint8_t **>(&p_tmp_quote_collateral),
            &p_collateral_size);
          
        if (dcap_ret == SGX_QL_SUCCESS) {
            SE_TRACE(SE_TRACE_DEBUG,"\tInfo: tee_qv_get_collateral successfully returned.\n");
            p_quote_collateral = reinterpret_cast<const sgx_ql_qve_collateral_t *>(p_tmp_quote_collateral);
        }
        else {
            SE_TRACE(SE_TRACE_DEBUG,"\tError: tee_qv_get_collateral failed: 0x%04x\n", dcap_ret);
        }
    }   

    unsigned char rand_nonce[17] = {0};
    if(!RAND_bytes(rand_nonce, 16))
    {
        SE_TRACE(SE_TRACE_DEBUG,"\tError: Failed to generate random request_id.\n");
    }

    dcap_ret = JWTJsonGenerator(
        TEE_PALTFORM_TOKEN_UUID, TEE_PLATFORM_TOKEN_VER,
        TEE_ENCLAVE_TOKEN_UUID, TEE_ENCLAVE_TOKEN_VER,
        reinterpret_cast<const char*>(rand_nonce),
        quote_verification_result,
        current_time,
        reinterpret_cast<const sgx_ql_qv_supplemental_t*>(supp_data.p_data),
        p_quote,
        p_quote_collateral,
        p_verification_result_token_buffer_size,
        p_verification_result_token);

    if(free_quote_collateral){
        tee_qv_free_collateral(reinterpret_cast<uint8_t *>(p_tmp_quote_collateral));
    }
    return dcap_ret;
}

quote3_error_t tee_free_verify_quote_qvt(uint8_t *p_verification_result_token, uint32_t *p_verification_result_token_buffer_size)
{
    if(p_verification_result_token == NULL)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    free(p_verification_result_token);
    p_verification_result_token_buffer_size = 0;
    return SGX_QL_SUCCESS;
}