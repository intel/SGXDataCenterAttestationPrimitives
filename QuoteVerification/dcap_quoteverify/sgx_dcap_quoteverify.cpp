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

    // Load the QvE
    if (g_qve_status.m_qve_eid == 0)
    {
        if (!get_qve_path(qve_enclave_path, MAX_PATH)) {

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
    int mutex_locked = 0;

    do {
        mutex_locked = se_mutex_lock(&g_qve_status.m_qve_mutex);
        if (mutex_locked == 0)
        {
            SE_TRACE(SE_TRACE_ERROR, "Failed to lock mutex\n");
            return SGX_QL_ERROR_UNEXPECTED;
        }

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

    if (mutex_locked != 0) {
        mutex_locked = se_mutex_unlock(&g_qve_status.m_qve_mutex);
        if (mutex_locked == 0) {
            SE_TRACE(SE_TRACE_ERROR, "Failed to unlock mutex\n");
        }
    }

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

    if (CHECK_MANDATORY_PARAMS(p_quote, quote_size) ||
        quote_size < QUOTE_MIN_SIZE ||
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
    int mutex_locked = 0;

    do {
        if (p_qve_report_info) {
            mutex_locked = se_mutex_lock(&g_qve_status.m_qve_mutex);
            if (mutex_locked == 0)
            {
                SE_TRACE(SE_TRACE_ERROR, "Failed to lock mutex\n");
                return SGX_QL_ERROR_UNEXPECTED;
            }

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

    if (mutex_locked != 0) {
        mutex_locked = se_mutex_unlock(&g_qve_status.m_qve_mutex);
        if (mutex_locked == 0) {
            SE_TRACE(SE_TRACE_ERROR, "Failed to unlock mutex\n");
        }
    }

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
#endif
