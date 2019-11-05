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
/**
 * File: sgx_dcap_qpl.cpp 
 *  
 * Description: Quote Provider Library
 */

#include <string>
#include <stdio.h>
#include <stdlib.h>
#include "se_memcpy.h"
#include "sgx_default_quote_provider.h"
#include "sgx_default_qcnl_wrapper.h"

using namespace std;

#ifndef _MSC_VER
#define __unaligned
#endif

static quote3_error_t qcnl_error_to_ql_error(sgx_qcnl_error_t ret)
{
    switch (ret){
        case SGX_QCNL_SUCCESS:
            return SGX_QL_SUCCESS;
        case SGX_QCNL_UNEXPECTED_ERROR:
            return SGX_QL_ERROR_UNEXPECTED;
        case SGX_QCNL_INVALID_PARAMETER:
            return SGX_QL_ERROR_INVALID_PARAMETER;
        case SGX_QCNL_OUT_OF_MEMORY:
            return SGX_QL_ERROR_OUT_OF_MEMORY;
        case SGX_QCNL_NETWORK_ERROR:
        case SGX_QCNL_NETWORK_PROXY_FAIL:
        case SGX_QCNL_NETWORK_HOST_FAIL:
        case SGX_QCNL_NETWORK_COULDNT_CONNECT:
        case SGX_QCNL_NETWORK_HTTP2_ERROR:
        case SGX_QCNL_NETWORK_WRITE_ERROR:
        case SGX_QCNL_NETWORK_OPERATION_TIMEDOUT:
        case SGX_QCNL_NETWORK_HTTPS_ERROR:
        case SGX_QCNL_NETWORK_UNKNOWN_OPTION:
        case SGX_QCNL_NETWORK_INIT_ERROR:
            return SGX_QL_NETWORK_ERROR;
        case SGX_QCNL_MSG_ERROR:
            return SGX_QL_MESSAGE_ERROR;
        case SGX_QCNL_ERROR_STATUS_NOT_FOUND:
            return SGX_QL_NO_QUOTE_COLLATERAL_DATA;
        default:
            return SGX_QL_ERROR_UNEXPECTED;
    }
}

quote3_error_t sgx_ql_get_quote_config(const sgx_ql_pck_cert_id_t *p_cert_id, sgx_ql_config_t **pp_quote_config)
{
    sgx_qcnl_error_t ret = sgx_qcnl_get_pck_cert_chain(p_cert_id, pp_quote_config);

    if (ret == SGX_QCNL_ERROR_STATUS_NOT_FOUND)
        return SGX_QL_NO_PLATFORM_CERT_DATA;
    else
        return qcnl_error_to_ql_error(ret);
}

quote3_error_t sgx_ql_free_quote_config(sgx_ql_config_t *p_quote_config)
{
    sgx_qcnl_free_pck_cert_chain(p_quote_config);

    return SGX_QL_SUCCESS;
}

static quote3_error_t split_buffer(uint8_t *in_buf, uint16_t in_buf_size, char** __unaligned out_buf1, uint32_t* __unaligned out_buf1_size,
                                   char** __unaligned out_buf2, uint32_t* __unaligned out_buf2_size)
{
    const string delimiter = "-----BEGIN CERTIFICATE-----";

    string s0((char*)in_buf, in_buf_size);
    size_t pos = s0.find(delimiter);
    if (pos == string::npos) {
        return SGX_QL_MESSAGE_ERROR;
    }

    *out_buf1_size = (uint32_t)(pos+1);   // one extra byte for NULL terminator
    *out_buf1 = reinterpret_cast<char*>(malloc(*out_buf1_size));
    if (!(*out_buf1)) {
        return SGX_QL_ERROR_OUT_OF_MEMORY;
    }
    if (memcpy_s(*out_buf1, pos, s0.c_str(), pos) != 0) {
        free(*out_buf1);
        *out_buf1 = NULL;
        return SGX_QL_ERROR_UNEXPECTED;
    }
    (*out_buf1)[pos] = 0;  // add NULL terminator

    *out_buf2_size = (uint32_t)(in_buf_size - pos +1);   // one extra byte for NULL terminator
    *out_buf2 = reinterpret_cast<char*>(malloc(*out_buf2_size));
    if (!(*out_buf2)) {
        free(*out_buf1);
        *out_buf1 = NULL;
        return SGX_QL_ERROR_OUT_OF_MEMORY;
    }
    if (memcpy_s(*out_buf2, *out_buf2_size - 1, s0.substr(pos).c_str(), in_buf_size - pos)  != 0) {
        free(*out_buf1);
        free(*out_buf2);
        *out_buf1 = NULL;
        *out_buf2 = NULL;
        return SGX_QL_ERROR_UNEXPECTED;
    }
    (*out_buf2)[*out_buf2_size - 1] = 0;  // add NULL terminator

    return SGX_QL_SUCCESS;
}

quote3_error_t sgx_ql_get_quote_verification_collateral(const uint8_t *fmspc, uint16_t fmspc_size, const char *pck_ca,
                          sgx_ql_qve_collateral_t **pp_quote_collateral)
{
    if (fmspc == NULL || pck_ca == NULL || pp_quote_collateral == NULL)
        return SGX_QL_ERROR_INVALID_PARAMETER;

    // Allocate buffer
    *pp_quote_collateral = (sgx_ql_qve_collateral_t*)malloc(sizeof(sgx_ql_qve_collateral_t));
    if (!(*pp_quote_collateral)) {
        return SGX_QL_ERROR_OUT_OF_MEMORY;
    }
    memset(*pp_quote_collateral, 0, sizeof(sgx_ql_qve_collateral_t));

    uint8_t *p_pck_crl_chain = NULL;
    uint16_t pck_crl_chain_size = 0;
    uint8_t *p_tcbinfo = NULL;
    uint16_t tcbinfo_size = 0;
    uint8_t *p_qe_identity = NULL;
    uint16_t qe_identity_size = 0;
    uint8_t *p_root_ca_crl = NULL;
    uint16_t root_ca_crl_size = 0;

    sgx_qcnl_error_t qcnl_ret = SGX_QCNL_UNEXPECTED_ERROR;
    quote3_error_t ret = SGX_QL_ERROR_UNEXPECTED;

    do {
        // Set version
        (*pp_quote_collateral)->version = 1;

        // Set PCK CRL and certchain
        qcnl_ret = sgx_qcnl_get_pck_crl_chain(pck_ca, (uint16_t)strlen(pck_ca), &p_pck_crl_chain, &pck_crl_chain_size);
        if (qcnl_ret != SGX_QCNL_SUCCESS) {
            ret = qcnl_error_to_ql_error(qcnl_ret);
            break;
        }

        ret = split_buffer(p_pck_crl_chain, pck_crl_chain_size, &(*pp_quote_collateral)->pck_crl, &(*pp_quote_collateral)->pck_crl_size,
             &(*pp_quote_collateral)->pck_crl_issuer_chain, &(*pp_quote_collateral)->pck_crl_issuer_chain_size);
        if (ret != SGX_QL_SUCCESS){
            break;
        }

        // Set TCBInfo and certchain
        qcnl_ret = sgx_qcnl_get_tcbinfo(reinterpret_cast<const char*>(fmspc), fmspc_size, &p_tcbinfo, &tcbinfo_size);
        if (qcnl_ret != SGX_QCNL_SUCCESS) {
            ret = qcnl_error_to_ql_error(qcnl_ret);
            break;
        }

        ret = split_buffer(p_tcbinfo, tcbinfo_size, &(*pp_quote_collateral)->tcb_info, &(*pp_quote_collateral)->tcb_info_size,
             &(*pp_quote_collateral)->tcb_info_issuer_chain, &(*pp_quote_collateral)->tcb_info_issuer_chain_size);
        if (ret != SGX_QL_SUCCESS){
            break;
        }

        // Set QEIdentity and certchain
        qcnl_ret = sgx_qcnl_get_qe_identity(0, &p_qe_identity, &qe_identity_size);
        if (qcnl_ret != SGX_QCNL_SUCCESS) {
            ret = qcnl_error_to_ql_error(qcnl_ret);
            break;
        }

        ret = split_buffer(p_qe_identity, qe_identity_size, &(*pp_quote_collateral)->qe_identity, &(*pp_quote_collateral)->qe_identity_size,
             &(*pp_quote_collateral)->qe_identity_issuer_chain, &(*pp_quote_collateral)->qe_identity_issuer_chain_size);
        if (ret != SGX_QL_SUCCESS){
            break;
        }

        // Set Root CA CRL
        qcnl_ret = sgx_qcnl_get_root_ca_crl(&p_root_ca_crl, &root_ca_crl_size);
        if (qcnl_ret != SGX_QCNL_SUCCESS) {
            ret = qcnl_error_to_ql_error(qcnl_ret);
            break;
        }
        (*pp_quote_collateral)->root_ca_crl_size = root_ca_crl_size + 1;
        (*pp_quote_collateral)->root_ca_crl = reinterpret_cast<char*>(malloc((*pp_quote_collateral)->root_ca_crl_size));
        if (!(*pp_quote_collateral)->root_ca_crl) {
            ret = SGX_QL_ERROR_OUT_OF_MEMORY;
            break;
        }
        if (memcpy_s((*pp_quote_collateral)->root_ca_crl, (*pp_quote_collateral)->root_ca_crl_size,
                     p_root_ca_crl, root_ca_crl_size) != 0) {
            ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }
        (*pp_quote_collateral)->root_ca_crl[root_ca_crl_size] = 0; // Add NULL terminator

        ret = SGX_QL_SUCCESS;
    }
    while (0);

    sgx_qcnl_free_pck_crl_chain(p_pck_crl_chain);
    sgx_qcnl_free_tcbinfo(p_tcbinfo);
    sgx_qcnl_free_qe_identity(p_qe_identity);
    sgx_qcnl_free_root_ca_crl(p_root_ca_crl);

    if (ret != SGX_QL_SUCCESS) {
        sgx_ql_free_quote_verification_collateral(*pp_quote_collateral);
        *pp_quote_collateral = NULL;
    }

    return ret;
}

quote3_error_t sgx_ql_free_quote_verification_collateral(sgx_ql_qve_collateral_t *p_quote_collateral)
{
    if (p_quote_collateral) {
        if (p_quote_collateral->pck_crl_issuer_chain) {
            free(p_quote_collateral->pck_crl_issuer_chain);
            p_quote_collateral->pck_crl_issuer_chain = NULL;
        }
        if (p_quote_collateral->root_ca_crl) {
            free(p_quote_collateral->root_ca_crl);
            p_quote_collateral->root_ca_crl = NULL;
        }
        if (p_quote_collateral->pck_crl) {
            free(p_quote_collateral->pck_crl);
            p_quote_collateral->pck_crl = NULL;
        }
        if (p_quote_collateral->tcb_info_issuer_chain) {
            free(p_quote_collateral->tcb_info_issuer_chain);
            p_quote_collateral->tcb_info_issuer_chain = NULL;
        }
        if (p_quote_collateral->tcb_info) {
            free(p_quote_collateral->tcb_info);
            p_quote_collateral->tcb_info = NULL;
        }
        if (p_quote_collateral->qe_identity_issuer_chain) {
            free(p_quote_collateral->qe_identity_issuer_chain);
            p_quote_collateral->qe_identity_issuer_chain = NULL;
        }
        if (p_quote_collateral->qe_identity) {
            free(p_quote_collateral->qe_identity);
            p_quote_collateral->qe_identity = NULL;
        }
        free(p_quote_collateral);
    }

    return SGX_QL_SUCCESS;
}

quote3_error_t sgx_ql_get_qve_identity(char **pp_qve_identity, 
                                       uint32_t *p_qve_identity_size, 
                                       char **pp_qve_identity_issuer_chain, 
                                       uint32_t *p_qve_identity_issuer_chain_size)
{
    sgx_qcnl_error_t ret = sgx_qcnl_get_qve_identity(pp_qve_identity, p_qve_identity_size, pp_qve_identity_issuer_chain, p_qve_identity_issuer_chain_size);

    if (ret == SGX_QCNL_ERROR_STATUS_NOT_FOUND)
        return SGX_QL_NO_QVE_IDENTITY_DATA;
    else
        return qcnl_error_to_ql_error(ret);
}

quote3_error_t sgx_ql_free_qve_identity(char *p_qve_identity, char *p_qve_identity_issuer_chain)
{
    sgx_qcnl_free_qve_identity(p_qve_identity, p_qve_identity_issuer_chain);

    return SGX_QL_SUCCESS;
}
