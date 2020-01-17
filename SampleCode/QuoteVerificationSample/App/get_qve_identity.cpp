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
 * File: get_qve_identity.cpp
 *
 * Description: DCAP PCCS communication APIs. Dynamically load and call quote provider APIs.
 */

#include <stdio.h>
#include <stdlib.h>

#ifndef _MSC_VER
#include <dlfcn.h>
#else
#include <tchar.h>
#include <windows.h>
#endif

#include "qve_header.h"
#include "get_qve_identity.h"

#ifndef _MSC_VER
#define SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME "libdcap_quoteprov.so.1"
#define SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME_LEGACY "libdcap_quoteprov.so"
#define TCHAR char
#define _T(x) (x)
#else
#define SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME "dcap_quoteprov.dll"
#endif

#define QL_API_GET_QUOTE_VERIFICATION_COLLATERAL "sgx_ql_get_quote_verification_collateral"
#define QL_API_FREE_QUOTE_VERIFICATION_COLLATERAL "sgx_ql_free_quote_verification_collateral"

#define QL_API_GET_QVE_IDENTITY "sgx_ql_get_qve_identity"
#define QL_API_FREE_QVE_IDENTITY "sgx_ql_free_qve_identity"

#define QL_API_GET_ROOT_CA_CRL "sgx_ql_get_root_ca_crl"
#define QL_API_FREE_ROOT_CA_CRL "sgx_ql_free_root_ca_crl"

typedef quote3_error_t(*sgx_get_quote_verification_collateral_func_t)(const char *fmspc,
        uint16_t fmspc_size,
        const char *pck_ca,
        struct _sgx_ql_qve_collateral_t **pp_quote_collateral);

typedef quote3_error_t(*sgx_free_quote_verification_collateral_func_t)(struct _sgx_ql_qve_collateral_t *p_quote_collateral);

typedef quote3_error_t(*sgx_ql_get_qve_identity_func_t)(char **pp_qve_identity,
        uint32_t *p_qve_identity_size,
        char **pp_qve_identity_issuer_chain,
        uint32_t *p_qve_identity_issuer_chain_size);

typedef quote3_error_t(*sgx_ql_free_qve_identity_func_t)(char *p_qve_identity, char *p_qve_identity_issue_chain);

typedef quote3_error_t(*sgx_ql_get_root_ca_crl_func_t)(uint8_t **pp_root_ca_crl, uint16_t *p_root_ca_cal_size);

typedef quote3_error_t(*sgx_ql_free_root_ca_crl_func_t)(uint8_t *p_root_ca_crl);

/**
 * Dynamically load QPL and call API sgx_ql_get_qve_identity and sgx_ql_get_root_ca_crl to get QvE Identity and related info
 *
 * @param pp_qveid[IN/OUT] - Pointer to a pointer to the QvE Identity JSON data
 * @param p_qveid_size[IN/OUT] - Pointer to QvE Identity JSON data size
 * @param pp_qveid_issue_chain[IN/OUT] - Pointer to a pointer to the QvE Identity Signing Chain
 * @param p_qveid_issue_chain_size[IN/OUT] - Pointer to QvE Identity Signing Chain size
 * @param pp_root_ca_crl[IN/OUT] - Pointer to a pointer to the Root CA CRL
 * @param p_root_ca_crl_size[IN/OUT] - Pointer to QvE Identity Signing Chain size
 *
 * @return Status code of the operation, one of:
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_NO_QUOTE_COLLATERAL_DATA
 *      - SGX_QL_ERROR_INVALID_PARAMETER
 *      - SGX_QL_PLATFORM_LIB_UNAVAILABLE
 **/

quote3_error_t get_qve_identity(
        uint8_t **pp_qveid,
        uint32_t *p_qveid_size,
        uint8_t **pp_qveid_issue_chain,
        uint32_t *p_qveid_issue_chain_size,
        uint8_t **pp_root_ca_crl,
        uint16_t *p_root_ca_crl_size)
{

    quote3_error_t ret = SGX_QL_ERROR_INVALID_PARAMETER;
    sgx_ql_get_qve_identity_func_t p_sgx_ql_get_qve_identity = NULL;
    sgx_ql_get_root_ca_crl_func_t p_sgx_ql_get_root_ca_crl = NULL;

#ifndef _MSC_VER
    void *handle = NULL;
    char *get_qve_identity_symbol_err = NULL;
    char *get_root_ca_crl_symbol_err = NULL;
#else
    HINSTANCE handle;
#endif

    if (pp_qveid == NULL || p_qveid_size == NULL ||
        pp_qveid_issue_chain == NULL || p_qveid_issue_chain_size == NULL ||
        pp_root_ca_crl == NULL || p_root_ca_crl_size == NULL) {

        return ret;
    }

    do {
#ifndef _MSC_VER

        //try to dynamically load libdcap_quoteprov.so
        //
        handle = dlopen(SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME, RTLD_LAZY);
        if (NULL == handle)
        {
            ///TODO:
            // This is a temporary solution to make sure the legacy library without a version suffix can be loaded.
            // We shalll remove this when we have a major version change later and drop the backward compatible
            // support for old lib name.
            handle = dlopen(SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME_LEGACY, RTLD_LAZY);
        }
        if (handle == NULL) {
            fputs(dlerror(), stderr);
            ret = SGX_QL_PLATFORM_LIB_UNAVAILABLE;
            printf("Couldn't find the Quote's dependent library. %s or %s\n",
                SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME,
                SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME_LEGACY);
            break;
        }

        //search for sgx_ql_get_qve_identity symbol in dcap_quoteprov library
        //
        p_sgx_ql_get_qve_identity = (sgx_ql_get_qve_identity_func_t)dlsym(handle, QL_API_GET_QVE_IDENTITY);
        get_qve_identity_symbol_err = dlerror();
        if (p_sgx_ql_get_qve_identity == NULL || get_qve_identity_symbol_err != NULL) {
            printf("Couldn't locate %s in Quote's dependent library. %s.\n", QL_API_GET_QVE_IDENTITY, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            ret = SGX_QL_PLATFORM_LIB_UNAVAILABLE;
            break;
        }

        //search for sgx_ql_get_root_ca_crl symbol in dcap_quoteprov library
        //
        p_sgx_ql_get_root_ca_crl = (sgx_ql_get_root_ca_crl_func_t)dlsym(handle, QL_API_GET_ROOT_CA_CRL);
        get_root_ca_crl_symbol_err = dlerror();
        if (p_sgx_ql_get_root_ca_crl == NULL || get_root_ca_crl_symbol_err != NULL) {
            printf("Couldn't locate %s in Quote's dependent library. %s.\n", QL_API_GET_ROOT_CA_CRL, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            ret = SGX_QL_PLATFORM_LIB_UNAVAILABLE;
            break;
        }


#else //_MSC_VER

        //try to dynamically load dcap_quoteprov.dll
        //
        handle = LoadLibrary(TEXT(SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME));
        if (handle == NULL) {
            printf("Couldn't find the Quote's dependent library. %s.\n", SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            ret = SGX_QL_PLATFORM_LIB_UNAVAILABLE;
            break;
        }

        //search for sgx_ql_get_qve_identity symbol in dcap_quoteprov library
        //
        p_sgx_ql_get_qve_identity = (sgx_ql_get_qve_identity_func_t)GetProcAddress(handle, QL_API_GET_QVE_IDENTITY);
        if (p_sgx_ql_get_qve_identity == NULL) {
            printf("Couldn't locate %s in Quote's dependent library. %s.\n", QL_API_GET_QVE_IDENTITY, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            ret = SGX_QL_PLATFORM_LIB_UNAVAILABLE;
            break;
        }

        //search for sgx_ql_get_root_ca_crl symbol in dcap_quoteprov library
        //
        p_sgx_ql_get_root_ca_crl = (sgx_ql_get_root_ca_crl_func_t)GetProcAddress(handle, QL_API_GET_ROOT_CA_CRL);
        if (p_sgx_ql_get_root_ca_crl == NULL) {
            printf("Couldn't locate %s in Quote's dependent library. %s.\n", QL_API_GET_ROOT_CA_CRL, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            ret = SGX_QL_PLATFORM_LIB_UNAVAILABLE;
            break;
        }

#endif //_MSC_VER

        //call sgx_ql_get_qve_identity to retrieve QvE Identity and Signing Chain
        //
        ret = p_sgx_ql_get_qve_identity(
            (char **)pp_qveid,
            p_qveid_size,
            (char **)pp_qveid_issue_chain,
            p_qveid_issue_chain_size);
        if (ret != SGX_QL_SUCCESS) {
            break;
        }
        if (*pp_qveid == NULL || *pp_qveid_issue_chain == NULL) {
            ret = SGX_QL_NO_QUOTE_COLLATERAL_DATA;
            break;
        }

        //call sgx_ql_get_root_ca_crl to retrieve Root CA CRL
        //
        ret = p_sgx_ql_get_root_ca_crl(
            pp_root_ca_crl,
            p_root_ca_crl_size);
        if (ret != SGX_QL_SUCCESS) {
            break;
        }
        if (*pp_root_ca_crl == NULL) {
            ret = SGX_QL_NO_QUOTE_COLLATERAL_DATA;
            break;
        }

        ret = SGX_QL_SUCCESS;
    } while (0);

    if (handle != NULL) {
#ifndef _MSC_VER
        dlclose(handle);
#else //_MSC_VER
        FreeLibrary(handle);
#endif //_MSC_VER
    }

    return ret;
}

/**
 * Dynamically load sgx_ql_free_qve_identity and sgx_ql_free_root_ca_crl symbol and call it.
 *
 * @param p_qveid[IN] - Pointer to the QvE Identity that the sgx_ql_get_qve_identity API has allocated
 * @param p_qveid_issue_chain[IN] - Pointer to the QvE Identity Signing Chain that the sgx_ql_get_qve_identity API has allocated
 * @param p_root_ca_crl[IN] - Pointer to the Root CA CRL that the sgx_ql_get_root_ca_crl API has allocated
 *
 * @return Status code of the operation, one of:
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_ERROR_UNEXPECTED
 **/
quote3_error_t free_qve_identity(uint8_t *p_qveid, uint8_t *p_qveid_issue_chain, uint8_t *p_root_ca_crl)
{
    quote3_error_t ret = SGX_QL_ERROR_INVALID_PARAMETER;
    sgx_ql_free_qve_identity_func_t p_sgx_ql_free_qve_identity = NULL;
    sgx_ql_free_root_ca_crl_func_t p_sgx_ql_free_root_ca_crl = NULL;

#ifndef _MSC_VER
    void *handle = NULL;
    char *free_qve_identity_symbol_err = NULL;
    char *free_root_ca_crl_symbol_err = NULL;
#else
    HINSTANCE handle;
#endif

    //if all input parameters are NULL, return error
    //
    if (p_qveid == NULL && p_qveid_issue_chain == NULL && p_root_ca_crl == NULL) {
        return ret;
    }

    do {
#ifndef _MSC_VER
        //try to dynamically load libdcap_quoteprov.so
        //
        handle = dlopen(SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME, RTLD_LAZY);
        if (NULL == handle)
        {
            ///TODO:
            // This is a temporary solution to make sure the legacy library without a version suffix can be loaded.
            // We shalll remove this when we have a major version change later and drop the backward compatible
            // support for old lib name.
            handle = dlopen(SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME_LEGACY, RTLD_LAZY);
        }
        if (handle == NULL) {
            fputs(dlerror(), stderr);
            printf("Couldn't find the Quote's dependent library. %s or %s\n",
                SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME,
                SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME_LEGACY);
            ret = SGX_QL_PLATFORM_LIB_UNAVAILABLE;
            break;
        }

        //search for sgx_ql_free_qve_identity symbol in dcap_quoteprov library
        //
        p_sgx_ql_free_qve_identity = (sgx_ql_free_qve_identity_func_t)dlsym(handle, QL_API_FREE_QVE_IDENTITY);
        free_qve_identity_symbol_err = dlerror();
        if (p_sgx_ql_free_qve_identity == NULL || free_qve_identity_symbol_err != NULL) {
            printf("Couldn't locate %s in Quote's dependent library. %s.\n", QL_API_FREE_QVE_IDENTITY, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            ret = SGX_QL_PLATFORM_LIB_UNAVAILABLE;
            break;
        }

        //search for sgx_ql_free_root_ca_crl symbol in dcap_quoteprov library
        //
        p_sgx_ql_free_root_ca_crl = (sgx_ql_free_root_ca_crl_func_t)dlsym(handle, QL_API_FREE_ROOT_CA_CRL);
        free_root_ca_crl_symbol_err = dlerror();
        if (p_sgx_ql_free_root_ca_crl == NULL || free_root_ca_crl_symbol_err != NULL) {
            printf("Couldn't locate %s in Quote's dependent library. %s.\n", QL_API_FREE_ROOT_CA_CRL, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            ret = SGX_QL_PLATFORM_LIB_UNAVAILABLE;
            break;
        }

#else // _MSC_VER

        //try to dynamically load dcap_quoteprov.dll
        //
        handle = LoadLibrary(TEXT(SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME));
        if (handle == NULL) {
            printf("Couldn't find the Quote's dependent library. %s.\n", SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            ret = SGX_QL_PLATFORM_LIB_UNAVAILABLE;
            break;
        }

        //search for sgx_ql_free_qve_identity symbol in dcap_quoteprov library
        //
        p_sgx_ql_free_qve_identity = (sgx_ql_free_qve_identity_func_t)GetProcAddress(handle, QL_API_FREE_QVE_IDENTITY);
        if (p_sgx_ql_free_qve_identity == NULL) {
            printf("Couldn't locate %s in Quote's dependent library. %s.\n", QL_API_FREE_QVE_IDENTITY, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            ret = SGX_QL_PLATFORM_LIB_UNAVAILABLE;
            break;
        }

        //search for sgx_ql_free_root_ca_crl symbol in dcap_quoteprov library
        //
        p_sgx_ql_free_root_ca_crl = (sgx_ql_free_root_ca_crl_func_t)GetProcAddress(handle, QL_API_FREE_ROOT_CA_CRL);
        if (p_sgx_ql_free_root_ca_crl == NULL) {
            printf("Couldn't locate %s in Quote's dependent library. %s.\n", QL_API_FREE_ROOT_CA_CRL, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            ret = SGX_QL_PLATFORM_LIB_UNAVAILABLE;
            break;
        }

#endif // _MSC_VER

        if (p_qveid != NULL || p_qveid_issue_chain != NULL) {
            //call p_sgx_ql_free_qve_identity to free allocated memory
            //
            ret = p_sgx_ql_free_qve_identity((char *)p_qveid, (char*)p_qveid_issue_chain);
            if (ret != SGX_QL_SUCCESS) {
                break;
            }
        }

        if (p_root_ca_crl != NULL) {
            //call p_sgx_ql_free_root_ca_crl to free allocated memory
            //
            ret = p_sgx_ql_free_root_ca_crl(p_root_ca_crl);
            if (ret != SGX_QL_SUCCESS) {
                break;
            }
        }

        ret = SGX_QL_SUCCESS;
    } while (0);

    if (handle != NULL) {
#ifndef _MSC_VER
        dlclose(handle);
#else //_MSC_VER
        FreeLibrary(handle);
#endif //_MSC_VER
    }

    return ret;
}

