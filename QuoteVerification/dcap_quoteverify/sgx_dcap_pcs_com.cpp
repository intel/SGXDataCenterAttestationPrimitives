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
 * File: sgx_dcap_pcs_com.cpp
 *
 * Description: DCAP PCS communication APIs. Dynamically load and call quote provider APIs.
 */

#include "qve_header.h"
#include "sgx_dcap_pcs_com.h"
#include <stdlib.h>
#include "se_trace.h"

#ifndef _MSC_VER
#include <dlfcn.h>
#else
#include <tchar.h>
#include <windows.h>
#endif

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

typedef quote3_error_t(*sgx_get_quote_verification_collateral_func_t)(const char *fmspc,
    uint16_t fmspc_size,
    const char *pck_ca,
    struct _sgx_ql_qve_collateral_t **pp_quote_collateral);

typedef quote3_error_t(*sgx_free_quote_verification_collateral_func_t)(struct _sgx_ql_qve_collateral_t *p_quote_collateral);


/**
 * Dynamically load sgx_ql_get_quote_verification_collateral symbol and call it.
 *
 * @param fmspc[IN] - Pointer to base 16-encoded representation of FMSPC. (5 bytes).
 * @param pck_ca[IN] - Pointer to Null terminated string identifier of the PCK Cert CA that issued the PCK Certificates. Allowed values {platform, processor}.
 * @param pp_quote_collateral[OUT] - Pointer to a pointer to the PCK quote collateral data needed for quote verification.
 *                                   The provider library will allocate this buffer and it is expected that the Quote Library will free it using the provider library’s sgx_ql_free_quote_verification_collateral() API.
 *
 * @return Status code of the operation, one of:
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_NO_QUOTE_COLLATERAL_DATA
 *      - SGX_QL_ERROR_INVALID_PARAMETER
 *      - SGX_QL_PLATFORM_LIB_UNAVAILABLE
 **/
quote3_error_t sgx_dcap_retrieve_verification_collateral(
    const char *fmspc,
    uint16_t fmspc_size,
    const char *pck_ca,
    struct _sgx_ql_qve_collateral_t **pp_quote_collateral) {

    quote3_error_t ret = SGX_QL_ERROR_INVALID_PARAMETER;
    sgx_get_quote_verification_collateral_func_t p_sgx_ql_get_quote_verification_collateral = NULL;

#ifndef _MSC_VER
    void *handle = NULL;
    char *get_quote_verification_collateral_symbol_err = NULL;
#else
    HINSTANCE handle;
#endif


    if (fmspc == NULL || pck_ca == NULL || pp_quote_collateral == NULL || *pp_quote_collateral != NULL) {
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
            SE_TRACE(SE_TRACE_DEBUG, "Couldn't find the Quote's dependent library. %s or %s\n",
                SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME,
                SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME_LEGACY);
            break;
        }

        //search for sgx_ql_get_quote_verification_collateral symbol in dcap_quoteprov library
        //
        p_sgx_ql_get_quote_verification_collateral = (sgx_get_quote_verification_collateral_func_t)dlsym(handle, QL_API_GET_QUOTE_VERIFICATION_COLLATERAL);
        get_quote_verification_collateral_symbol_err = dlerror();
        if (p_sgx_ql_get_quote_verification_collateral == NULL || get_quote_verification_collateral_symbol_err != NULL) {
            SE_TRACE(SE_TRACE_DEBUG, "Couldn't locate %s in Quote's dependent library. %s.\n", QL_API_GET_QUOTE_VERIFICATION_COLLATERAL, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            ret = SGX_QL_PLATFORM_LIB_UNAVAILABLE;
            break;
        }
#else //_MSC_VER

        //try to dynamically load dcap_quoteprov.dll
        //
        handle = LoadLibrary(TEXT(SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME));
        if (handle == NULL) {
            SE_TRACE(SE_TRACE_DEBUG, "Couldn't find the Quote's dependent library. %s.\n", SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            ret = SGX_QL_PLATFORM_LIB_UNAVAILABLE;
            break;
        }

        //search for sgx_ql_get_quote_verification_collateral symbol in dcap_quoteprov library
        //
        p_sgx_ql_get_quote_verification_collateral = (sgx_get_quote_verification_collateral_func_t)GetProcAddress(handle, QL_API_GET_QUOTE_VERIFICATION_COLLATERAL);
        if (p_sgx_ql_get_quote_verification_collateral == NULL) {
            SE_TRACE(SE_TRACE_DEBUG, "Couldn't locate %s in Quote's dependent library. %s.\n", QL_API_GET_QUOTE_VERIFICATION_COLLATERAL, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            ret = SGX_QL_PLATFORM_LIB_UNAVAILABLE;
            break;
        }
#endif //_MSC_VER

        //call p_sgx_ql_get_quote_verification_collateral to retrieve verification collateral
        //
        ret = p_sgx_ql_get_quote_verification_collateral(
            fmspc,
            fmspc_size,
            pck_ca,
            pp_quote_collateral);
        if (ret != SGX_QL_SUCCESS) {
            break;
        }
        if (*pp_quote_collateral == NULL) {
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
 * Dynamically load sgx_ql_free_quote_verification_collateral symbol and call it.
 *
 * @param pp_quote_collateral[IN] - Pointer to the PCK certification that the sgx_ql_get_quote_verification_collateral() API has allocated.
 *
 * @return Status code of the operation, one of:
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_ERROR_UNEXPECTED
 **/
quote3_error_t sgx_dcap_free_verification_collateral(struct _sgx_ql_qve_collateral_t *p_quote_collateral) {

    quote3_error_t ret = SGX_QL_ERROR_INVALID_PARAMETER;
    sgx_free_quote_verification_collateral_func_t p_sgx_ql_free_quote_verification_collateral = NULL;

#ifndef _MSC_VER
    void *handle = NULL;
    char *free_quote_verification_collateral_symbol_err = NULL;
#else
    HINSTANCE handle;
#endif


    if (p_quote_collateral == NULL) {
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
            SE_TRACE(SE_TRACE_DEBUG, "Couldn't find the Quote's dependent library. %s or %s\n",
                SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME,
                SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME_LEGACY);
            ret = SGX_QL_PLATFORM_LIB_UNAVAILABLE;
            break;
        }

        //search for sgx_ql_free_quote_verification_collateral symbol in dcap_quoteprov library
        //
        p_sgx_ql_free_quote_verification_collateral = (sgx_free_quote_verification_collateral_func_t)dlsym(handle, QL_API_FREE_QUOTE_VERIFICATION_COLLATERAL);
        free_quote_verification_collateral_symbol_err = dlerror();
        if (p_sgx_ql_free_quote_verification_collateral == NULL || free_quote_verification_collateral_symbol_err != NULL) {
            SE_TRACE(SE_TRACE_DEBUG, "Couldn't locate %s in Quote's dependent library. %s.\n", QL_API_FREE_QUOTE_VERIFICATION_COLLATERAL, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            ret = SGX_QL_PLATFORM_LIB_UNAVAILABLE;
            break;
        }
#else // _MSC_VER
        //try to dynamically load dcap_quoteprov.dll
        //
        handle = LoadLibrary(TEXT(SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME));
        if (handle == NULL) {
            SE_TRACE(SE_TRACE_DEBUG, "Couldn't find the Quote's dependent library. %s.\n", SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            ret = SGX_QL_PLATFORM_LIB_UNAVAILABLE;
            break;
        }

        //search for sgx_ql_free_quote_verification_collateral symbol in dcap_quoteprov library
        //
        p_sgx_ql_free_quote_verification_collateral = (sgx_free_quote_verification_collateral_func_t)GetProcAddress(handle, QL_API_FREE_QUOTE_VERIFICATION_COLLATERAL);
        if (p_sgx_ql_free_quote_verification_collateral == NULL) {
            SE_TRACE(SE_TRACE_DEBUG, "Couldn't locate %s in Quote's dependent library. %s.\n", QL_API_FREE_QUOTE_VERIFICATION_COLLATERAL, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            ret = SGX_QL_PLATFORM_LIB_UNAVAILABLE;
            break;
        }
#endif // _MSC_VER

        //call p_sgx_ql_free_quote_verification_collateral to free allocated memory
        //
        ret = p_sgx_ql_free_quote_verification_collateral(p_quote_collateral);
        if (ret != SGX_QL_SUCCESS) {
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

