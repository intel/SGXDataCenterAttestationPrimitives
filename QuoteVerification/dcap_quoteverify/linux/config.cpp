/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
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
 * File: config.cpp
 *
 * Description: Load SGX QPL on demand, then unload it in destructor
 *
 */

#include <dlfcn.h>
#include "sgx_qve_header.h"
#include "sgx_dcap_pcs_com.h"
#include "se_trace.h"
#include "se_thread.h"

#define MAX(x, y) (((x)>(y))?(x):(y))
#define PATH_SEPARATOR '/'
#define SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME "libdcap_quoteprov.so.1"
#define SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME_LEGACY "libdcap_quoteprov.so"

void *g_qpl_handle = NULL;
se_mutex_t g_qpl_mutex;

extern sgx_get_quote_verification_collateral_func_t p_sgx_ql_get_quote_verification_collateral;
extern sgx_free_quote_verification_collateral_func_t p_sgx_ql_free_quote_verification_collateral;

extern sgx_ql_get_qve_identity_func_t p_sgx_ql_get_qve_identity;
extern sgx_ql_free_qve_identity_func_t p_sgx_ql_free_qve_identity;

extern sgx_ql_get_root_ca_crl_func_t p_sgx_ql_get_root_ca_crl;
extern sgx_ql_free_root_ca_crl_func_t p_sgx_ql_free_root_ca_crl;

#ifndef MAX_PATH
#define MAX_PATH 260
#endif
static char g_qpl_path[MAX_PATH];


extern "C" bool sgx_qv_set_qpl_path(const char* p_path)
{
    // p_path isn't NULL, caller has checked it.
    // len <= sizeof(g_qpl_path)
    size_t len = strnlen(p_path, sizeof(g_qpl_path));
    // Make sure there is enough space for the '\0'
    // after this line len <= sizeof(g_qpl_path) - 1
    if(len > sizeof(g_qpl_path) - 1)
        return false;
    strncpy(g_qpl_path, p_path, sizeof(g_qpl_path) - 1);
    // Make sure the full path is ended with "\0"
    g_qpl_path[len] = '\0';
    return true;
}


bool sgx_dcap_load_qpl()
{
    char *err = NULL;
    bool ret = false;

    int rc = se_mutex_lock(&g_qpl_mutex);
    if (rc != 1) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to lock qpl mutex");
        return false;
    }

    if (g_qpl_handle &&
            p_sgx_ql_get_quote_verification_collateral && p_sgx_ql_free_quote_verification_collateral &&
            p_sgx_ql_get_qve_identity && p_sgx_ql_free_qve_identity &&
            p_sgx_ql_get_root_ca_crl && p_sgx_ql_free_root_ca_crl) {

        ret = true;
        goto end;
    }

    do {
        if (g_qpl_path[0]) {
            g_qpl_handle = dlopen(g_qpl_path, RTLD_LAZY);
            if (NULL == g_qpl_handle) {
                SE_TRACE(SE_TRACE_DEBUG, "Couldn't find the Quote's dependent library. %s\n",
                    g_qpl_path);
                 ret = false;
                 goto end;
             }
        }
        else {
            //try to dynamically load libdcap_quoteprov.so
            g_qpl_handle = dlopen(SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME, RTLD_LAZY);

            if (NULL == g_qpl_handle)
            {
                ///TODO:
                // This is a temporary solution to make sure the legacy library without a version suffix can be loaded.
                // We shalll remove this when we have a major version change later and drop the backward compatible
                // support for old lib name.
                g_qpl_handle = dlopen(SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME_LEGACY, RTLD_LAZY);
            }
            if (g_qpl_handle == NULL) {
                fputs(dlerror(), stderr);
                SE_TRACE(SE_TRACE_DEBUG, "Couldn't find the Quote's dependent library. %s or %s\n",
                    SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME,
                    SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME_LEGACY);
                break;
            }
        }

        //search for sgx_ql_get_quote_verification_collateral symbol in dcap_quoteprov library
        //
        p_sgx_ql_get_quote_verification_collateral = (sgx_get_quote_verification_collateral_func_t)dlsym(g_qpl_handle, QL_API_GET_QUOTE_VERIFICATION_COLLATERAL);
        err = dlerror();
        if (p_sgx_ql_get_quote_verification_collateral == NULL || err != NULL) {
            SE_TRACE(SE_TRACE_DEBUG, "Couldn't locate %s in Quote's dependent library. %s.\n", QL_API_GET_QUOTE_VERIFICATION_COLLATERAL, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            break;
        }

        //search for sgx_ql_free_quote_verification_collateral symbol in dcap_quoteprov library
        //
        p_sgx_ql_free_quote_verification_collateral = (sgx_free_quote_verification_collateral_func_t)dlsym(g_qpl_handle, QL_API_FREE_QUOTE_VERIFICATION_COLLATERAL);
        err = dlerror();
        if (p_sgx_ql_free_quote_verification_collateral == NULL || err != NULL) {
            SE_TRACE(SE_TRACE_DEBUG, "Couldn't locate %s in Quote's dependent library. %s.\n", QL_API_FREE_QUOTE_VERIFICATION_COLLATERAL, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            break;
        }

        //search for sgx_ql_get_qve_identity symbol in dcap_quoteprov library
        //
        p_sgx_ql_get_qve_identity = (sgx_ql_get_qve_identity_func_t)dlsym(g_qpl_handle, QL_API_GET_QVE_IDENTITY);
        err = dlerror();
        if (p_sgx_ql_get_qve_identity == NULL || err != NULL) {
            SE_TRACE(SE_TRACE_DEBUG, "Couldn't locate %s in Quote's dependent library. %s.\n", QL_API_GET_QVE_IDENTITY, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            break;
        }

        //search for sgx_ql_free_qve_identity symbol in dcap_quoteprov library
        //
        p_sgx_ql_free_qve_identity = (sgx_ql_free_qve_identity_func_t)dlsym(g_qpl_handle, QL_API_FREE_QVE_IDENTITY);
        err = dlerror();
        if (p_sgx_ql_free_qve_identity == NULL || err != NULL) {
            SE_TRACE(SE_TRACE_DEBUG, "Couldn't locate %s in Quote's dependent library. %s.\n", QL_API_FREE_QVE_IDENTITY, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            break;
        }

        //search for sgx_ql_get_root_ca_crl symbol in dcap_quoteprov library
        //
        p_sgx_ql_get_root_ca_crl = (sgx_ql_get_root_ca_crl_func_t)dlsym(g_qpl_handle, QL_API_GET_ROOT_CA_CRL);
        err = dlerror();
        if (p_sgx_ql_get_root_ca_crl == NULL || err != NULL) {
            SE_TRACE(SE_TRACE_DEBUG, "Couldn't locate %s in Quote's dependent library. %s.\n", QL_API_GET_ROOT_CA_CRL, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            break;
        }

        //search for sgx_ql_free_root_ca_crl symbol in dcap_quoteprov library
        //
        p_sgx_ql_free_root_ca_crl = (sgx_ql_free_root_ca_crl_func_t)dlsym(g_qpl_handle, QL_API_FREE_ROOT_CA_CRL);
        err = dlerror();
        if (p_sgx_ql_free_root_ca_crl == NULL || err != NULL) {
            SE_TRACE(SE_TRACE_DEBUG, "Couldn't locate %s in Quote's dependent library. %s.\n", QL_API_FREE_ROOT_CA_CRL, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            break;
        }

        ret = true;

    } while (0);


end:
    rc = se_mutex_unlock(&g_qpl_mutex);
    if (rc != 1) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to unlock qpl mutex");
        return false;
    }

    return ret;
}


/**
* Global constructor function of the sgx_dcap_quoteverify library. Will be called when .so is loaded
*/
__attribute__((constructor)) void _qv_global_constructor()
{
    se_mutex_init(&g_qpl_mutex);
    return;
}


/**
* Global destructor function of the sgx_dcap_quoteverify library. Will be called when .so is unloaded
*/
__attribute__((destructor)) void _qv_global_destructor()
{
    int rc = se_mutex_lock(&g_qpl_mutex);
    if (rc != 1) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to lock qpl mutex");
        //destroy the mutex before lib is unloaded, even there are some errs here
        se_mutex_destroy(&g_qpl_mutex);
        return;
    }

    if (p_sgx_ql_get_quote_verification_collateral)
        p_sgx_ql_get_quote_verification_collateral = NULL;
    if (p_sgx_ql_free_quote_verification_collateral)
        p_sgx_ql_free_quote_verification_collateral = NULL;

    if (p_sgx_ql_get_qve_identity)
        p_sgx_ql_get_qve_identity = NULL;
    if (p_sgx_ql_free_qve_identity)
        p_sgx_ql_free_qve_identity = NULL;

    if (p_sgx_ql_get_root_ca_crl)
        p_sgx_ql_get_root_ca_crl = NULL;
    if (p_sgx_ql_free_root_ca_crl)
        p_sgx_ql_free_root_ca_crl = NULL;

    if (g_qpl_handle) {
        dlclose(g_qpl_handle);
        g_qpl_handle = NULL;
    }

    rc = se_mutex_unlock(&g_qpl_mutex);
    if (rc != 1) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to unlock qpl mutex");
    }

    se_mutex_destroy(&g_qpl_mutex);
}
