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
 * File: platform.cpp 
 *  
 * Description: Sample platform library
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include "sgx_ql_lib_common.h"
#include "sgx_pce.h"
#include "platform.h"
#include "certchain.h"
#include <sys/stat.h>

#define MAX_PATH 260
extern "C" quote3_error_t sgx_ql_write_persistent_data(const uint8_t* p_buf, uint32_t buf_size, const char *p_data_label)
{
    quote3_error_t ret_val = SGX_QL_ERROR_UNEXPECTED;
    uint32_t write_length = 0;
    FILE* p_file = NULL;
    char p_full_path[MAX_PATH]= {0};
    fprintf(stdout, "    Entering function: sgx_ql_write_persistent_data.\n");

    if ((NULL == p_buf) || (NULL == p_data_label)) {
        ret_val = SGX_QL_ERROR_INVALID_PARAMETER;
        goto CLEANUP;
    }

    if (strnlen(p_data_label, MAX_PATH)>=MAX_PATH) {
        ret_val = SGX_QL_ERROR_INVALID_PARAMETER;
        goto CLEANUP;
    }
#if defined(_MSC_VER)
    (void)strncpy_s(p_full_path,p_data_label, MAX_PATH);
    if (0 != fopen_s(&p_file, p_full_path, "wb")) {
#else
    (void)strncpy(p_full_path,p_data_label, MAX_PATH);
    if (NULL == (p_file = fopen(p_full_path, "wb"))) {
#endif
        ret_val = SGX_QL_FILE_ACCESS_ERROR;
        goto CLEANUP;
    }

    write_length = (uint32_t)fwrite(p_buf, 1, buf_size, p_file);
    if (buf_size != write_length) {
        ret_val = SGX_QL_ERROR_UNEXPECTED;
        goto CLEANUP;
    }
    ret_val = SGX_QL_SUCCESS;

CLEANUP:
    if (p_file)
        fclose(p_file);

    fprintf(stdout, "    Leaving function: sgx_ql_write_persistent_data. 0x%04x\n", ret_val);
    return(ret_val);
}

extern "C" quote3_error_t sgx_ql_read_persistent_data(uint8_t *p_buf, uint32_t *p_buf_size, const char *p_data_label)
{
    quote3_error_t ret_val = SGX_QL_ERROR_UNEXPECTED;
    FILE* p_file = NULL;
    char p_full_path[MAX_PATH]= {0};

    fprintf(stdout, "    Entering function: sgx_ql_read_persistent_data.\n");

    if ((NULL == p_buf) ||(NULL == p_data_label)) {
         ret_val = SGX_QL_ERROR_INVALID_PARAMETER;
         goto CLEANUP;
        }

    if (strnlen(p_data_label,MAX_PATH)>=MAX_PATH) {
        ret_val = SGX_QL_ERROR_INVALID_PARAMETER;
        goto CLEANUP;
    }
#if defined(_MSC_VER)
    (void)strncpy_s(p_full_path,p_data_label, MAX_PATH);
    if (0 != fopen_s(&p_file, p_full_path, "rb")) {
#else
    (void)strncpy(p_full_path,p_data_label, MAX_PATH);
    if (NULL == (p_file = fopen(p_full_path, "rb"))) {
#endif
        ret_val = SGX_QL_FILE_ACCESS_ERROR;
         goto CLEANUP;
   }

    *p_buf_size = (uint32_t)fread(p_buf, 1, *p_buf_size, p_file);
    ret_val = SGX_QL_SUCCESS;

CLEANUP:
    if (p_file)
        fclose(p_file);

    fprintf(stdout, "    Leaving function: sgx_ql_read_persistent_data. 0x%04x\n", ret_val);
    return(ret_val);
}

extern "C" quote3_error_t sgx_ql_get_quote_config(const sgx_ql_pck_cert_id_t *p_cert_id, sgx_ql_config_t **pp_cert_config)
{
    quote3_error_t ret_val = SGX_QL_ERROR_UNEXPECTED;
    sgx_ql_config_t * p_ql_config = NULL;
    sgx_cpu_svn_t cpusvn;
    sgx_isv_svn_t pce_isvsvn;
    char* p_certdata = NULL;
    size_t certdatasize = 0;

    fprintf(stdout, "    Entering function: sgx_ql_get_quote_config.\n");
    
    if (!p_cert_id || !pp_cert_config) {
        ret_val = SGX_QL_ERROR_INVALID_PARAMETER;
        goto CLEANUP;
    }

    if (getpckchain(&p_certdata, certdatasize, &cpusvn, &pce_isvsvn) != CERT_SUCCESS){
        ret_val = SGX_QL_FILE_ACCESS_ERROR;
        goto CLEANUP;
    }

    p_ql_config = (sgx_ql_config_t *)malloc(sizeof(*p_ql_config));
    if (!p_ql_config){
        if (p_certdata){
            free(p_certdata);
            p_certdata = NULL;
        }
        ret_val = SGX_QL_ERROR_OUT_OF_MEMORY;
        goto CLEANUP;
    }
    memset(p_ql_config, 0, sizeof(*p_ql_config));

    p_ql_config->version = SGX_QL_CONFIG_VERSION_1;        
    memcpy(&p_ql_config->cert_cpu_svn, &cpusvn, sizeof(sgx_cpu_svn_t));
    memcpy(&p_ql_config->cert_pce_isv_svn, &pce_isvsvn, sizeof(sgx_isv_svn_t));

    /*<TODO> in this version (SGX_QL_CONFIG_VERSION_1), we only support certificate data (sgx_ql_config_t.p_cert_data) to be PCK certificate chain. In future version, we would support more types of certificate data, sgx_ql_config_t.p_cert_data would point to a TLV filed, which includes certificate type, size and data */
    p_ql_config->p_cert_data = (uint8_t *)p_certdata;
    p_ql_config->cert_data_size = (uint32_t)certdatasize;

    *pp_cert_config = p_ql_config;
    ret_val = SGX_QL_SUCCESS;
CLEANUP:

    fprintf(stdout, "    Leaving function: sgx_ql_get_quote_config. 0x%04x\n", ret_val);

    return ret_val;
}

extern "C" quote3_error_t sgx_ql_free_quote_config(sgx_ql_config_t *p_cert_config)
{
    quote3_error_t ret_val = SGX_QL_SUCCESS;

    fprintf(stdout, "    Entering function: sgx_ql_free_quote_config.\n");

    if (p_cert_config->p_cert_data)
        free(p_cert_config->p_cert_data);

    if (p_cert_config) 
        free(p_cert_config);

    fprintf(stdout, "    Leaving function: sgx_ql_free_quote_config. 0x%04x\n", ret_val);
    return(ret_val);
}
