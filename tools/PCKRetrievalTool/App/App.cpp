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
 * File: app.cpp
 *
 * Description: Sample application to
 * demonstrate the usage of quote generation.
 */

#include <stdio.h>
#include <stdlib.h>
#ifdef _MSC_VER
#include <Windows.h>
#include <tchar.h>
#else
#include <dlfcn.h>
#endif
#include "version.h"
#include "sgx_urts.h"
#include "sgx_report.h"
#include "sgx_dcap_ql_wrapper.h"
#include "sgx_pce.h"
#include "sgx_quote_3.h"


#include "Enclave_u.h"

#ifdef  _MSC_VER
#define SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME _T("dcap_quoteprov.dll")
#define ENCLAVE_PATH _T("enclave.signed.dll")
#else
#define ENCLAVE_PATH "enclave.signed.so"
#define SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME "libdcap_quoteprov.so.1"
#endif
#define MAX_PATH 260

void PrintHelp() {
    printf("Usage: %s [OPTION] \n", VER_PRODUCTNAME_STR);
    printf("Example: %s -f pck_retrieval_result.csv\n", VER_PRODUCTNAME_STR);
    printf( "\nOptions:\n");
    printf( "  -f filename       - output the retrieval result to the \"filename\"\n");
    printf( "  -?                - show command help\n");
    printf( "  -h                - show command help\n");
    printf( "  -help             - show command help\n\n");
    printf( "If option is not specified, default filename(pckid_retrieval.csv) will be used\n\n");
}


// Some utility MACRO to output some of the data structures.
#define PRINT_BYTE_ARRAY(stream,mem, len)                     \
{                                                             \
    if (!(mem) || !(len)) {                                       \
        fprintf(stream,"\n( null )\n");                       \
    } else {                                                  \
        uint8_t *array = (uint8_t *)(mem);                      \
        uint32_t i = 0;                                       \
        for (i = 0; i < (len) - 1; i++) {                       \
            fprintf(stream,"%02x", array[i]);                 \
            if (i % 32 == 31 && stream == stdout)             \
               fprintf(stream,"\n");                          \
        }                                                     \
        fprintf(stream,"%02x", array[i]);                     \
    }                                                         \
}

#define WRITE_COMMA                                           \
    fprintf(pFile,",");                                       \

#ifdef DEBUG
#define PRINT_MESSAGE(message) printf(message);
#else
#define PRINT_MESSAGE(message) ;
#endif

bool create_app_enclave_report(sgx_target_info_t qe_target_info, sgx_report_t *app_report)
{
    bool ret = true;
    uint32_t retval = 0;
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_enclave_id_t eid = 0;
    int launch_token_updated = 0;
    sgx_launch_token_t launch_token = { 0 };

    // Get the app enclave report targeting the QE3
    memset(&launch_token, 0, sizeof(sgx_launch_token_t));
    sgx_status = sgx_create_enclave(ENCLAVE_PATH,
                                    0,
                                    &launch_token,
                                    &launch_token_updated,
                                    &eid,
                                    NULL);
    if (SGX_SUCCESS != sgx_status) {
        printf("Error, call sgx_create_enclave fail [%s], SGXError:%04x.\n", __FUNCTION__, sgx_status);
        ret = false;
        goto CLEANUP;
    }

    sgx_status = enclave_create_report(eid,
                                       &retval,
                                       &qe_target_info,
                                       app_report);
    if ((SGX_SUCCESS != sgx_status) || (0 != retval)) {
        printf("\nCall to get_app_enclave_report() failed\n");
        ret = false;
        goto CLEANUP;
    }

CLEANUP:
    sgx_destroy_enclave(eid);
    return ret;
}


int main(int argc, char* argv[])
{
    int ret = 0;
    bool is_default_filename_used = true;
    quote3_error_t qe3_ret = SGX_QL_SUCCESS;
    uint32_t quote_size = 0;
    uint8_t* p_quote_buffer = NULL;
    sgx_target_info_t qe_target_info;
    sgx_report_t app_report;
    FILE* pFile = NULL;
    char output_filename[MAX_PATH] = { 0 };

    printf("\n%s Version ", VER_FILE_DESCRIPTION_STR);
    printf("%s\n\n", VER_FILE_VERSION_STR);

    if(3 < argc){
        printf("Invalid arguments. parameter number is: %d\n", argc);
        PrintHelp();
        return -1;
    } else if( 2 == argc) {
        PrintHelp();
        return -1;
    } else if( 3 == argc) {
        if(strcmp(argv[1], "-f")==0){
#ifdef _MSC_VER
            strncpy_s(output_filename, argv[2], MAX_PATH);
#else
            strncpy(output_filename, argv[2], MAX_PATH);
#endif
            is_default_filename_used = false;
        }else {
            printf("Invalid arguments: %s, %s.\n \n", argv[1], argv[2]);
            PrintHelp();
            return -1;
        }
    }

	// try to load quote provide library.
#ifdef _MSC_VER
    HINSTANCE handle = LoadLibrary(SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
    if (handle != NULL) {
        PRINT_MESSAGE("Found the Quote provider library. \n");
    }
#else
    void *handle = dlopen(SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME, RTLD_LAZY);
    if (handle != NULL) {
        PRINT_MESSAGE("Found the Quote provider library. \n");
    }
#endif

    PRINT_MESSAGE("\nStep1: Call sgx_qe_get_target_info:");
    qe3_ret = sgx_qe_get_target_info(&qe_target_info);
    if (SGX_QL_SUCCESS != qe3_ret) {
        printf("Error in sgx_qe_get_target_info. 0x%04x\n", qe3_ret);
        ret = -1;
        goto CLEANUP;
    }

    PRINT_MESSAGE("succeed! \nStep2: Call create_app_report:");
    if(true != create_app_enclave_report(qe_target_info, &app_report)) {
        printf("\nCall to create_app_report() failed\n");
        ret = -1;
        goto CLEANUP;
    }

    PRINT_MESSAGE("succeed! \nStep3: Call sgx_qe_get_quote_size:");
    qe3_ret = sgx_qe_get_quote_size(&quote_size);
    if (SGX_QL_SUCCESS != qe3_ret) {
        printf("Error in sgx_qe_get_quote_size. 0x%04x\n", qe3_ret);
        ret = -1;
        goto CLEANUP;
    }

    PRINT_MESSAGE("succeed!");
    p_quote_buffer = (uint8_t*)malloc(quote_size);
    if (NULL == p_quote_buffer) {
        printf("Couldn't allocate quote_buffer\n");
        ret = -1;
        goto CLEANUP;
    }
    memset(p_quote_buffer, 0, quote_size);

    // Get the Quote
    PRINT_MESSAGE("\nStep4: Call sgx_qe_get_quote:");
    qe3_ret = sgx_qe_get_quote(&app_report,
                               quote_size,
                               p_quote_buffer);
    if (SGX_QL_SUCCESS != qe3_ret) {
        printf( "Error in sgx_qe_get_quote. 0x%04x\n", qe3_ret);
        ret = -1;
        goto CLEANUP;
    }
    PRINT_MESSAGE("succeed!");


    // Output PCK Cert Retrieval Data
    do {
        sgx_quote3_t* p_quote = (sgx_quote3_t*) p_quote_buffer;
        sgx_ql_ecdsa_sig_data_t* p_sig_data = (sgx_ql_ecdsa_sig_data_t*)p_quote->signature_data;
        sgx_ql_auth_data_t* p_auth_data = (sgx_ql_auth_data_t*)p_sig_data->auth_certification_data;
        sgx_ql_certification_data_t* p_temp_cert_data = (sgx_ql_certification_data_t*)((uint8_t*)p_auth_data + sizeof(*p_auth_data) + p_auth_data->size);
        sgx_ql_ppid_rsa3072_encrypted_cert_info_t* p_cert_info = (sgx_ql_ppid_rsa3072_encrypted_cert_info_t*)(p_temp_cert_data->certification_data);

        if(is_default_filename_used) {
#ifdef _MSC_VER
            if (0 != fopen_s(&pFile,"pckid_retrieval.csv", "w")) {
#else
            if (NULL == (pFile = fopen("pckid_retrieval.csv", "w"))) {
#endif
                printf("\nError opening pckid_retrieval.csv output file.\n");
                ret = -1;
                break;
            }
        } else {
#ifdef _MSC_VER
            if (0 != fopen_s(&pFile,output_filename, "w")) {
#else
            if (NULL == (pFile = fopen(output_filename, "w"))) {
#endif
                printf("\nError opening %s output file.\n",output_filename);
                ret = -1;
                break;
            }
        }

        uint64_t data_index = 0;
#ifdef DEBUG
        PRINT_MESSAGE("EncPPID:\n");
        PRINT_BYTE_ARRAY(stdout,p_temp_cert_data->certification_data + data_index, sizeof(p_cert_info->enc_ppid));
        PRINT_MESSAGE("\n PCE_ID:\n");
        data_index = data_index + sizeof(p_cert_info->enc_ppid);
        PRINT_BYTE_ARRAY(stdout,p_temp_cert_data->certification_data + data_index, sizeof(p_cert_info->pce_info.pce_id));
        PRINT_MESSAGE("\n TCBr - CPUSVN:\n");
        data_index = data_index + sizeof(p_cert_info->pce_info.pce_id);
        PRINT_BYTE_ARRAY(stdout,p_temp_cert_data->certification_data + data_index, sizeof(p_cert_info->cpu_svn));
        PRINT_MESSAGE("\n TCBr - PCE_ISVSVN:\n");
        data_index = data_index + sizeof(p_cert_info->cpu_svn);
        PRINT_BYTE_ARRAY(stdout,p_temp_cert_data->certification_data + data_index, sizeof(p_cert_info->pce_info.pce_isv_svn));
        PRINT_MESSAGE("\n QE_ID:\n");
        PRINT_BYTE_ARRAY(stdout,&p_quote->header.user_data[0], 16);
        PRINT_MESSAGE("\n new QE_ID:\n");
        data_index = data_index + sizeof(p_cert_info->pce_info.pce_isv_svn);
        PRINT_BYTE_ARRAY(stdout,p_temp_cert_data->certification_data + data_index, 16);
#endif
        data_index = 0;
        PRINT_BYTE_ARRAY(pFile,p_temp_cert_data->certification_data + data_index, sizeof(p_cert_info->enc_ppid));
        WRITE_COMMA;
        data_index = data_index + sizeof(p_cert_info->enc_ppid);
        PRINT_BYTE_ARRAY(pFile,p_temp_cert_data->certification_data + data_index, sizeof(p_cert_info->pce_info.pce_id));
        WRITE_COMMA;
        data_index = data_index + sizeof(p_cert_info->pce_info.pce_id);
        PRINT_BYTE_ARRAY(pFile,p_temp_cert_data->certification_data + data_index, sizeof(p_cert_info->cpu_svn));
        WRITE_COMMA;
        data_index = data_index + sizeof(p_cert_info->cpu_svn);
        PRINT_BYTE_ARRAY(pFile,p_temp_cert_data->certification_data + data_index, sizeof(p_cert_info->pce_info.pce_isv_svn));
        WRITE_COMMA;
        PRINT_BYTE_ARRAY(pFile,&p_quote->header.user_data[0], 16);
        PRINT_MESSAGE("\n");

    }while(0);
CLEANUP:
    if (NULL != p_quote_buffer) {
        free(p_quote_buffer);
    }
    if (pFile) {
        fclose(pFile);
    }
#ifdef _MSC_VER
	if (handle != NULL) {
		FreeLibrary(handle);
	}
#else
	if (handle != NULL) {
		dlclose(handle);
	}
#endif
    if(ret == 0) {
        if(is_default_filename_used) {
            printf("pckid_retrieval.csv has been generated successfully!\n");
        } else {
            printf("%s has been generated successfully!\n",output_filename);
        }
    }
    return ret;
}






