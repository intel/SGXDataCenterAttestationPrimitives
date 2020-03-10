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
 * File: utility.cpp
 *
 * Description: utility functions
 *
 */
#include <stdio.h>
#include <string>
#ifdef _MSC_VER
#include <Windows.h>
#include <tchar.h>
#else
#include <dlfcn.h>
#endif
#include "sgx_urts.h"     
#include "sgx_dcap_ql_wrapper.h"
#include "Enclave_u.h"


#ifdef DEBUG
#define PRINT_MESSAGE(message) printf(message);
#else
#define PRINT_MESSAGE(message) ;
#endif

#ifdef  _MSC_VER                
#define ENCLAVE_PATH _T("enclave.signed.dll")
#define SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME _T("dcap_quoteprov.dll")
#define SGX_MULTI_PACKAGE_AGENT_UEFI_LIBRARY _T("mp_uefi.dll")
#define FINDFUNCTIONSYM   GetProcAddress
#define CLOSELIBRARYHANDLE  FreeLibrary
#define EFIVARS_FILE_SYSTEM_IN_OS ""//for Windows OS, don't need this path 
#else
#define ENCLAVE_PATH "enclave.signed.so"
#define SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME "libdcap_quoteprov.so.1"
#define SGX_MULTI_PACKAGE_AGENT_UEFI_LIBRARY "libmpa_uefi.so"
#define FINDFUNCTIONSYM   dlsym
#define CLOSELIBRARYHANDLE  dlclose
#define EFIVARS_FILE_SYSTEM_IN_OS "/sys/firmware/efi/efivars/"
#endif 

#ifdef MPA     
#include "MPUefi.h"
typedef MpResult(*mp_uefi_init_func_t)(const char* path, const LogLevel logLevel);
typedef MpResult(*mp_uefi_get_request_type_func_t)(MpRequestType* type);
typedef MpResult(*mp_uefi_get_request_func_t)(uint8_t *request, uint16_t *request_size);
typedef MpResult(*mp_uefi_get_registration_status_func_t)(MpRegistrationStatus* status);
typedef MpResult(*mp_uefi_set_registration_status_func_t)(const MpRegistrationStatus* status);
typedef MpResult(*mp_uefi_terminate_func_t)();
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

#ifdef MPA
// for multi-package platfrom, get the platform manifet
// return value:
//  1: it means that the uefi shared library doesn't exist, maybe the registration agent package is not installed
//  0: successfully get the platform manifest
// -1: error happens.
int get_platform_manifest(uint8_t ** buffer, uint16_t &out_buffer_size)
{
    int ret = -1;
#ifdef _MSC_VER
    HINSTANCE uefi_lib_handle = LoadLibrary(SGX_MULTI_PACKAGE_AGENT_UEFI_LIBRARY);
    if (uefi_lib_handle != NULL) {
        PRINT_MESSAGE("Found the UEFI library. \n");
    }
    else {
        out_buffer_size = 0;
        buffer = NULL;
        printf("Warning: If this is a multi-package platfrom, please install registration agent package.\n");
        printf("         otherwise, the platform manifest information will NOT be retrieved.\n");
        return 1;
    }
#else
    void *uefi_lib_handle = dlopen(SGX_MULTI_PACKAGE_AGENT_UEFI_LIBRARY, RTLD_LAZY);
    if (uefi_lib_handle != NULL) {
        PRINT_MESSAGE("Found the UEFI library. \n");
    }
    else {
        out_buffer_size = 0;
        buffer = NULL;
        printf("Warning: If this is a multi-package platfrom, please install registration agent package.\n");
        printf("         otherwise, the platform manifest information will NOT be retrieved.\n");
        return 1;
    }
#endif
    mp_uefi_init_func_t p_mp_uefi_init = (mp_uefi_init_func_t)FINDFUNCTIONSYM(uefi_lib_handle, "mp_uefi_init");
    mp_uefi_get_request_type_func_t p_mp_uefi_get_request_type = (mp_uefi_get_request_type_func_t)FINDFUNCTIONSYM(uefi_lib_handle, "mp_uefi_get_request_type");
    mp_uefi_get_request_func_t p_mp_uefi_get_request = (mp_uefi_get_request_func_t)FINDFUNCTIONSYM(uefi_lib_handle, "mp_uefi_get_request");
    mp_uefi_terminate_func_t p_mp_uefi_terminate = (mp_uefi_terminate_func_t)FINDFUNCTIONSYM(uefi_lib_handle, "mp_uefi_terminate");
    if (p_mp_uefi_init == NULL ||
        p_mp_uefi_get_request_type == NULL ||
        p_mp_uefi_get_request == NULL ||
        p_mp_uefi_terminate == NULL) {
        printf("Error: cound't find uefi function interface(s) in the multi-package agent shared library.\n");
        return ret;
    }

    MpResult mpResult = MP_SUCCESS;
    MpRequestType type = MP_REQ_NONE;
    mpResult = p_mp_uefi_init(EFIVARS_FILE_SYSTEM_IN_OS, MP_REG_LOG_LEVEL_ERROR);
    if (mpResult != MP_SUCCESS) {
        printf("Error: couldn't init uefi shared library.\n");
        return ret;
    }
    do {
        mpResult = p_mp_uefi_get_request_type(&type);
        if (mpResult == MP_SUCCESS) {
            if (type == MP_REQ_REGISTRATION) {
                *buffer = new unsigned char[UINT16_MAX];
                mpResult = p_mp_uefi_get_request(*buffer, &out_buffer_size);
                if (mpResult != MP_SUCCESS) {
                    printf("Error: Couldn't get the platform manifest information.\n");
                    break;
                }
            }
            else if (type == MP_REQ_ADD_PACKAGE) {
                printf("Error: Add Package type is not supported.\n");
                break;
            }
            else {
                printf("Error: platform manifest is not avaiable.\n");
                break;
            }
        }
        else {
            printf("Error: get UEFI request type error, and the error code is: %d.\n", mpResult);
            break;
        }
        ret = 0;
    } while (0);
    p_mp_uefi_terminate();

    if (uefi_lib_handle != NULL) {
        CLOSELIBRARYHANDLE(uefi_lib_handle);
    }
    return ret;
}


// for multi-package platfrom, set registration status 
// return value:
//  1: it means that the uefi shared library doesn't exist, maybe the registration agent package is not installed
//  0: successfully set the platform's registration status.
// -1: error happens.
int set_registration_status()
{
    int ret = -1;
#ifdef _MSC_VER
    HINSTANCE uefi_lib_handle = LoadLibrary(SGX_MULTI_PACKAGE_AGENT_UEFI_LIBRARY);
    if (uefi_lib_handle != NULL) {
        PRINT_MESSAGE("Found the UEFI library. \n");
    }
    else {
        printf("Warning: If this is a multi-package platfrom, please install registration agent package.\n");
        printf("         otherwise, the platform manifest information will NOT be retrieved.\n");
        return 1;
    }
#else
    void *uefi_lib_handle = dlopen(SGX_MULTI_PACKAGE_AGENT_UEFI_LIBRARY, RTLD_LAZY);
    if (uefi_lib_handle != NULL) {
        PRINT_MESSAGE("Found the UEFI library. \n");
    }
    else {
        printf("Warning: If this is a multi-package platfrom, please install registration agent package.\n");
        printf("         otherwise, the platform manifest information will NOT be retrieved.\n");
        return 1;
    }
#endif
    mp_uefi_init_func_t p_mp_uefi_init = (mp_uefi_init_func_t)FINDFUNCTIONSYM(uefi_lib_handle, "mp_uefi_init");
    mp_uefi_set_registration_status_func_t p_mp_uefi_set_registration_status = (mp_uefi_set_registration_status_func_t)FINDFUNCTIONSYM(uefi_lib_handle, "mp_uefi_set_registration_status");
    mp_uefi_terminate_func_t p_mp_uefi_terminate = (mp_uefi_terminate_func_t)FINDFUNCTIONSYM(uefi_lib_handle, "mp_uefi_terminate");
    if (p_mp_uefi_init == NULL ||
        p_mp_uefi_set_registration_status == NULL ||
        p_mp_uefi_terminate == NULL) {
        printf("Error: cound't find uefi function interface(s) in the multi-package agent shared library.\n");
        return ret;
    }

    MpResult mpResult = MP_SUCCESS;
    MpRegistrationStatus status;
    mpResult = p_mp_uefi_init(EFIVARS_FILE_SYSTEM_IN_OS, MP_REG_LOG_LEVEL_ERROR);
    if (mpResult != MP_SUCCESS) {
        printf("Error: couldn't init uefi shared library.\n");
        return ret;
    }

    status.registrationStatus = MP_TASK_COMPLETED;
    status.errorCode = MPA_SUCCESS;
    mpResult = p_mp_uefi_set_registration_status(&status);
    if (mpResult != MP_SUCCESS) {
        printf("Warning: error happens when set registration status, the error code is: %d \n", mpResult);
    }
    else {
        ret = 0;
    }
    
    p_mp_uefi_terminate();

    if (uefi_lib_handle != NULL) {
        CLOSELIBRARYHANDLE(uefi_lib_handle);
    }
    return ret;
}
#endif


// generate ecdsa quote
// return value:
//  0: successfully generate the ecdsa quote
// -1: error happens.
int generate_quote(uint8_t **quote_buffer, uint32_t& quote_size)
{
    int ret = -1;
    quote3_error_t qe3_ret = SGX_QL_SUCCESS;
    sgx_target_info_t qe_target_info;
    sgx_report_t app_report;
    // try to load quote provide library.
#ifdef _MSC_VER
    HINSTANCE handle = LoadLibrary(SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
    if (handle != NULL) {
        PRINT_MESSAGE("Found the Quote provider library. \n");
    }
    else {
        printf("Warning: didn't find the quote provider library. \n");
    }
#else
    void *handle = dlopen(SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME, RTLD_LAZY);
    if (handle != NULL) {
        PRINT_MESSAGE("Found the Quote provider library. \n");
    }
    else {
        printf("Warning: didn't find the quote provider library. \n");
    }
#endif
    do {
        PRINT_MESSAGE("\nStep1: Call sgx_qe_get_target_info:");
        qe3_ret = sgx_qe_get_target_info(&qe_target_info);
        if (SGX_QL_SUCCESS != qe3_ret) {
            printf("Error in sgx_qe_get_target_info. 0x%04x\n", qe3_ret);
            break;
        }

        PRINT_MESSAGE("succeed! \nStep2: Call create_app_report:");
        if (true != create_app_enclave_report(qe_target_info, &app_report)) {
            printf("\nCall to create_app_report() failed\n");
            break;
        }

        PRINT_MESSAGE("succeed! \nStep3: Call sgx_qe_get_quote_size:");
        qe3_ret = sgx_qe_get_quote_size(&quote_size);
        if (SGX_QL_SUCCESS != qe3_ret) {
            printf("Error in sgx_qe_get_quote_size. 0x%04x\n", qe3_ret);
            break;
        }

        PRINT_MESSAGE("succeed!");
        *quote_buffer = (uint8_t*)malloc(quote_size);
        if (NULL == *quote_buffer) {
            printf("Couldn't allocate quote_buffer\n");
            break;
        }
        memset(*quote_buffer, 0, quote_size);

        // Get the Quote
        PRINT_MESSAGE("\nStep4: Call sgx_qe_get_quote:");
        qe3_ret = sgx_qe_get_quote(&app_report, quote_size, *quote_buffer);
        if (SGX_QL_SUCCESS != qe3_ret) {
            printf("Error in sgx_qe_get_quote. 0x%04x\n", qe3_ret);
            break;
        }
        PRINT_MESSAGE("succeed!\n");
        ret = 0;
    } while (0);

    if (handle != NULL) {
        CLOSELIBRARYHANDLE(handle);
    }
    return ret;
}


bool is_valid_proxy_type(std::string& proxy_type) {
    if (proxy_type.compare("DEFAULT") == 0 ||
        proxy_type.compare("MANUAL")  == 0 ||
        proxy_type.compare("AUTO")    == 0 ||
        proxy_type.compare("DIRECT")  == 0 ) { 
        return true;
    }
    else {
        return false;
    }                
}

bool is_valid_user_secure_cert(std::string& user_secure_cert) {
    if (user_secure_cert.compare("TRUE") == 0 ||
        user_secure_cert.compare("FALSE") == 0 ) {
        return true;
    }
    else {
        return false;
    }  
}
