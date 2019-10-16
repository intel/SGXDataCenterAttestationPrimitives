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
#if defined(_MSC_VER)
#include <Windows.h>
#include <tchar.h>
#endif

#include "sgx_urts.h"
#include "sgx_quote3_defs.h"
#include "sgx_report.h"
#include "sgx_dcap_ql_wrapper.h"
#include "sgx_pce.h"
#include "sgx_error.h"

#include "Enclave_u.h"

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>

#if defined(_MSC_VER)
#define ENCLAVE_PATH _T("enclave.signed.dll")
#else
#define ENCLAVE_PATH "enclave.signed.so"
#endif

uint16_t quote_certification_type(sgx_quote3_t *p_quote_buffer);

bool create_app_enclave_report(sgx_target_info_t qe_target_info, sgx_report_t *app_report)
{
        bool ret = true;
        uint32_t retval = 0;
        sgx_status_t sgx_status = SGX_SUCCESS;
        sgx_enclave_id_t eid = 0;
        int launch_token_updated = 0;
        sgx_launch_token_t launch_token = { 0 };
        uint16_t qtype;

        sgx_status = sgx_create_enclave(ENCLAVE_PATH,
                SGX_DEBUG_FLAG,
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
    (void)(argc);
    (void)(argv);

    int ret = 0;
    int qtype = 0;
    quote3_error_t qe3_ret = SGX_QL_SUCCESS;
    uint32_t quote_size = 0;
    uint8_t* p_quote_buffer = NULL;
    sgx_target_info_t qe_target_info; 
    sgx_report_t app_report;

    printf("This step is optional: the default enclave load policy is persistent: \n");
    printf("set the enclave load policy as persistent:");
    qe3_ret = sgx_qe_set_enclave_load_policy(SGX_QL_PERSISTENT);
        if(SGX_QL_SUCCESS != qe3_ret) {
                printf("Error in set enclave load policy: 0x%04x\n", qe3_ret);
        ret = -1;
        goto CLEANUP;
    }
    printf("OK");
        
    printf("\nStep1: Call sgx_qe_get_target_info:");
    qe3_ret = sgx_qe_get_target_info(&qe_target_info);
    if (SGX_QL_SUCCESS != qe3_ret) {
        printf("Error in sgx_qe_get_target_info. 0x%04x\n", qe3_ret);
                ret = -1;
        goto CLEANUP;
    }
    printf("OK");
    printf("\nStep2: Call create_app_report:");
    if(true != create_app_enclave_report(qe_target_info, &app_report)) {
        printf("\nCall to create_app_report() failed\n");
        ret = -1;
        goto CLEANUP;
    }

    printf("OK");
    printf("\nStep3: Call sgx_qe_get_quote_size:");
    qe3_ret = sgx_qe_get_quote_size(&quote_size);
    if (SGX_QL_SUCCESS != qe3_ret) {
        printf("Error in sgx_qe_get_quote_size. 0x%04x\n", qe3_ret);
        ret = -1;
        goto CLEANUP;
    }

    printf("OK");
    p_quote_buffer = (uint8_t*)malloc(quote_size);
    if (NULL == p_quote_buffer) {
        printf("Couldn't allocate quote_buffer\n");
        ret = -1;
        goto CLEANUP;
    }
    memset(p_quote_buffer, 0, quote_size);

    // Get the Quote
    printf("\nStep4: Call sgx_qe_get_quote:");
    qe3_ret = sgx_qe_get_quote(&app_report,
        quote_size,
        p_quote_buffer);
    if (SGX_QL_SUCCESS != qe3_ret) {
        printf( "Error in sgx_qe_get_quote. 0x%04x\n", qe3_ret);
        ret = -1;
        goto CLEANUP;
    }
    printf("OK\n");

    /* Determine the quote type (the evidence used to sign the quote) */
    qtype= quote_certification_type((sgx_quote3_t *) p_quote_buffer);
    if ( qtype > 0 ) {
        printf("Quote type = %d (", qtype);
        switch(qtype) {
        case PPID_CLEARTEXT:
            printf("Clear PPID + CPU_SVN, PvE_SVN, PCE_SVN, PCE_ID");
            break;
        case PPID_RSA2048_ENCRYPTED:
            printf("RSA-2048-OAEP Encrypted PPID + CPU_SVN, PvE_SVN, PCE_SVN, PCE_ID");
            break;
        case PPID_RSA3072_ENCRYPTED:
            printf("RSA-3072-OAEP Encrypted PPID + CPU_SVN, PvE_SVN, PCE_SVN, PCE_ID");
            break;
        case PCK_CLEARTEXT:
            printf("Clear PCK Leaf Cert");
            break;
        case PCK_CERT_CHAIN:
            printf("Full PCK Cert chain");
            break;
        case ECDSA_SIG_AUX_DATA:
            printf("CERTIFICATION_INFO_DATA contains the ECDSA_SIG_AUX_DATA of another quote");
            break;
        }
        printf(")\n");
    }
 
    printf("Clean up the enclave load policy:");
    qe3_ret = sgx_qe_cleanup_by_policy();
    if(SGX_QL_SUCCESS != qe3_ret) {
        printf("Error in cleanup enclave load policy: 0x%04x\n", qe3_ret);
        ret = -1;
        goto CLEANUP;
    }
    printf("OK\n");
CLEANUP:
    if (NULL != p_quote_buffer) {
        free(p_quote_buffer);
    }
    return ret;
}

uint16_t quote_certification_type(sgx_quote3_t *q3)
{
    sgx_quote3_header_t *q3h= (sgx_quote3_header_t *) q3;
    sgx_ql_ecdsa_sig_data_t *q3s= NULL;
    sgx_ql_auth_data_t *ql_auth= NULL;
    sgx_ql_certification_data_t *ql_cert= NULL;
    uint8_t *ql_ac_data= NULL;

    switch(q3h->version) {
    case 2:
        fprintf(stderr, "EPID quote received");
        return 0;
        break;
    case 3:
        break;
    default:
        fprintf(stderr, "Unknown quote version");
        return 0;
    }

    /* Parse the variable-length data structures */

    q3s= (sgx_ql_ecdsa_sig_data_t *) &(q3->signature_data);

    ql_ac_data= (uint8_t *) &(q3s->auth_certification_data);

    ql_auth= (sgx_ql_auth_data_t *) ql_ac_data;

    ql_cert= (sgx_ql_certification_data_t *) 
        (uint8_t *)(ql_ac_data + sizeof(ql_auth->size) + ql_auth->size);

    return ql_cert->cert_key_type;
}

