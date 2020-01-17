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


#include <stdio.h>
#include <vector>
#include <string>
#include <assert.h>
#include <fstream>
#include <sgx_uae_launch.h>
#include "sgx_urts.h"
#include "Enclave_u.h"
#include "sgx_ql_quote.h"
#include "sgx_dcap_quoteverify.h"
#include "get_qve_identity.h"

#ifndef _MSC_VER

#define SAMPLE_ISV_ENCLAVE "enclave.signed.so"
#define DEFAULT_QUOTE   "../QuoteGenerationSample/quote.dat"

#else

#define SAMPLE_ISV_ENCLAVE "enclave.signed.dll"
#define DEFAULT_QUOTE   "..\\..\\..\\QuoteGenerationSample\\x64\\Debug\\quote.dat"

#define strncpy	strncpy_s
#endif


using namespace std;


vector<uint8_t> readBinaryContent(const string& filePath)
{
    ifstream file(filePath, ios::binary);
    if (!file.is_open())
    {
        printf("Error: Unable to open quote file %s\n", filePath.c_str());
        return {};
    }

    file.seekg(0, ios_base::end);
    streampos fileSize = file.tellg();

    file.seekg(0, ios_base::beg);
    vector<uint8_t> retVal(fileSize);
    file.read(reinterpret_cast<char*>(retVal.data()), fileSize);
    file.close();
    return retVal;
}
#define PATHSIZE 0x418U


/**
 * @param quote - ECDSA quote buffer
 * @param use_qve - Set quote verification mode
 *                   If true, quote verification will be performed by Intel QvE
 *                   If false, quote verification will be performed by untrusted QVL
 */

int ecdsa_quote_verification(vector<uint8_t> quote, bool use_qve)
{
    int ret = 0;
    time_t current_time = 0;
    uint32_t supplemental_data_size = 0;
    uint8_t *p_supplemental_data = NULL;
    sgx_status_t sgx_ret = SGX_SUCCESS;
    quote3_error_t qve_ret = SGX_QL_ERROR_UNEXPECTED;
    quote3_error_t qpl_ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_ql_qv_result_t p_quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    sgx_ql_qe_report_info_t p_qve_report_info;
    unsigned char rand_nonce[16] = "59jslk201fgjmm;";
    uint32_t p_collateral_expiration_status = 1;
    uint8_t *p_qveid = NULL, *p_qveid_issue_chain = NULL;
    uint32_t qveid_size = 0, qveid_issue_chain_size = 0;
    uint8_t *p_root_ca_crl = NULL;
    uint16_t root_ca_crl_size = 0;

    int updated = 0;
    sgx_status_t verify_report_ret = SGX_ERROR_UNEXPECTED;
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = { 0 };


    // Trusted quote verification
    if (use_qve) {

        //set nonce
        //
        memcpy(p_qve_report_info.nonce.rand, rand_nonce, sizeof(rand_nonce));

        //get target info of SampleISVEnclave. QvE will target the generated report to this enclave.
        //
        sgx_ret = sgx_create_enclave(SAMPLE_ISV_ENCLAVE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
        if (sgx_ret != SGX_SUCCESS) {
            printf("\tError: Can't load SampleISVEnclave. 0x%04x\n", sgx_ret);
            return -1;
        }
        sgx_status_t get_target_info_ret;
        sgx_ret = ecall_get_target_info(eid, &get_target_info_ret, &p_qve_report_info.app_enclave_target_info);
        if (sgx_ret != SGX_SUCCESS || get_target_info_ret != SGX_SUCCESS) {
            printf("\tError in sgx_get_target_info. 0x%04x\n", qve_ret);
        }
        else {
            printf("\tInfo: get target info successfully returned.\n");
        }

        //call DCAP quote verify library to set QvE loading policy
        //
        qve_ret = sgx_qv_set_enclave_load_policy(SGX_QL_DEFAULT);
        if (qve_ret == SGX_QL_SUCCESS) {
            printf("\tInfo: sgx_qv_set_enclave_load_policy successfully returned.\n");
        }
        else {
            printf("\tError: sgx_qv_set_enclave_load_policy failed: 0x%04x\n", qve_ret);
        }


        //call DCAP quote verify library to get supplemental data size
        //
        qve_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
        if (qve_ret == SGX_QL_SUCCESS && supplemental_data_size == sizeof(sgx_ql_qv_supplemental_t)) {
            printf("\tInfo: sgx_qv_get_quote_supplemental_data_size successfully returned.\n");
            p_supplemental_data = (uint8_t*)malloc(supplemental_data_size);
        }
        else {
            printf("\tError: sgx_qv_get_quote_supplemental_data_size failed: 0x%04x\n", qve_ret);
            supplemental_data_size = 0;
        }

        //set current time. This is only for sample purposes, in production mode a trusted time should be used.
        //
        current_time = time(NULL);


        //call DCAP quote verify library for quote verification
        //here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter 'p_qve_report_info'
        //if 'p_qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
        //if 'p_qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
        qve_ret = sgx_qv_verify_quote(
            quote.data(), (uint32_t)quote.size(),
            NULL,
            current_time,
            &p_collateral_expiration_status,
            &p_quote_verification_result,
            &p_qve_report_info,
            supplemental_data_size,
            p_supplemental_data);
        if (qve_ret == SGX_QL_SUCCESS) {
            printf("\tInfo: App: sgx_qv_verify_quote successfully returned.\n");
        }
        else {
            printf("\tError: App: sgx_qv_verify_quote failed: 0x%04x\n", qve_ret);
        }

        //call QPL to retrieve QvE Identity and Root CA CRL from PCCS
        //
        qpl_ret = get_qve_identity(&p_qveid,
            &qveid_size,
            &p_qveid_issue_chain,
            &qveid_issue_chain_size,
            &p_root_ca_crl,
            &root_ca_crl_size);
        if (qpl_ret != SGX_QL_SUCCESS) {
            printf("\tError: App: Get QvE Identity and Root CA CRL from PCCS failed: 0x%04x\n", qpl_ret);
            free_qve_identity(p_qveid, p_qveid_issue_chain, p_root_ca_crl);
            sgx_destroy_enclave(eid);
            return -1;
        }
        else {
            printf("\tInfo: App: Get QvE Identity and Root CA CRL from PCCS successfully returned.\n");
        }


        //call SampleISVEnclave to verify QvE's report and QvE Identity
        //
        sgx_ret = ecall_verify_report(eid, &verify_report_ret,
            reinterpret_cast<uint8_t*>(&p_qve_report_info.qe_report),
            sizeof(sgx_report_t),
            p_qve_report_info.nonce.rand,
            sizeof(p_qve_report_info.nonce.rand),
            quote.data(),
            quote.size(),
            p_qveid,
            qveid_size,
            p_qveid_issue_chain,
            qveid_issue_chain_size,
            p_root_ca_crl,
            root_ca_crl_size,
            current_time,
            p_collateral_expiration_status,
            (uint32_t)p_quote_verification_result,
            p_supplemental_data,
            supplemental_data_size);

        if (sgx_ret != SGX_SUCCESS || verify_report_ret != SGX_SUCCESS) {
            printf("\tError: failed to verify QvE report. 0x%04x\n", verify_report_ret);
        }
        else {
            printf("\tInfo: ecall_verify_report successfully returned.\n");
        }

        //check verification result
        //
        switch (p_quote_verification_result)
        {
        case SGX_QL_QV_RESULT_OK:
            printf("\tInfo: App: Verification completed successfully.\n");
            ret = 0;
            break;
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
            printf("\tWarning: App: Verification completed with Non-terminal result: %x\n", p_quote_verification_result);
            ret = 1;
            break;
        case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
        case SGX_QL_QV_RESULT_REVOKED:
        case SGX_QL_QV_RESULT_UNSPECIFIED:
        default:
            printf("\tError: App: Verification completed with Terminal result: %x\n", p_quote_verification_result);
            ret = -1;
            break;
        }
    }



    // Untrusted quote verification
    else {
        //call DCAP quote verify library to get supplemental data size
        //
        qve_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
        if (qve_ret == SGX_QL_SUCCESS && supplemental_data_size == sizeof(sgx_ql_qv_supplemental_t)) {
            printf("\tInfo: sgx_qv_get_quote_supplemental_data_size successfully returned.\n");
            p_supplemental_data = (uint8_t*)malloc(supplemental_data_size);
        }
        else {
            printf("\tError: sgx_qv_get_quote_supplemental_data_size failed: 0x%04x\n", qve_ret);
            supplemental_data_size = 0;
        }

        //set current time. This is only for sample purposes, in production mode a trusted time should be used.
        //
        current_time = time(NULL);


        //call DCAP quote verify library for quote verification
        //here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter 'p_qve_report_info'
        //if 'p_qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
        //if 'p_qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
        qve_ret = sgx_qv_verify_quote(
            quote.data(), (uint32_t)quote.size(),
            NULL,
            current_time,
            &p_collateral_expiration_status,
            &p_quote_verification_result,
            NULL,
            supplemental_data_size,
            p_supplemental_data);
        if (qve_ret == SGX_QL_SUCCESS) {
            printf("\tInfo: App: sgx_qv_verify_quote successfully returned.\n");
        }
        else {
            printf("\tError: App: sgx_qv_verify_quote failed: 0x%04x\n", qve_ret);
        }

        //check verification result
        //
        switch (p_quote_verification_result)
        {
        case SGX_QL_QV_RESULT_OK:
            printf("\tInfo: App: Verification completed successfully.\n");
            ret = 0;
            break;
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
            printf("\tWarning: App: Verification completed with Non-terminal result: %x\n", p_quote_verification_result);
            ret = 1;
            break;
        case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
        case SGX_QL_QV_RESULT_REVOKED:
        case SGX_QL_QV_RESULT_UNSPECIFIED:
        default:
            printf("\tError: App: Verification completed with Terminal result: %x\n", p_quote_verification_result);
            ret = -1;
            break;
        }

    }


    if (p_qveid || p_qveid_issue_chain || p_root_ca_crl) {
        free_qve_identity(p_qveid, p_qveid_issue_chain, p_root_ca_crl);
    }

    if (eid) {
        sgx_destroy_enclave(eid);
    }

    return ret;
}

void usage()
{
    printf("\nUsage:\n");
    printf("\tPlease specify quote path, e.g. \"./app -quote <path/to/quote>\"\n");
    printf("\tDefault quote path is %s when no command line args\n\n", DEFAULT_QUOTE);
}


/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    vector<uint8_t> quote;

    char quote_path[PATHSIZE] = { '\0' };

    //Just for sample use, better to change solid command line args solution in production env
    if (argc != 1 && argc != 3) {
        usage();
        return 0;
    }

    if (argv[1] && argv[2]) {
        if (!strcmp(argv[1], "-quote")) {
            strncpy(quote_path, argv[2], PATHSIZE);
        }
    }

    if (*quote_path == '\0') {
        strncpy(quote_path, DEFAULT_QUOTE, PATHSIZE);
    }

    //read quote from file
    //
    quote = readBinaryContent(quote_path);
    if (quote.empty()) {
        usage();
        return -1;
    }

    printf("Info: ECDSA quote path: %s\n", quote_path);


    //We demonstrate two different types of quote verification
    //   a. Trusted quote verification - quote will be verified by Intel QvE
    //   b. Untrusted quote verification - quote will be verified by untrusted QVL (Quote Verification Library)
    //      this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
    //

    // Trusted quote verification, ignore error checking
    printf("\nTrusted quote verification:\n");
    ecdsa_quote_verification(quote, true);

    printf("\n===========================================\n");

    // Unrusted quote verification, ignore error checking
    printf("\nUntrusted quote verification:\n");
    ecdsa_quote_verification(quote, false);
    printf("\n");

    return 0;
}
