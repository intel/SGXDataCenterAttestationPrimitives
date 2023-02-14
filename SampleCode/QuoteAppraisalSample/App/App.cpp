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
#include "sgx_dcap_qal.h"
#include "jwt-cpp/jwt.h"

#ifndef _MSC_VER

#define SAMPLE_ISV_ENCLAVE  "enclave.signed.so"
#define DEFAULT_QUOTE   "../QuoteGenerationSample/quote.dat"

#else

#define SAMPLE_ISV_ENCLAVE  "enclave.signed.dll"
#define DEFAULT_QUOTE   "..\\..\\..\\QuoteGenerationSample\\x64\\Debug\\quote.dat"

#define strncpy	strncpy_s
#endif

using namespace std;

typedef union _supp_ver_t{
    uint32_t version;
    struct {
        uint16_t major_version;
        uint16_t minor_version;
    };
} supp_ver_t;


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

int get_policy_token(char **p_qap, const char *policy_token_file)
{
    size_t file_size, read_size;
    char *buffer = NULL;
    FILE *fp = NULL;
    const char *prefix_str[] = {"signed token: ", "unsigned token: "};

    if(!p_qap || !policy_token_file) {
        printf("Error: get_policy_token: invalid parameter.\n");
        return -1;
    }
    *p_qap = NULL;

    // open token file to read
    fp = fopen(policy_token_file, "rb");
    if (!fp) {
        printf("Error: get_policy_token: failed to open file %s.\n", policy_token_file);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (!(buffer = (char *)malloc(file_size))) {
        printf("Error: get_policy_token: failed to allocate buffer to read file %s.\n", policy_token_file);
        fclose(fp);
        return -1;
    }

    // "signed token: " or "unsigned token: " is expected to be at the beginning of the file
    read_size = strlen(prefix_str[0]);
    if (read_size != fread(buffer, 1, read_size, fp)) {
        printf("Error: get_policy_token: read file content failed.\n");
        free(buffer);
        return -1;
    }
    if(!strncmp(buffer, prefix_str[1], read_size)) {
        fseek(fp, strlen(prefix_str[1]) - read_size, SEEK_CUR);
	read_size = strlen(prefix_str[1]);
    }
    else if (strncmp(buffer, prefix_str[0], read_size)) {
        printf("Error: get_policy_token: read file content failed.\n");
        free(buffer);
        return -1;
    }

    // read token to buffer
    read_size = file_size - read_size;
    if(read_size != fread(buffer, 1, read_size, fp)) {
        printf("Error: get_policy_token: read file content failed.\n");
        fclose(fp);
        free(buffer);
        return -1;
    }
    fclose(fp);
    buffer[read_size-1] = 0;

    *p_qap = buffer;
    return 0;
}


/**
 * @param quote - ECDSA quote buffer
 * @param use_qve - Set quote verification mode
 *                   If true, quote verification will be performed by Intel QvE
 *                   If false, quote verification will be performed by untrusted QVL
 */

int ecdsa_quote_verification(vector<uint8_t> quote, bool use_qve)
{
#ifndef TD_ENV
    sgx_status_t sgx_ret = SGX_SUCCESS;
    sgx_ql_qe_report_info_t qve_report_info;
    int updated = 0;
    sgx_launch_token_t token = { 0 };
    unsigned char rand_nonce[16] = "59jslk201fgjmm;";
#endif

    quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_enclave_id_t eid = 0;

    unsigned int jwt_token_size = 0;
    uint8_t *jwt_token = NULL;
 
    uint8_t *appraisal_result = NULL;
    uint32_t appraisal_result_buf_size = 0;

    uint8_t n_qaps = 0;
    uint8_t *p_qaps[2] = {NULL, NULL};
    time_t current_time = time(NULL);


    // Trusted quote verification
    if (use_qve) {

#ifndef TD_ENV
        //set nonce
        //
        memcpy(qve_report_info.nonce.rand, rand_nonce, sizeof(rand_nonce));

        //get target info of SampleISVEnclave. QvE will target the generated report to this enclave.
        //
        sgx_ret = sgx_create_enclave(SAMPLE_ISV_ENCLAVE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
        if (sgx_ret != SGX_SUCCESS) {
            printf("\tError: Can't load SampleISVEnclave. 0x%04x\n", sgx_ret);
            return -1;
        }
        sgx_status_t get_target_info_ret;
        sgx_ret = ecall_get_target_info(eid, &get_target_info_ret, &qve_report_info.app_enclave_target_info);
        if (sgx_ret != SGX_SUCCESS || get_target_info_ret != SGX_SUCCESS) {
            printf("\tError in sgx_get_target_info. 0x%04x\n", get_target_info_ret);
        }
        else {
            printf("\tInfo: get target info successfully returned.\n");
        }

        //call DCAP quote verify library to set QvE loading policy
        //
        dcap_ret = sgx_qv_set_enclave_load_policy(SGX_QL_DEFAULT);
        if (dcap_ret == SGX_QL_SUCCESS) {
            printf("\tInfo: sgx_qv_set_enclave_load_policy successfully returned.\n");
        }
        else {
            printf("\tError: sgx_qv_set_enclave_load_policy failed: 0x%04x\n", dcap_ret);
        }


        dcap_ret = tee_verify_quote_qvt(
                                        quote.data(), (uint32_t)quote.size(),
                                        NULL,
                                        &qve_report_info,
                                        NULL,
                                        &jwt_token_size,
                                        &jwt_token);

        if(dcap_ret ==  SGX_QL_SUCCESS){
            printf("Info: tee_verify_quote_qvt successfully returned\n");
        }
        else{
            printf("Error: tee_verify_quote_qvt failed: 0x%04x\n", dcap_ret);
            return -1;
        }
#endif

    }

    // Untrusted quote verification
    else {
        dcap_ret = tee_verify_quote_qvt(
                                        quote.data(), (uint32_t)quote.size(),
                                        NULL,
                                        NULL,
                                        NULL,
                                        &jwt_token_size,
                                        &jwt_token);

        if(dcap_ret ==  SGX_QL_SUCCESS){
            printf("Info: tee_verify_quote_qvt successfully returned\n");
        }
        else{
            printf("Error: tee_verify_quote_qvt failed: 0x%04x\n", dcap_ret);
            return -1;
        }
    }

    // appraisal
    const char *enclave_policy = "Policies/enclave_policy.txt";
    const char *platform_policy[] = {
        "Policies/platform_policy_strict.txt",
        "Policies/platform_policy_platform_grace_period.txt",
        "Policies/platform_policy_collateral_grace_period.txt",
        "Policies/platform_policy_rejected_id.txt",
    };
    uint32_t result = 0;
    for (int j = 0; j < sizeof(platform_policy)/sizeof(platform_policy[0]); j++) {
	printf("------------------------------------\n");
	printf("Appraise with policies:\n");
        n_qaps = 0;
        if (get_policy_token((char**)&p_qaps[n_qaps], enclave_policy) == 0) {
	    printf("\tenclave policy:  %s\n", enclave_policy);
            n_qaps++;
        }
        if(get_policy_token((char**)&p_qaps[n_qaps], platform_policy[j]) == 0) {
	    n_qaps++;
	    printf("\tplatform policy: %s\n", platform_policy[j]);
        }
	if(n_qaps <= 0) {
            printf("Error: failed to get policy token\n");
	    break;
	}

        for (int i = 0; i < 2; i++)
        {
            dcap_ret = tee_appraise_verification_token((const uint8_t *)jwt_token, (uint8_t **)p_qaps, n_qaps,
                                     current_time, NULL, &appraisal_result_buf_size, appraisal_result);
            if (dcap_ret == SGX_QL_SUCCESS) {
                printf("\tInfo: tee_appraise_verification_token successfully returned.\n");
                std::string jwt_str((const char*)appraisal_result);
                auto decoded = jwt::decode(jwt_str);
                auto result_str = decoded.get_payload_claim("appraisal_result").to_json().to_str();
                if (result_str.find("\"overall_appraisal_result\":true") != string::npos) {
                    printf("\tInfo: appraisal result: success\n");
		    result |= 1 << j;
                }
                else {
                    printf("\tError: appraisal result: fail\n");
                }
            }
            else if (dcap_ret == SGX_QL_ERROR_OUT_OF_MEMORY && appraisal_result_buf_size > 0) {
                appraisal_result = (uint8_t*)malloc(appraisal_result_buf_size);
                if(!appraisal_result) {
                    printf("\tError: Failed to allocate buffer for appraisal_result\n");
                    break;
                }
            }
            else {
                printf("\tError: tee_appraise_verification_token failed: 0x%04x\n", dcap_ret);
                break;
	    }
        }
        for(int i = 0; i < n_qaps; i++) {
            if(p_qaps[i]) free(p_qaps[i]);
        }
        if(appraisal_result) {
            free(appraisal_result);
            appraisal_result = 0;
            appraisal_result_buf_size = 0;
        }
    }

    if(jwt_token) {
        dcap_ret = tee_free_verify_quote_qvt(jwt_token, &jwt_token_size);
        if(dcap_ret !=  SGX_QL_SUCCESS){
            printf("\tError: free_tee_verify_quote_qvt failed: 0x%04x\n", dcap_ret);
        }
    }

    printf("Results:\n");
    for (int j = 0; j < sizeof(platform_policy)/sizeof(platform_policy[0]); j++) {
        printf("Appraisal result: %s, platform policy: %s\n", (result & (1<<j)) ? "success":"fail", platform_policy[j]+9);
    }
    return 0;
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
            strncpy(quote_path, argv[2], PATHSIZE - 1);
        }
    }

    if (*quote_path == '\0') {
        strncpy(quote_path, DEFAULT_QUOTE, PATHSIZE - 1);
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
    //      this mode doesn't rely on SGX/TDX capable system, but the results can not be cryptographically authenticated
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
