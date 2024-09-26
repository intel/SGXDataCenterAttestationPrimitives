/*
 * Copyright (C) 2011-2024 Intel Corporation. All rights reserved.
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
#include "sgx_ql_quote.h"
#include "sgx_dcap_quoteverify.h"
#include "sgx_dcap_qal.h"
#include "jwt-cpp/jwt.h"
#include "sgx_dcap_qae_tvl.h"
#include "Enclave_u.h"
#include "sgx_urts.h"

#define DEFAULT_QUOTE   "../../QuoteGenerationSample/quote.dat"
#define ENCLAVE_FILENAME "enclave.signed.so"
#define PUBKEY_FILENAME "../Policies/ec_pub.pem"
using namespace std;

string enclave_policy = "../Policies/sgx_enclave_policy.jwt";
string tdx_policy = "../Policies/tenant_td_policy.jwt";
vector<string> sgx_platform_policy = {
    "../Policies/sgx_platform_policy_strict.jwt",
    "../Policies/sgx_platform_policy_platform_grace_period.jwt",
    "../Policies/sgx_platform_policy_collateral_grace_period.jwt",
    "../Policies/sgx_platform_policy_rejected_id.jwt",
};
vector<string> tdx_platform_policy = {
    "../Policies/tdx_platform_policy_strict.jwt",
    "../Policies/tdx_platform_policy_platform_grace_period.jwt",
    "../Policies/tdx_platform_policy_collateral_grace_period.jwt",
    "../Policies/tdx_platform_policy_rejected_id.jwt",
    // Alibaba Cloud predefined TDX platform policy with FMSPC 90C06F000000
    "../Policies/alibabacloud_tdx_platform_policy_90C06F000000.jwt",
};
string &g_tenant_policy = enclave_policy;
vector<string> &g_platform_policy = sgx_platform_policy;
sgx_enclave_id_t g_eid = 0;

#define SGX_QUOTE_TYPE 0x0
#define TDX_QUOTE_TYPE 0x81
#define QAE_ISVSVN     0xC 

int check_quote_type(uint8_t *quote)
{
    uint32_t *p_type = (uint32_t *) (quote + sizeof(uint16_t) * 2);

    if (*p_type == SGX_QUOTE_TYPE) {
        printf("Info: Quote type - SGX quote.\n");
        g_tenant_policy = enclave_policy;
        g_platform_policy = sgx_platform_policy;
    }
    else if (*p_type == TDX_QUOTE_TYPE) {
        printf("Info: Quote type - TDX quote.\n");
        g_tenant_policy = tdx_policy;
        g_platform_policy = tdx_platform_policy;
    }
    else {
        printf("Error: Unsupported quote type.\n");
        //quote type is not supported
        return -1;
    }
    return 0;
}

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

int gen_random_data(uint8_t *buf, uint32_t buf_size)
{
    static bool init = false;

    if (!init) {
        srand((uint32_t)time(NULL));
        init = true;
    }

    for(uint32_t i = 0; i < buf_size; i++) {
        buf[i] = (uint8_t)rand();
    }

    return 0;
}

#define PATHSIZE 0x418U

int get_policy_token(char **p_qap, const char *policy_token_file)
{
    size_t file_size;
    char *buffer = NULL;
    FILE *fp = NULL;

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
    if (!(buffer = (char *)malloc(file_size+1))) {
        printf("Error: get_policy_token: failed to allocate buffer to read file %s.\n", policy_token_file);
        fclose(fp);
        return -1;
    }

    // read token to buffer
    if(file_size != fread(buffer, 1, file_size, fp)) {
        printf("Error: get_policy_token: read file content failed.\n");
        fclose(fp);
        free(buffer);
        return -1;
    }
    fclose(fp);
    buffer[file_size] = 0;

    *p_qap = buffer;
    return 0;
}

static int quote_appraisal(vector<uint8_t> quote, uint8_t **p_appraisal_result, uint8_t **p_qaps, uint8_t n_qaps)
{
    quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_status_t sgx_ret = SGX_ERROR_UNEXPECTED;

    uint8_t *jwt_token = NULL;
    unsigned int jwt_token_size = 0;

    uint8_t *appraisal_result = NULL;
    uint32_t appraisal_result_buf_size = 0;
    time_t current_time = time(NULL);

    sgx_ql_qe_report_info_t report_info;
    qae_verification_input_t input;

    if(quote.empty() || p_appraisal_result == NULL || p_qaps == NULL || n_qaps != 2)
    {
        return -1;
    }
    *p_appraisal_result = NULL;

    memset(&report_info, 0, sizeof(report_info));
    gen_random_data(report_info.nonce.rand, sizeof(report_info.nonce.rand));
    // Get the enclave target info
    sgx_ret = sgx_get_target_info(g_eid, &report_info.app_enclave_target_info);
    if (sgx_ret != SGX_SUCCESS) {
        printf("sgx_get_target_info failed: 0x%04x\n", sgx_ret);
        goto CLEANUP;
    }

    // verify quote
    dcap_ret = tee_verify_quote_qvt(
                 quote.data(), (uint32_t)quote.size(),
                 NULL,
                 &report_info,
                 NULL,
                 &jwt_token_size,
                 &jwt_token);
    if(dcap_ret ==  SGX_QL_SUCCESS){
        printf("\tInfo: tee_verify_quote_qvt successfully returned\n");
    }
    else{
        printf("\tError: tee_verify_quote_qvt failed: 0x%04x\n", dcap_ret);
        return -1;
    }

    // appraise quote
    dcap_ret = tee_appraise_verification_token(
                    jwt_token, 
                    p_qaps, n_qaps,
                    current_time, 
                    &report_info, 
                    &appraisal_result_buf_size, 
                    &appraisal_result);
    if (dcap_ret == SGX_QL_SUCCESS) {
        printf("\tInfo: tee_appraise_verification_token successfully returned.\n");
    }
    else {
        printf("\tError: tee_appraise_verification_token failed: 0x%04x\n", dcap_ret);
        goto CLEANUP;
    }

    // read appraial result from token
    {
        string jwt_str((const char*)appraisal_result);
        auto decoded = jwt::decode(jwt_str);
        auto result_str = decoded.get_payload_claim("appraisal_result").to_json().to_str();
        if (result_str.find("\"overall_appraisal_result\":1") != string::npos) {
            printf("\tInfo: Appraisal result: success\n");
        }
        else {
            printf("\tError: Appraisal result: failure\n");
            printf("\tAppraisal result:%s\n", result_str.c_str());
            goto CLEANUP;
        }
    }

    // verify QAE report and identify
    memset(&input, 0, sizeof(input));
    input.mode = APPRAISAL;
    input.input.appraisal.p_appraisal_jwt = (char *)appraisal_result;
    input.input.appraisal.p_qvl_jwt = (char *)jwt_token;
    input.input.appraisal.appraisal_check_date = current_time;
    input.input.appraisal.p_policies = p_qaps;
    input.input.appraisal.policy_count = n_qaps;

    sgx_ret = tee_verify_qae_report_and_identity(g_eid, &dcap_ret, &input, report_info, QAE_ISVSVN);
    if(sgx_ret != SGX_SUCCESS)
    {
        printf("\tError: tee_verify_qae_report_and_identity failed: 0x%04x\n", sgx_ret);
        goto CLEANUP;
    }
    if(dcap_ret != TEE_SUCCESS)
    {
        printf("\tError: verify appraisal result failed: 0x%04x\n", dcap_ret);
        goto CLEANUP;
    }

    *p_appraisal_result = appraisal_result;

CLEANUP: 
    // free the quote verification result token
    if(jwt_token) {
        dcap_ret = tee_free_verify_quote_qvt(jwt_token, &jwt_token_size);
        if(dcap_ret !=  SGX_QL_SUCCESS){
            printf("\tError: tee_free_verify_quote_qvt failed: 0x%04x\n", dcap_ret);
        }
    }
    if(*p_appraisal_result == NULL && appraisal_result) {
        dcap_ret = tee_free_appraisal_token(appraisal_result);
        if(dcap_ret !=  SGX_QL_SUCCESS){
            printf("\tError: tee_free_appraisal_token failed: 0x%04x\n", dcap_ret);
        }
    }
    return 0;
}

static int authenticate_policy(vector<uint8_t> quote, uint8_t *appraisal_result, uint8_t **p_qaps, uint8_t n_qaps)
{
    quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_status_t sgx_ret = SGX_ERROR_UNEXPECTED;

    tee_policy_bundle_t bundle;
    tee_policy_auth_result_t auth_result = TEE_AUTH_FAILURE;

    sgx_ql_qe_report_info_t qae_report_info;
    sgx_target_info_t enclave_target_info;

    qae_verification_input_t input;

    if(quote.empty() || appraisal_result == NULL || p_qaps == NULL || n_qaps != 2)
    {
        return -1;
    }

    // check whether the input policies are used in the appraisal process
    memset(&bundle, 0, sizeof(tee_policy_bundle_t));
    bundle.p_tenant_identity_policy = (const uint8_t*)p_qaps[0];
    bundle.platform_policy.p_policy = (const uint8_t*)p_qaps[1];
    bundle.platform_policy.pt = CUSTOMIZED;

    // Get the enclave target info
    memset(&enclave_target_info, 0, sizeof(enclave_target_info));
    sgx_ret = sgx_get_target_info(g_eid, &enclave_target_info);
    if (sgx_ret != SGX_SUCCESS) {
        printf("sgx_get_target_info failed: 0x%04x\n", sgx_ret);
        return -1;
    }
    memset(&qae_report_info, 0, sizeof(qae_report_info));
    gen_random_data(qae_report_info.nonce.rand, sizeof(qae_report_info.nonce.rand));
    memcpy(&qae_report_info.app_enclave_target_info, &enclave_target_info, sizeof(enclave_target_info));

    dcap_ret = tee_authenticate_appraisal_result_ex(
                    quote.data(), (uint32_t)quote.size(),
                    appraisal_result,
                    &bundle,
                    NULL, NULL,
                    &auth_result,
                    &qae_report_info);
    if (dcap_ret != SGX_QL_SUCCESS) {
        printf("\tError: tee_authenticate_appraisal_result_ex() failed: 0x%04x\n", dcap_ret);
        return -1;
    }
    else
    {
        if (auth_result == TEE_AUTH_SUCCESS)
        {
            printf("\tInfo: Policies are authenticated successfully.\n");
        }
        else if (auth_result == TEE_AUTH_FAILURE)
        {
            printf("\tError: Authentication failures occur in some policies. Please check.\n");
            return -1;
        }
        else
        {
            printf("\tError: There are some policies un-authenticated. Please check.\n");
            return -1;
        }
    }
    // verify QAE report and identify
    memset(&input, 0, sizeof(input));
    input.mode = AUTH_POLICY;
    input.input.auth_policy.p_appraisal_jwt = (char *)appraisal_result;
    input.input.auth_policy.p_policy_bundle = &bundle;
    input.input.auth_policy.p_result = &auth_result;
    input.input.auth_policy.p_quote = quote.data();
    input.input.auth_policy.quote_size = (uint32_t)quote.size();

    sgx_ret = tee_verify_qae_report_and_identity(g_eid, &dcap_ret, &input, qae_report_info, QAE_ISVSVN);
    if(sgx_ret != SGX_SUCCESS)
    {
        printf("\tError: tee_verify_qae_report_and_identity failed: 0x%04x\n", sgx_ret);
        return -1;
    }
    if(dcap_ret != TEE_SUCCESS)
    {
        printf("\tError: Verify auth policy failed: 0x%04x\n", dcap_ret);
        return -1;
    }
    else
    {
        printf("\tInfo: Verify policy authentication successfully\n");
    }

    return 0;
}

static int authenticate_owner(vector<uint8_t> quote, uint8_t *appraisal_result)
{
    quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_status_t sgx_ret = SGX_ERROR_UNEXPECTED;

    vector<uint8_t> pub_key = readBinaryContent(PUBKEY_FILENAME);
    pub_key.push_back(0);
    uint8_t *key_list[1];
    key_list[0] = pub_key.data();

    tee_policy_auth_result_t auth_result = TEE_AUTH_FAILURE;

    sgx_ql_qe_report_info_t qae_report_info;
    sgx_target_info_t enclave_target_info;

    qae_verification_input_t input;

    if(quote.empty() || appraisal_result == NULL)
    {
        return -1;
    }

    // Get the enclave target info
    memset(&enclave_target_info, 0, sizeof(enclave_target_info));
    sgx_ret = sgx_get_target_info(g_eid, &enclave_target_info);
    if (sgx_ret != SGX_SUCCESS) {
        printf("sgx_get_target_info failed: 0x%04x\n", sgx_ret);
        return -1;
    }
    memset(&qae_report_info, 0, sizeof(qae_report_info));
    gen_random_data(qae_report_info.nonce.rand, sizeof(qae_report_info.nonce.rand));
    memcpy(&qae_report_info.app_enclave_target_info, &enclave_target_info, sizeof(enclave_target_info));

    dcap_ret = tee_authenticate_policy_owner(
                    quote.data(), (uint32_t)quote.size(), 
                    appraisal_result, 
                    const_cast<const uint8_t **>(key_list), sizeof(key_list)/sizeof(key_list[0]), 
                    NULL, NULL, 
                    &auth_result,
                    &qae_report_info);
    if (dcap_ret != SGX_QL_SUCCESS) {
         printf("\tError: tee_authenticate_policy_owner failed: 0x%04x\n", dcap_ret);
         return -1;
    }
    if(auth_result != TEE_AUTH_SUCCESS) {
         printf("\tError: Authenticate policy owner failed, %x\n", auth_result);
         return -1;
    }
    else {
         printf("\tInfo: Authenticate policy owner successfully\n");
    }

    // verify QAE report and identify
    memset(&input, 0, sizeof(input));
    input.mode = AUTH_OWNER;
    input.input.auth_owner.p_appraisal_jwt = (char *)appraisal_result;
    input.input.auth_owner.p_policy_key_list = (uint8_t **)key_list;
    input.input.auth_owner.key_list_count = sizeof(key_list)/sizeof(key_list[0]);
    input.input.auth_owner.p_result = &auth_result;
    input.input.auth_owner.p_quote = quote.data();
    input.input.auth_owner.quote_size = (uint32_t)quote.size();

    sgx_ret = tee_verify_qae_report_and_identity(g_eid, &dcap_ret, &input, qae_report_info, QAE_ISVSVN);
    if(sgx_ret != SGX_SUCCESS) {
        printf("\tError: tee_verify_qae_report_and_identity failed: 0x%04x\n", sgx_ret);
        return -1;
    }
    if(dcap_ret != TEE_SUCCESS) {
        printf("\tError: Verify auth owner failed: 0x%04x\n", dcap_ret);
        return -1;
    }
    else {
        printf("\tInfo: Verify owner authentication successfully\n");
    }
    return 0;
}

// @param quote - ECDSA quote buffer
int ecdsa_quote_verification(vector<uint8_t> quote)
{
    quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_status_t sgx_ret = SGX_ERROR_UNEXPECTED;
    uint32_t result = 0;

    // call DCAP quote verify library to set QvE loading policy
    // Note: this API is not neccessary if the request policy is SGX_QL_DEFAULT
    dcap_ret = sgx_qv_set_enclave_load_policy(SGX_QL_DEFAULT);
    if (dcap_ret == TEE_SUCCESS)
    {
        printf("Info: sgx_qv_set_enclave_load_policy successfully returned.");
    }
    else
    {
        printf("Error: sgx_qv_set_enclave_load_policy failed: 0x%04x", dcap_ret);
        return -1;
    }

    // Load enclave for quote verification
    sgx_ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &g_eid, NULL);
    if (sgx_ret != SGX_SUCCESS) {
        printf("sgx_create_enclave failed: 0x%04x\n", sgx_ret);
        return -1;
    }
    // appraisal
    for (size_t j = 0; j < g_platform_policy.size(); j++) {
        uint8_t n_qaps = 0;
        uint8_t *p_qaps[2] = {NULL, NULL};

        uint8_t *appraisal_result = NULL;

	printf("------------------------------------\n");
	printf("Appraise with policies:\n");
        n_qaps = 0;
        if (get_policy_token((char**)&p_qaps[n_qaps], g_tenant_policy.c_str()) == 0) {
	    printf("\ttenant policy:  %s\n", g_tenant_policy.c_str());
            n_qaps++;
        }
        if(get_policy_token((char**)&p_qaps[n_qaps], g_platform_policy[j].c_str()) == 0) {
	    n_qaps++;
	    printf("\tplatform policy: %s\n", g_platform_policy[j].c_str());
        }
	if(n_qaps <= 0) {
            printf("Error: failed to get policy token\n");
	    break;
	}

        // quote appraisal
        if(0 != quote_appraisal(quote, &appraisal_result, (uint8_t **)p_qaps, n_qaps)) {
            goto CLEANUP;
        }

	// authenticate plicy
        if(0 != authenticate_policy(quote, appraisal_result, (uint8_t **)p_qaps, n_qaps)) {
            goto CLEANUP;
        }

	// authenticate owner
        if(0 != authenticate_owner(quote, appraisal_result)) {
            goto CLEANUP;
        }
        result |= 1 << j;

CLEANUP:
        // free the policy tokens
        for(int i = 0; i < n_qaps; i++) {
            if(p_qaps[i]) free(p_qaps[i]);
        }
	// free the appraisal result token
        if(appraisal_result) {
            dcap_ret = tee_free_appraisal_token(appraisal_result);
            if(dcap_ret !=  SGX_QL_SUCCESS){
                printf("\tError: tee_free_appraisal_token failed: 0x%04x\n", dcap_ret);
            }
            appraisal_result = 0;
        }
    }

    printf("Results:\n");
    for (size_t j = 0; j < g_platform_policy.size(); j++) {
        printf("Appraisal result: %s, tenant policy: %s, platform policy: %s\n", (result & (1<<j)) ? "success":"failure", g_tenant_policy.c_str()+12, g_platform_policy[j].c_str()+12);
    }
    sgx_destroy_enclave(g_eid);
    return 0;
}

void usage()
{
    printf("\nUsage:\n");
    printf("\tPlease specify quote path, e.g. \"./app -quote <path/to/quote>\"\n");
    printf("\tDefault quote path is %s when no command line args\n\n", DEFAULT_QUOTE);
}

// Application entry
int main(int argc, char *argv[])
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
    quote = readBinaryContent(quote_path);
    if (quote.empty()) {
        usage();
        return -1;
    }

    printf("Info: ECDSA quote path: %s\n", quote_path);

    // check quote type and specify the policy files
    if (0 != check_quote_type(quote.data())) {
        usage();
        return -1;
    }

    // Unrusted quote verification
    ecdsa_quote_verification(quote);

    printf("\n");

    return 0;
}
