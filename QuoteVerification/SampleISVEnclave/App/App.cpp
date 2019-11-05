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
#include <sgx_uae_service.h>
#include "sgx_urts.h"
#include "Enclave_u.h"
#include "qve_header.h"
#include "sgx_dcap_quoteverify.h"
#include "collateral_files.h"
#ifndef _MSC_VER
#define SAMPLE_ISV_ENCLAVE "enclave.signed.so"
#else
#define SAMPLE_ISV_ENCLAVE "enclave.signed.dll"
#endif
using namespace std;

vector<uint8_t> readBinaryContent(const string& filePath);
vector<uint8_t> readBinaryContent(const string& filePath)
{
    ifstream file(filePath, ios::binary);
    if (!file.is_open())
    {
        printf("Error: Unable to open %s file\n", filePath.c_str());
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

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    vector<uint8_t> quote;
    int ret = -1;
    time_t current_time = 0;
    uint32_t supplemental_data_size = 0;
    uint8_t *p_supplemental_data = NULL;
    quote3_error_t qve_ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_ql_qv_result_t p_quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    sgx_ql_qe_report_info_t p_qve_report_info;
    unsigned char rand_nonce[16] = "59jslk201fgjmm;";
    uint32_t p_collateral_expiration_status = 1;
    int updated = 0;
    sgx_status_t verify_report_ret = SGX_ERROR_UNEXPECTED;
    sgx_enclave_id_t eid;
    sgx_launch_token_t token = { 0 };

    //set nonce
    //
    memcpy(p_qve_report_info.nonce.rand, rand_nonce, sizeof(rand_nonce));

    //get target info of SampleISVEnclave. QvE will target the generated report to this enclave.
    //
    ret = sgx_create_enclave(SAMPLE_ISV_ENCLAVE, 1, &token, &updated, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Error: Can't create SampleISVEnclave. 0x%04x\n", ret);
        return -1;
    }
    sgx_status_t get_target_info_ret;
    sgx_status_t sgx_ret = ecall_get_target_info(eid, &get_target_info_ret, &p_qve_report_info.app_enclave_target_info);
    if (sgx_ret != SGX_SUCCESS || get_target_info_ret != SGX_SUCCESS) {
        printf("Error in sgx_get_target_info. 0x%04x\n", qve_ret);
    }
    else {
        printf("Info: get target info successfully returned.\n");
    }

    //call DCAP quote verify library to set QvE loading policy
    //
    qve_ret = sgx_qv_set_enclave_load_policy(SGX_QL_DEFAULT);
    if (qve_ret == SGX_QL_SUCCESS) {
        printf("Info: sgx_qv_set_enclave_load_policy successfully returned.\n");
    }
    else {
        printf("Error: sgx_qv_set_enclave_load_policy failed: 0x%04x\n", qve_ret);
    }


    //call DCAP quote verify library to get supplemental data size
    //
    qve_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
    if (qve_ret == SGX_QL_SUCCESS && supplemental_data_size == sizeof(sgx_ql_qv_supplemental_t)) {
        printf("Info: sgx_qv_get_quote_supplemental_data_size successfully returned.\n");
        p_supplemental_data = (uint8_t*)malloc(supplemental_data_size);
    }
    else {
        printf("Error: sgx_qv_get_quote_supplemental_data_size failed: 0x%04x\n", qve_ret);
        supplemental_data_size = 0;
    }

    //read quote from file
    //
    quote = readBinaryContent(QUOTE);
    if (quote.empty()) {
        printf("Error: Quote not available.\n");
        sgx_destroy_enclave(eid);
        return -1;
    }

    //set current time. This is only for sample purposes, in production mode a trusted time should be used.
    //
    current_time = time(NULL);

    //call DCAP quote verify library for quote verification
    //
    qve_ret = sgx_qv_verify_quote(
        quote.data(), quote.size(),
        NULL,
        current_time,
        &p_collateral_expiration_status,
        &p_quote_verification_result,
        &p_qve_report_info,
        supplemental_data_size,
        p_supplemental_data);
    if (qve_ret == SGX_QL_SUCCESS) {
        printf("Info: App: sgx_qv_verify_quote successfully returned.\n");
    }
    else {
        printf("Error: App: sgx_qv_verify_quote failed: 0x%04x\n", qve_ret);
    }

    //call SampleISVEnclave to verify QvE's report
    //
    sgx_ret = ecall_verify_report(eid, &verify_report_ret, 
        &p_qve_report_info,
        quote.data(),
        quote.size(),
        current_time,
        p_collateral_expiration_status,
        p_quote_verification_result,
        p_supplemental_data,
        supplemental_data_size);

    if (sgx_ret != SGX_SUCCESS || verify_report_ret != SGX_SUCCESS) {
        printf("Error: failed to verify QvE report. 0x%04x\n", verify_report_ret);
    }
    else {
        printf("Info: ecall_verify_report successfully returned.\n");
    }

    //check verification result
    //
    switch (p_quote_verification_result)
    {
    case SGX_QL_QV_RESULT_OK:
        printf("Info: App: Verification completed successfully.\n");
        ret = 0;
        break;
    case SGX_QL_QV_RESULT_CONFIG_NEEDED:
    case SGX_QL_QV_RESULT_OUT_OF_DATE:
    case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        printf("Warning: App: Verification completed with Non-terminal result: %x\n", p_quote_verification_result);
        ret = 1;
        break;
    case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
    case SGX_QL_QV_RESULT_REVOKED:
    case SGX_QL_QV_RESULT_UNSPECIFIED:
    default:
        printf("Error: App: Verification completed with Terminal result: %x\n", p_quote_verification_result);
        ret = -1;
        break;
    }

    sgx_destroy_enclave(eid);
    printf("Enter a character before exit ...\n");
    getchar();
    return ret;
}
