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

#ifndef _QVE_HEADER_H_
#define _QVE_HEADER_H_

#include "sgx_ql_lib_common.h"
#include <sgx_ql_quote.h>
#include <sgx_key.h>
#include "time.h"
#include "sgx_report.h"
#include "sgx_quote.h"

#ifndef DEBUG_MODE
#define DEBUG_MODE 0
#endif //DEBUG_MODE

#define SUPPLEMENTAL_DATA_VERSION 2
#define QVE_COLLATERAL_VERSION 1
#define FMSPC_SIZE 6
#define CA_SIZE 10
#define SGX_CPUSVN_SIZE   16
//QUOTE_MIN_SIZE = {HEADER_BYTE_LEN (48) + BODY_BYTE_LEN (384) + AUTH_DATA_SIZE_BYTE_LEN (4) + AUTH_DATA_MIN_BYTE_LEN (584)}
//
#define QUOTE_MIN_SIZE 1020
#define QUOTE_CERT_TYPE 5
#define PROCESSOR_ISSUER "Processor"
#define PLATFORM_ISSUER "Platform"
#define PROCESSOR_ISSUER_ID "processor"
#define PLATFORM_ISSUER_ID "platform"
#define TRUSTED_ROOT_CA_CERT "-----BEGIN CERTIFICATE-----\nMIICjjCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNDExMVoXDTMzMDUyMTEwNDExMFowaDEaMBgG\nA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0\naW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT\nAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7\n1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB\nuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ\nMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50\nZWwuY29tL0ludGVsU0dYUm9vdENBLmNybDAdBgNVHQ4EFgQUImUM1lqdNInzg7SV\nUr9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI\nKoZIzj0EAwIDSAAwRQIgQQs/08rycdPauCFk8UPQXCMAlsloBe7NwaQGTcdpa0EC\nIQCUt8SGvxKmjpcM/z0WP9Dvo8h2k5du1iWDdBkAn+0iiA==\n-----END CERTIFICATE-----"

#define UNUSED_PARAM(x) (void)(x)
#define CHECK_MANDATORY_PARAMS(param, param_size) (param == NULL || param_size == 0)
#define CHECK_OPT_PARAMS(param, param_size) ((param == NULL && param_size != 0) || (param != NULL && param_size == 0))

#define NULL_POINTER(x) x==NULL
#define NULL_BREAK(x) if (x == NULL) {break;}
#define BREAK_ERR(x) {if (x != STATUS_OK) break;}
#define SGX_ERR_BREAK(x) {if (x != SGX_SUCCESS) break;}
#ifndef CLEAR_FREE_MEM
#include <string.h>
#define CLEAR_FREE_MEM(address, size) {             \
    if (address != NULL) {                          \
        if (size > 0) {                             \
            (void)memset_s(address, size, 0, size); \
        }                                           \
        free(address);                              \
     }                                              \
}
#endif //CLEAR_FREE_MEM

#define EXPECTED_CERTIFICATE_COUNT_IN_PCK_CHAIN 3
#ifndef SGX_QL_QV_MK_ERROR
#define SGX_QL_QV_MK_ERROR(x)              (0x0000A000|(x))
#endif //SGX_QL_QV_MK_ERROR
/** Contains the possible values of the quote verification result. */
typedef enum _sgx_ql_qv_result_t
{
   SGX_QL_QV_RESULT_OK = 0x0000,                                            ///< The Quote verification passed and is at the latest TCB level
   SGX_QL_QV_RESULT_MIN = SGX_QL_QV_MK_ERROR(0x0001),
   SGX_QL_QV_RESULT_CONFIG_NEEDED = SGX_QL_QV_MK_ERROR(0x0001),             ///< The Quote verification passed and the platform is patched to
                                                                            ///< the latest TCB level but additional configuration of the SGX
                                                                            ///< platform may be needed
   SGX_QL_QV_RESULT_OUT_OF_DATE = SGX_QL_QV_MK_ERROR(0x0002),               ///< The Quote is good but TCB level of the platform is out of date.
                                                                            ///< The platform needs patching to be at the latest TCB level
   SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED = SGX_QL_QV_MK_ERROR(0x0003), ///< The Quote is good but the TCB level of the platform is out of
                                                                            ///< date and additional configuration of the SGX Platform at its
                                                                            ///< current patching level may be needed. The platform needs
                                                                            ///< patching to be at the latest TCB level
   SGX_QL_QV_RESULT_INVALID_SIGNATURE = SGX_QL_QV_MK_ERROR(0x0004),         ///< The signature over the application report is invalid
   SGX_QL_QV_RESULT_REVOKED = SGX_QL_QV_MK_ERROR(0x0005),                   ///< The attestation key or platform has been revoked
   SGX_QL_QV_RESULT_UNSPECIFIED = SGX_QL_QV_MK_ERROR(0x0006),               ///< The Quote verification failed due to an error in one of the input
   SGX_QL_QV_RESULT_SW_HARDENING_NEEDED = SGX_QL_QV_MK_ERROR(0x0007),       ///< The TCB level of the platform is up to date, but SGX SW Hardening
                                                                            ///< is needed
   SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED = SGX_QL_QV_MK_ERROR(0x0008),   ///< The TCB level of the platform is up to date, but additional
                                                                                   ///< configuration of the platform at its current patching level
                                                                                   ///< may be needed. Moreove, SGX SW Hardening is also needed

   SGX_QL_QV_RESULT_MAX = SGX_QL_QV_MK_ERROR(0x00FF),                              ///< Indicate max result to allow better translation

} sgx_ql_qv_result_t;


/** Contains data that will allow an alternative quote verification policy. */
typedef struct _sgx_ql_qv_supplemental_t
{
    uint32_t version;                     ///< Supplemental data version
    time_t earliest_issue_date;           ///< Earliest issue date of all the collateral (UTC)
    time_t latest_issue_date;             ///< Latest issue date of all the collateral (UTC)
    time_t earliest_expiration_date;      ///< Earliest expiration date of all the collateral (UTC)
    time_t tcb_level_date_tag;            ///< The SGX TCB of the platform that generated the quote is not vulnerable
                                          ///< to any Security Advisory with an SGX TCB impact released on or before this date.
                                          ///< See Intel Security Center Advisories
    uint32_t pck_crl_num;                 ///< CRL Num from PCK Cert CRL
    uint32_t root_ca_crl_num;             ///< CRL Num from Root CA CRL
    uint32_t tcb_eval_ref_num;            ///< Lower number of the TCBInfo and QEIdentity
    uint8_t root_key_id[48];              ///< ID of the collateral's root signer (hash of Root CA's public key SHA-384)
    sgx_key_128bit_t pck_ppid;            ///< PPID from remote platform.  Can be used for platform ownership checks
    sgx_cpu_svn_t tcb_cpusvn;             ///< CPUSVN of the remote platform's PCK Cert
    sgx_isv_svn_t tcb_pce_isvsvn;         ///< PCE_ISVNSVN of the remote platform's PCK Cert
    uint16_t pce_id;                      ///< PCE_ID of the remote platform
} sgx_ql_qv_supplemental_t;


#endif //_QVE_HEADER_H_
