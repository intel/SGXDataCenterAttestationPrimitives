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

/**
 * File: migtd_attest.h
 *
 * Description: API definitions for MigTD Attestation library called by MigTD Core
 *
 */
#ifndef _MIGTD_ATTEST_H_
#define _MIGTD_ATTEST_H_

#include <stdint.h>

#define TDX_REPORT_SIZE 1024
#define HEAP_PAGE_SIZE 0x1000
#define TDX_REPORT_BODY_SIZE 584

#if defined(__cplusplus)
extern "C"
{
#endif

typedef enum _migtd_attest_error_t
{
    MIGTD_ATTEST_SUCCESS = 0x0000,                                         ///< Success
    MIGTD_ATTEST_ERROR_MIN = 0x0001,                      ///< Indicate min error to allow better translation.
    MIGTD_ATTEST_ERROR_UNEXPECTED = 0x0001,               ///< Unexpected error
    MIGTD_ATTEST_ERROR_INVALID_PARAMETER = 0x0002,        ///< The parameter is incorrect
    MIGTD_ATTEST_ERROR_OUT_OF_MEMORY = 0x0003,            ///< Not enough memory is available to complete this operation
    MIGTD_ATTEST_ERROR_ECDSA_ID_MISMATCH = 0x0004,        ///< Expected ECDSA_ID does not match the value stored in the ECDSA Blob
    MIGTD_ATTEST_PATHNAME_BUFFER_OVERFLOW_ERROR = 0x0005, ///< The ECDSA blob pathname is too large
    MIGTD_ATTEST_FILE_ACCESS_ERROR = 0x0006,              ///< Error accessing ECDSA blob
    MIGTD_ATTEST_ERROR_STORED_KEY = 0x0007,               ///< Cached ECDSA key is invalid
    MIGTD_ATTEST_ERROR_PUB_KEY_ID_MISMATCH = 0x0008,      ///< Cached ECDSA key does not match requested key
    MIGTD_ATTEST_ERROR_INVALID_PCE_SIG_SCHEME = 0x0009,   ///< PCE use the incorrect signature scheme
    MIGTD_ATTEST_ATT_KEY_BLOB_ERROR = 0x000a,             ///< There is a problem with the attestation key blob.
    MIGTD_ATTEST_UNSUPPORTED_ATT_KEY_ID = 0x000b,         ///< Unsupported attestation key ID.
    MIGTD_ATTEST_UNSUPPORTED_LOADING_POLICY = 0x000c,     ///< Unsupported enclave loading policy.
    MIGTD_ATTEST_INTERFACE_UNAVAILABLE = 0x000d,          ///< Unable to load the QE enclave
    MIGTD_ATTEST_PLATFORM_LIB_UNAVAILABLE = 0x000e,       ///< Unable to find the platform library with the dependent APIs.  Not fatal.
    MIGTD_ATTEST_ATT_KEY_NOT_INITIALIZED = 0x000f,        ///< The attestation key doesn't exist or has not been certified.
    MIGTD_ATTEST_ATT_KEY_CERT_DATA_INVALID = 0x0010,      ///< The certification data retrieved from the platform library is invalid.
    MIGTD_ATTEST_NO_PLATFORM_CERT_DATA = 0x0011,          ///< The platform library doesn't have any platfrom cert data.
    MIGTD_ATTEST_OUT_OF_EPC = 0x0012,                     ///< Not enough memory in the EPC to load the enclave.
    MIGTD_ATTEST_ERROR_REPORT = 0x0013,                   ///< There was a problem verifying an SGX REPORT.
    MIGTD_ATTEST_ENCLAVE_LOST = 0x0014,                   ///< Interfacing to the enclave failed due to a power transition.
    MIGTD_ATTEST_INVALID_REPORT = 0x0015,                 ///< Error verifying the application enclave's report.
    MIGTD_ATTEST_ENCLAVE_LOAD_ERROR = 0x0016,             ///< Unable to load the enclaves. Could be due to file I/O error, loading infrastructure error, or non-SGX capable system
    MIGTD_ATTEST_UNABLE_TO_GENERATE_QE_REPORT = 0x0017,   ///< The QE was unable to generate its own report targeting the application enclave either
                                                                     ///< because the QE doesn't support this feature there is an enclave compatibility issue.
                                                                     ///< Please call again with the p_qe_report_info to NULL.
    MIGTD_ATTEST_KEY_CERTIFCATION_ERROR = 0x0018,         ///< Caused when the provider library returns an invalid TCB (too high).
    MIGTD_ATTEST_NETWORK_ERROR = 0x0019,                  ///< Network error when retrieving PCK certs
    MIGTD_ATTEST_MESSAGE_ERROR = 0x001a,                  ///< Message error when retrieving PCK certs
    MIGTD_ATTEST_NO_QUOTE_COLLATERAL_DATA = 0x001b,       ///< The platform does not have the quote verification collateral data available.
    MIGTD_ATTEST_QUOTE_CERTIFICATION_DATA_UNSUPPORTED = 0x001c,
    MIGTD_ATTEST_QUOTE_FORMAT_UNSUPPORTED = 0x001d,
    MIGTD_ATTEST_UNABLE_TO_GENERATE_REPORT = 0x001e,
    MIGTD_ATTEST_QE_REPORT_INVALID_SIGNATURE = 0x001f,
    MIGTD_ATTEST_QE_REPORT_UNSUPPORTED_FORMAT = 0x0020,
    MIGTD_ATTEST_PCK_CERT_UNSUPPORTED_FORMAT = 0x0021,
    MIGTD_ATTEST_PCK_CERT_CHAIN_ERROR = 0x0022,
    MIGTD_ATTEST_TCBINFO_UNSUPPORTED_FORMAT = 0x0023,
    MIGTD_ATTEST_TCBINFO_MISMATCH = 0x0024,
    MIGTD_ATTEST_QEIDENTITY_UNSUPPORTED_FORMAT = 0x0025,
    MIGTD_ATTEST_QEIDENTITY_MISMATCH = 0x0026,
    MIGTD_ATTEST_TCB_OUT_OF_DATE = 0x0027,
    MIGTD_ATTEST_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED = 0x0028,      ///< TCB out of date and Configuration needed
    MIGTD_ATTEST_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE = 0x0029,
    MIGTD_ATTEST_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE = 0x002a,
    MIGTD_ATTEST_QE_IDENTITY_OUT_OF_DATE = 0x002b,
    MIGTD_ATTEST_SGX_TCB_INFO_EXPIRED = 0x002c,
    MIGTD_ATTEST_SGX_PCK_CERT_CHAIN_EXPIRED = 0x002d,
    MIGTD_ATTEST_SGX_CRL_EXPIRED = 0x002e,
    MIGTD_ATTEST_SGX_SIGNING_CERT_CHAIN_EXPIRED = 0x002f,
    MIGTD_ATTEST_SGX_ENCLAVE_IDENTITY_EXPIRED = 0x0030,
    MIGTD_ATTEST_PCK_REVOKED = 0x0031,
    MIGTD_ATTEST_TCB_REVOKED = 0x0032,
    MIGTD_ATTEST_TCB_CONFIGURATION_NEEDED = 0x0033,
    MIGTD_ATTEST_UNABLE_TO_GET_COLLATERAL = 0x0034,
    MIGTD_ATTEST_ERROR_INVALID_PRIVILEGE = 0x0035,        ///< No enough privilege to perform the operation
    MIGTD_ATTEST_NO_QVE_IDENTITY_DATA = 0x0037,           ///< The platform does not have the QVE identity data available.
    MIGTD_ATTEST_CRL_UNSUPPORTED_FORMAT = 0x0038,
    MIGTD_ATTEST_QEIDENTITY_CHAIN_ERROR = 0x0039,
    MIGTD_ATTEST_TCBINFO_CHAIN_ERROR = 0x003a,
    MIGTD_ATTEST_ERROR_QVL_QVE_MISMATCH = 0x003b,          ///< QvE returned supplemental data version mismatched between QVL and QvE
    MIGTD_ATTEST_TCB_SW_HARDENING_NEEDED = 0x003c,         ///< TCB up to date but SW Hardening needed
    MIGTD_ATTEST_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED = 0x003d,        ///< TCB up to date but Configuration and SW Hardening needed

    MIGTD_ATTEST_UNSUPPORTED_MODE = 0x003e,

    MIGTD_ATTEST_NO_DEVICE = 0x003f,
    MIGTD_ATTEST_SERVICE_UNAVAILABLE = 0x0040,
    MIGTD_ATTEST_NETWORK_FAILURE = 0x0041,
    MIGTD_ATTEST_SERVICE_TIMEOUT = 0x0042,
    MIGTD_ATTEST_ERROR_BUSY = 0x0043,

    MIGTD_ATTEST_UNKNOWN_MESSAGE_RESPONSE  = 0x0044,      /// Unexpected error from the cache service
    MIGTD_ATTEST_PERSISTENT_STORAGE_ERROR  = 0x0045,      /// Error storing the retrieved cached data in persistent memory
    MIGTD_ATTEST_ERROR_MESSAGE_PARSING_ERROR   = 0x0046,  /// Message parsing error
    MIGTD_ATTEST_PLATFORM_UNKNOWN  = 0x0047,              /// Platform was not found in the cache
    MIGTD_ATTEST_UNKNOWN_API_VERSION  = 0x0048,           /// The current PCS API version configured is unknown
    MIGTD_ATTEST_CERTS_UNAVAILABLE  = 0x0049,             /// Certificates are not available for this platform

    MIGTD_ATTEST_QVEIDENTITY_MISMATCH = 0x0050,          ///< QvE Identity is NOT match to Intel signed QvE identity
    MIGTD_ATTEST_QVE_OUT_OF_DATE = 0x0051,               ///< QvE ISVSVN is smaller than the ISVSVN threshold, or input QvE ISVSVN is too small
    MIGTD_ATTEST_PSW_NOT_AVAILABLE = 0x0052,             ///< SGX PSW library cannot be loaded, could be due to file I/O error
    MIGTD_ATTEST_COLLATERAL_VERSION_NOT_SUPPORTED = 0x0053,  ///< SGX quote verification collateral version not supported by QVL/QvE
    MIGTD_ATTEST_TDX_MODULE_MISMATCH = 0x0060,            ///< TDX SEAM module identity is NOT match to Intel signed TDX SEAM module

    MIGTD_ATTEST_ERROR_QUOTE_FAILURE = 0x0070,            /// Error when MigTD invokes TDVMCALL<Get_Quote>

    MIGTD_ATTEST_ERROR_MAX = 0x00FF,                      ///< Indicate max error to allow better translation.
} migtd_attest_error_t;

/**
 * Get MigTD's Quote by passing tdx_report.
 * Note: all IN/OUT memory should be managed by Caller
 *
 * @param p_tdx_report [in] pointer to the input buffer for tdx_report. Must not be NULL.
 * @param tdx_report_size [in] length of p_tdx_report(in bytes), should be = TDX_REPORT_SIZE.
 * @param p_quote [in, out] pointer to the quote buffer. Must not be NULL.
 * @param p_quote_size [in, out] This function will place the size of the Quote, in
 *                           bytes, in the uint32_t pointed to by the
 *                           p_quote_size parameter. Must not be NULL.
 * @return Status code of the operation, one of:
 *      - MIGTD_ATTEST_SUCCESS: Successfully generate the Quote.
 *      - MIGTD_ATTEST_ERROR_UNEXPECTED: An unexpected internal error occurred.
 *      - MIGTD_ATTEST_ERROR_INVALID_PARAMETER: The parameter is incorrect.
 *      - MIGTD_ATTEST_ERROR_QUOTE_FAILURE: Failure when MigTD invokes TDVMCALL<Get_Quote>.
 *      - MIGTD_ATTEST_OUT_OF_MEMORY: Heap memory allocation error in library.
**/
__attribute__((visibility("default"))) migtd_attest_error_t get_quote(
            const void* p_tdx_report, uint32_t tdx_report_size, void* p_quote,
            uint32_t* p_quote_size);

/**
 * Verify the integrity of MigTD's Quote and return td report of MigTD
 * Note: all IN/OUT memory should be managed by Caller
 * @param p_quote [in] pointer to the input buffer for td_quote
 * @param quote_size [in] length of p_quote(in bytes), should be the real size of MigTD td quote
 * @param root_pub_key [in] pointer to Intel Root Public Key
 * @param root_pub_key_size [in] length of Intel Root Public Key(in bytes)
 * @param p_tdx_report_body [in, out] pointer to the output buffer for sgx_report2_body_t, buffer size should not less than the size of sgx_report2_body_t
 * @param p_tdx_report_body_size [in, out], size of the p_tdx_report_body buffer in bytes. If the API succeeds, the this will be the size of returned p_tdx_report_body in bytes
 *
 * @return Status code of the operation, one of:
 *      - MIGTD_ATTEST_SUCCESS
 *      - MIGTD_ATTEST_ERROR_UNEXPECTED
**/
__attribute__((visibility("default"))) migtd_attest_error_t verify_quote_integrity(
            const void* p_quote, uint32_t quote_size,
            const void* root_pub_key, uint32_t root_pub_key_size,
            void* p_tdx_report_body,
            uint32_t* p_tdx_report_body_size);

/**
 * Initialize heap space for MigTD Attestation library internal use.
 * Must be called only once by MigTD before other attestation lib APIs
 *
 * @param p_td_heap_base [in] the heap base address allocated by MigTD, the address should be aligned(0x1000).
 * @param td_heap_size [in] the capacity of the heap, should be multiples of 0x1000 (in bytes).
 * @return Status code of the operation, one of:
 *      - MIGTD_ATTEST_SUCCESS: Successfully init heap for internal use.
 *      - MIGTD_ATTEST_ERROR_INVALID_PARAMETER: The parameter is incorrect.
**/
__attribute__((visibility("default"))) migtd_attest_error_t init_heap(
            const void* p_td_heap_base, uint32_t td_heap_size);

#if defined(__cplusplus)
}
#endif

#endif
