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

'use strict';

/**
 * These statuses are taken from file QuoteVerification.h in QVL and should be kept in sync with it
 * @readonly
 * @enum {number}
 */
module.exports = {
    STATUS_OK:                                        0,
    STATUS_UNSUPPORTED_CERT_FORMAT:                   1,
    STATUS_SGX_ROOT_CA_MISSING:                       2,
    STATUS_SGX_ROOT_CA_INVALID:                       3,
    STATUS_SGX_ROOT_CA_INVALID_EXTENSIONS:            4,
    STATUS_SGX_ROOT_CA_INVALID_ISSUER:                5,
    STATUS_SGX_ROOT_CA_UNTRUSTED:                     6,
    STATUS_SGX_INTERMEDIATE_CA_MISSING:               7,
    STATUS_SGX_INTERMEDIATE_CA_INVALID:               8,
    STATUS_SGX_INTERMEDIATE_CA_INVALID_EXTENSIONS:    9,
    STATUS_SGX_INTERMEDIATE_CA_INVALID_ISSUER:        10,
    STATUS_SGX_INTERMEDIATE_CA_REVOKED:               11,
    STATUS_SGX_PCK_MISSING:                           12,
    STATUS_SGX_PCK_INVALID:                           13,
    STATUS_SGX_PCK_INVALID_EXTENSIONS:                14,
    STATUS_SGX_PCK_INVALID_ISSUER:                    15,
    STATUS_SGX_PCK_REVOKED:                           16,
    STATUS_TRUSTED_ROOT_CA_INVALID:                   17,
    STATUS_SGX_PCK_CERT_CHAIN_UNTRUSTED:              18,
    STATUS_SGX_TCB_INFO_UNSUPPORTED_FORMAT:           19,
    STATUS_SGX_TCB_INFO_INVALID:                      20,
    STATUS_TCB_INFO_INVALID_SIGNATURE:                21,
    STATUS_SGX_TCB_SIGNING_CERT_MISSING:              22,
    STATUS_SGX_TCB_SIGNING_CERT_INVALID:              23,
    STATUS_SGX_TCB_SIGNING_CERT_INVALID_EXTENSIONS:   24,
    STATUS_SGX_TCB_SIGNING_CERT_INVALID_ISSUER:       25,
    STATUS_SGX_TCB_SIGNING_CERT_CHAIN_UNTRUSTED:      26,
    STATUS_SGX_TCB_SIGNING_CERT_REVOKED:              27,
    STATUS_SGX_CRL_UNSUPPORTED_FORMAT:                28,
    STATUS_SGX_CRL_UNKNOWN_ISSUER:                    29,
    STATUS_SGX_CRL_INVALID:                           30,
    STATUS_SGX_CRL_INVALID_EXTENSIONS:                31,
    STATUS_SGX_CRL_INVALID_SIGNATURE:                 32,
    STATUS_SGX_CA_CERT_UNSUPPORTED_FORMAT:            33,
    STATUS_SGX_CA_CERT_INVALID:                       34,
    STATUS_TRUSTED_ROOT_CA_UNSUPPORTED_FORMAT:        35,
    STATUS_MISSING_PARAMETERS:                        36,
    STATUS_UNSUPPORTED_QUOTE_FORMAT:                  37,
    STATUS_UNSUPPORTED_PCK_CERT_FORMAT:               38,
    STATUS_INVALID_PCK_CERT:                          39,
    STATUS_UNSUPPORTED_PCK_RL_FORMAT:                 40,
    STATUS_INVALID_PCK_CRL:                           41,
    STATUS_UNSUPPORTED_TCB_INFO_FORMAT:               42,
    STATUS_PCK_REVOKED:                               43,
    STATUS_TCB_INFO_MISMATCH:                         44,
    STATUS_TCB_OUT_OF_DATE:                           45,
    STATUS_TCB_REVOKED:                               46,
    STATUS_TCB_CONFIGURATION_NEEDED:                  47,
    STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED:      48,
    STATUS_TCB_NOT_SUPPORTED:                         49,
    STATUS_TCB_UNRECOGNIZED_STATUS:                   50,
    STATUS_UNSUPPORTED_QE_CERTIFICATION:              51,
    STATUS_INVALID_QE_CERTIFICATION_DATA_SIZE:        52,
    STATUS_UNSUPPORTED_QE_CERTIFICATION_DATA_TYPE:    53,
    STATUS_PCK_CERT_MISMATCH:                         54,
    STATUS_INVALID_QE_REPORT_SIGNATURE:               55,
    STATUS_INVALID_QE_REPORT_DATA:                    56,
    STATUS_INVALID_QUOTE_SIGNATURE:                   57,
    STATUS_SGX_QE_IDENTITY_UNSUPPORTED_FORMAT:        58,
    STATUS_SGX_QE_IDENTITY_INVALID:                   59,
    STATUS_SGX_QE_IDENTITY_INVALID_SIGNATURE:         60,
    STATUS_SGX_ENCLAVE_REPORT_UNSUPPORTED_FORMAT:     61,
    STATUS_SGX_ENCLAVE_IDENTITY_UNSUPPORTED_FORMAT:   62,
    STATUS_SGX_ENCLAVE_IDENTITY_INVALID:              63,
    STATUS_SGX_ENCLAVE_IDENTITY_UNSUPPORTED_VERSION:  64,
    STATUS_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE:          65,
    STATUS_SGX_ENCLAVE_REPORT_MISCSELECT_MISMATCH:    66,
    STATUS_SGX_ENCLAVE_REPORT_ATTRIBUTES_MISMATCH:    67,
    STATUS_SGX_ENCLAVE_REPORT_MRENCLAVE_MISMATCH:     68,
    STATUS_SGX_ENCLAVE_REPORT_MRSIGNER_MISMATCH:      69,
    STATUS_SGX_ENCLAVE_REPORT_ISVPRODID_MISMATCH:     70,
    STATUS_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE:     71,
    STATUS_UNSUPPORTED_QE_IDENTITY_FORMAT:            72,
    STATUS_QE_IDENTITY_OUT_OF_DATE:                   73,
    STATUS_QE_IDENTITY_MISMATCH:                      74,
    STATUS_SGX_TCB_INFO_EXPIRED:                      75,
    STATUS_SGX_ENCLAVE_IDENTITY_INVALID_SIGNATURE:    76,
    STATUS_INVALID_PARAMETER:                         77,
    STATUS_SGX_PCK_CERT_CHAIN_EXPIRED:                78,
    STATUS_SGX_CRL_EXPIRED:                           79,
    STATUS_SGX_SIGNING_CERT_CHAIN_EXPIRED:            80,
    STATUS_SGX_ENCLAVE_IDENTITY_EXPIRED:              81,
    STATUS_TCB_SW_HARDENING_NEEDED:                   82,
    STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED: 83,
    STATUS_SGX_ENCLAVE_REPORT_ISVSVN_REVOKED:         84,
    STATUS_TDX_MODULE_MISMATCH:                       85
};
