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
 * File: sgx_quote3_defs.h
 *
 * Description: Quote structures
 */

#ifndef _SGX_QUOTE3_DEFS_H_
#define _SGX_QUOTE3_DEFS_H_

#include "sgx_report.h"
#include "sgx_pce.h"

typedef enum {
    PPID_CLEARTEXT = 1, ///< Clear PPID + CPU_SVN, PvE_SVN, PCE_SVN, PCE_ID
    PPID_RSA2048_ENCRYPTED = 2, ///< RSA-2048-OAEP Encrypted PPID + CPU_SVN, PvE_SVN, PCE_SVN, PCE_ID
    PPID_RSA3072_ENCRYPTED = 3, ///< RSA-3072-OAEP Encrypted PPID + CPU_SVN, PvE_SVN, PCE_SVN, PCE_ID
    PCK_CLEARTEXT = 4, ///< Clear PCK Leaf Cert
    PCK_CERT_CHAIN = 5, ///< Full PCK Cert chain (trustedRootCaCert||intermediateCa||pckCert)
    ECDSA_SIG_AUX_DATA = 6, ///< Indicates the contents of the CERTIFICATION_INFO_DATA contains the ECDSA_SIG_AUX_DATA of another Quote.
} sgx_ql_cert_key_type_t;

/**
 * In order to "overlay" a struct pointer on a buffer of packed data and
 * expect it to work, we need to force the compiler to use packed structs.
 */

struct _sgx_ql_ecdsa_sig_data_t {
    uint8_t             sig[64];                    /* 0 */
    uint8_t             att_public_key[64];         /* 64 */
    sgx_report_body_t   qe3_report;                 /* 128 */
    uint8_t             qe3_report_sig[64];         /* 512 */
    uint8_t             auth_certification_data[];  /* 576 */
    /*
     * auth_certification_data contains two, variable-length structures,
     * defined in order:
     *
     *   sgx_ql_auth_data_t
     *   sgx_ql_certification_data_t
     *
     */
};
typedef struct _sgx_ql_ecdsa_sig_data_t sgx_ql_ecdsa_sig_data_t;

/* QE Authentication Data */
struct _sgx_ql_auth_data_struct {
#pragma pack(push,2)    // Necessary to let us "overlay" the struct
                        // pointer on a buffer of packed data.
    uint16_t    size;            /* 0 */
#pragma pack(pop)
    uint8_t      auth_data[];    /* 2 */
};
typedef struct _sgx_ql_auth_data_struct sgx_ql_auth_data_t;

/* QE Certification Data */
struct _sgx_ql_certification_data_struct {
#pragma pack(push,2)    // Necessary to let us "overlay" the struct
                        // pointer on a buffer of packed data.
    uint16_t    cert_key_type;              /* 0 */
    uint32_t    size;                       /* 2 */
#pragma pack(pop)
    uint8_t        certification_data[];    /* 6 */
};
typedef struct _sgx_ql_certification_data_struct sgx_ql_certification_data_t;

struct _sgx_quote3_header_struct {
#pragma pack(push,2)
    uint16_t        version;            /* 0 */
    uint16_t        att_key_type;       /* 2 */
    uint8_t         att_key_data_0[4];  /* 4 */
    sgx_isv_svn_t   qe_svn;             /* 8 */
    sgx_isv_svn_t   pce_svn;            /* 10 */
    uint8_t         vendor_id[16];      /* 12 */
    uint8_t         user_data[20];      /* 28 */
};
typedef struct _sgx_quote3_header_struct sgx_quote3_header_t;

struct _sgx_quote3_struct {
    sgx_quote3_header_t header;             /* 0 */
    sgx_report_body_t   report_body;        /* 48 */
    uint32_t            signature_data_len; /* 432 */
    uint8_t             signature_data[];   /* 436 */
};
typedef struct _sgx_quote3_struct sgx_quote3_t;

#pragma pack(pop)

#endif

