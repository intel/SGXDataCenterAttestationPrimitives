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

#include "X509CertTypes.h"

namespace intel { namespace sgx { namespace dcap { namespace crypto {
    ASN1_SEQUENCE(SGX_INT) = {
            ASN1_SIMPLE(SGX_INT, oid, ASN1_OBJECT),
            ASN1_SIMPLE(SGX_INT, value, ASN1_INTEGER)
    } ASN1_SEQUENCE_END(SGX_INT)

    ASN1_SEQUENCE(SGX_ENUM) = {
            ASN1_SIMPLE(SGX_ENUM, oid, ASN1_OBJECT),
            ASN1_SIMPLE(SGX_ENUM, value, ASN1_ENUMERATED)
    } ASN1_SEQUENCE_END(SGX_ENUM)

    ASN1_SEQUENCE(SGX_BOOL) = {
            ASN1_SIMPLE(SGX_BOOL, oid, ASN1_OBJECT),
            ASN1_SIMPLE(SGX_BOOL, value, ASN1_BOOLEAN)
    } ASN1_SEQUENCE_END(SGX_BOOL)

    ASN1_SEQUENCE(SGX_OCTET_STRING) = {
            ASN1_SIMPLE(SGX_OCTET_STRING, oid, ASN1_OBJECT),
            ASN1_SIMPLE(SGX_OCTET_STRING, value, ASN1_OCTET_STRING)
    } ASN1_SEQUENCE_END(SGX_OCTET_STRING)

    ASN1_SEQUENCE(SGX_TCB) = {
            ASN1_SIMPLE(SGX_TCB, comp01, SGX_INT),
            ASN1_SIMPLE(SGX_TCB, comp02, SGX_INT),
            ASN1_SIMPLE(SGX_TCB, comp03, SGX_INT),
            ASN1_SIMPLE(SGX_TCB, comp04, SGX_INT),
            ASN1_SIMPLE(SGX_TCB, comp05, SGX_INT),
            ASN1_SIMPLE(SGX_TCB, comp06, SGX_INT),
            ASN1_SIMPLE(SGX_TCB, comp07, SGX_INT),
            ASN1_SIMPLE(SGX_TCB, comp08, SGX_INT),
            ASN1_SIMPLE(SGX_TCB, comp09, SGX_INT),
            ASN1_SIMPLE(SGX_TCB, comp10, SGX_INT),
            ASN1_SIMPLE(SGX_TCB, comp11, SGX_INT),
            ASN1_SIMPLE(SGX_TCB, comp12, SGX_INT),
            ASN1_SIMPLE(SGX_TCB, comp13, SGX_INT),
            ASN1_SIMPLE(SGX_TCB, comp14, SGX_INT),
            ASN1_SIMPLE(SGX_TCB, comp15, SGX_INT),
            ASN1_SIMPLE(SGX_TCB, comp16, SGX_INT),
            ASN1_SIMPLE(SGX_TCB, pcesvn, SGX_INT),
            ASN1_SIMPLE(SGX_TCB, cpusvn, SGX_OCTET_STRING)
    } ASN1_SEQUENCE_END(SGX_TCB)

    ASN1_SEQUENCE(SGX_TCB_SEQ) = {
            ASN1_SIMPLE(SGX_TCB_SEQ, oid, ASN1_OBJECT),
            ASN1_SIMPLE(SGX_TCB_SEQ, tcb, SGX_TCB)
    } ASN1_SEQUENCE_END(SGX_TCB_SEQ)

    ASN1_SEQUENCE(SGX_CONFIGURATION) = {
        ASN1_OPT(SGX_CONFIGURATION, dynamicPlatform, SGX_BOOL),
        ASN1_OPT(SGX_CONFIGURATION, cachedKeys, SGX_BOOL),
        ASN1_OPT(SGX_CONFIGURATION, smtEnabled, SGX_BOOL)
    } ASN1_SEQUENCE_END(SGX_CONFIGURATION)

    ASN1_SEQUENCE(SGX_CONFIGURATION_SEQ) = {
            ASN1_SIMPLE(SGX_CONFIGURATION_SEQ, oid, ASN1_OBJECT),
            ASN1_SIMPLE(SGX_CONFIGURATION_SEQ, configuration, SGX_CONFIGURATION)
    } ASN1_SEQUENCE_END(SGX_CONFIGURATION_SEQ)

    ASN1_SEQUENCE(SGX_EXTENSIONS) = {
            ASN1_SIMPLE(SGX_EXTENSIONS, ppid, SGX_OCTET_STRING),
            ASN1_SIMPLE(SGX_EXTENSIONS, tcb, SGX_TCB_SEQ),
            ASN1_SIMPLE(SGX_EXTENSIONS, pceid, SGX_OCTET_STRING),
            ASN1_SIMPLE(SGX_EXTENSIONS, fmspc, SGX_OCTET_STRING),
            ASN1_SIMPLE(SGX_EXTENSIONS, sgxType, SGX_ENUM),
            ASN1_OPT(SGX_EXTENSIONS, platformInstanceId, SGX_OCTET_STRING),
            ASN1_OPT(SGX_EXTENSIONS, configuration, SGX_CONFIGURATION_SEQ),
            ASN1_OPT(SGX_EXTENSIONS, unexpectedExtension, SGX_BOOL)
    } ASN1_SEQUENCE_END(SGX_EXTENSIONS)

    IMPLEMENT_ASN1_FUNCTIONS(SGX_INT)
    IMPLEMENT_ASN1_FUNCTIONS(SGX_OCTET_STRING)
    IMPLEMENT_ASN1_FUNCTIONS(SGX_ENUM)
    IMPLEMENT_ASN1_FUNCTIONS(SGX_BOOL)
    IMPLEMENT_ASN1_FUNCTIONS(SGX_TCB)
    IMPLEMENT_ASN1_FUNCTIONS(SGX_TCB_SEQ)
    IMPLEMENT_ASN1_FUNCTIONS(SGX_CONFIGURATION)
    IMPLEMENT_ASN1_FUNCTIONS(SGX_CONFIGURATION_SEQ)
    IMPLEMENT_ASN1_FUNCTIONS(SGX_EXTENSIONS)
}}}}
