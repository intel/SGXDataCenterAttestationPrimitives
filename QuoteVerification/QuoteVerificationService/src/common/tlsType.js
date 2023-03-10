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

const MTLS = 'MTLS';
const TLS = 'TLS';
const None = 'None';

const CIPHERS =
    'TLS_AES_256_GCM_SHA384:' +
    'TLS_AES_128_GCM_SHA256:' +
    'TLS_AES_128_CCM_SHA256: ' +
    'DHE-PSK-AES256-GCM-SHA384:' +
    'ECDHE-ECDSA-CHACHA20-POLY1305:' +
    'ECDHE-ECDSA-AES256-GCM-SHA384:' +
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:' +
    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:' +
    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:' +
    'ECDHE-PSK-CHACHA20-POLY1305:' +
    'DHE-PSK-CHACHA20-POLY1305:' +
    'DHE-DSS-AES256-GCM-SHA384:' +
    'DHE-DSS-AES128-GCM-SHA256:' +
    'DHE-PSK-AES128-GCM-SHA256:' +
    'ECDHE-ECDSA-AES128-GCM-SHA256';
const MIN_SECURE_PROTOCOL = 'TLSv1.2';
const MAX_SECURE_PROTOCOL = 'TLSv1.3';

module.exports = {
    MTLS,
    TLS,
    None,
    CIPHERS,
    MIN_SECURE_PROTOCOL,
    MAX_SECURE_PROTOCOL,
};
