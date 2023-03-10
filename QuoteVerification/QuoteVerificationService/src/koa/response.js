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

const InternalError = require('./errors').InternalError;

const STATUSES = {
    STATUS_OK:                            { httpCode: 200, name: 'STATUS_OK' },
    STATUS_CREATED:                       { httpCode: 201, name: 'STATUS_CREATED' },
    STATUS_CERT_NOT_FOUND:                { httpCode: 404, name: 'STATUS_CERTS_NOT_FOUND' },
    STATUS_PCK_NOT_FOUND:                 { httpCode: 404, name: 'STATUS_PCK_NOT_FOUND' },
    STATUS_PCK_REVOKED:                   { httpCode: 403, name: 'STATUS_PCK_REVOKED' },
    STATUS_TCB_OUT_OF_DATE:               { httpCode: 400, name: 'STATUS_TCB_OUT_OF_DATE' },
    STATUS_TCB_NOT_FOUND:                 { httpCode: 404, name: 'STATUS_TCB_NOT_FOUND' },
    STATUS_TCB_NOT_SUPPORTED:             { httpCode: 400, name: 'STATUS_TCB_NOT_SUPPORTED' },
    STATUS_DEVICE_KEY_NOT_FOUND:          { httpCode: 404, name: 'STATUS_DEVICE_KEY_NOT_FOUND' },
    STATUS_INTERNAL_ERROR:                { httpCode: 500, name: 'STATUS_INTERNAL_ERROR' },
    STATUS_GENERIC_ERROR:                 { httpCode: 500, name: 'STATUS_INTERNAL_ERROR' },
    STATUS_BAD_REQUEST:                   { httpCode: 400, name: 'STATUS_BAD_REQUEST' },
    STATUS_INVALID_CONTENT:               { httpCode: 400, name: 'STATUS_INVALID_CONTENT' },
    STATUS_INVALID_PLATFORM_MANIFEST:     { httpCode: 400, name: 'STATUS_INVALID_PLATFORM_MANIFEST' },
    STATUS_INVALID_REQUEST_SYNTAX:        { httpCode: 400, name: 'STATUS_INVALID_REQUEST_SYNTAX' },
    STATUS_INCOMPATIBLE_PACKAGE:          { httpCode: 400, name: 'STATUS_INCOMPATIBLE_PACKAGE' },
    STATUS_PACKAGE_NOT_FOUND:             { httpCode: 400, name: 'STATUS_PACKAGE_NOT_FOUND' },
    STATUS_INVALID_OR_REVOKED_PACKAGE:    { httpCode: 400, name: 'STATUS_INVALID_OR_REVOKED_PACKAGE' },
    STATUS_INVALID_REGISTRATION_SERVER:   { httpCode: 400, name: 'STATUS_INVALID_REGISTRATION_SERVER' },
    STATUS_NOT_FOUND:                     { httpCode: 404, name: 'STATUS_NOT_FOUND' },
    STATUS_PLATFORM_NOT_FOUND:            { httpCode: 404, name: 'STATUS_PLATFORM_NOT_FOUND' },
    STATUS_PLATFORM_KEYS_NOT_FOUND:       { httpCode: 404, name: 'STATUS_PLATFORM_KEYS_NOT_FOUND' },
    STATUS_DECRYPTION_FAILED:             { httpCode: 400, name: 'STATUS_DECRYPTION_FAILED' },
    STATUS_ENCLAVE_IDENTITY_NOT_FOUND:    { httpCode: 404, name: 'STATUS_ENCLAVE_IDENTITY_NOT_FOUND' },
    STATUS_NO_GROUPS_REMAINING:           { httpCode: 500, name: 'STATUS_NO_GROUPS_REMAINING' },
    STATUS_NO_ASSIGNMENT:                 { httpCode: 404, name: 'STATUS_NO_ASSIGNMENT' },
    STATUS_PAK_NOT_FOUND:                 { httpCode: 404, name: 'STATUS_PAK_NOT_FOUND' },
    STATUS_PAK_REVOKED:                   { httpCode: 403, name: 'STATUS_PAK_REVOKED' },
    STATUS_EPID_JOIN_DATA_ALREADY_EXISTS: { httpCode: 403, name: 'STATUS_EPID_JOIN_DATA_ALREADY_EXISTS' },
    STATUS_UNWRAPPING_FAILED:             { httpCode: 400, name: 'STATUS_UNWRAPPING_FAILED' },
    STATUS_GONE:                          { httpCode: 410, name: 'STATUS_GONE' },
    STATUS_PAYLOAD_TOO_LARGE:             { httpCode: 413, name: 'STATUS_PAYLOAD_TOO_LARGE' },
    STATUS_UNSUPPORTED_MEDIA_TYPE:        { httpCode: 415, name: 'STATUS_UNSUPPORTED_MEDIA_TYPE' },
    STATUS_SERVICE_UNAVAILABLE:           { httpCode: 503, name: 'STATUS_SERVICE_UNAVAILABLE' },
    STATUS_MAC_VERIFICATION_FAILED:       { httpCode: 500, name: 'STATUS_MAC_VERIFICATION_FAILED' },
    STATUS_MIN_SUPPORTED_RL_VERSION:      { httpCode: 500, name: 'STATUS_MIN_SUPPORTED_RL_VERSION' }
};

class GenericResponse {
    constructor(status, log) {
        if (!status.httpCode || !status.name) {
            log.error(`Cannot construct response because 'status' object is invalid: ${JSON.stringify(status)}.`);
            throw new InternalError();
        }
        this.httpCode = status.httpCode;
        this.jsonBody = { status: status.name };
    }
}

class InternalErrorResponse extends GenericResponse {
    constructor(log) {
        super(STATUSES.STATUS_INTERNAL_ERROR, log);
    }
}

class BadRequestResponse extends GenericResponse {
    constructor(log) {
        super(STATUSES.STATUS_BAD_REQUEST, log);
    }
}

/**
 * @typedef Response
 * @type jsonBody
 * @property {number} httpCode
 */

/**
 * Sets response body and status
 * @param response
 * @param ctx
 */
function setResponse(response, ctx) {
    ctx.body = response.jsonBody;
    ctx.status = response.httpCode;
}

module.exports = {
    STATUSES,
    setResponse,
    GenericResponse,
    InternalErrorResponse,
    BadRequestResponse
};
