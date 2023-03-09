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

class SgxError extends Error {
    constructor(message) {
        super(message);
        this.name = this.constructor.name;
    }
}

class TcbOutOfDate extends SgxError {}
class FmspNotFound extends SgxError {}
class DeviceKeyNotFound extends SgxError {}
class PpidNotFound extends SgxError {}
class EventDataNotFound extends SgxError {}
class EnclaveTcbNotFound extends SgxError {}
class EnclaveIdentityNotFound extends SgxError {}
class InvalidPlatformManifest extends SgxError {}
class IncompatiblePackage extends SgxError {}
class PackageNotFound extends SgxError {}
class InvalidOrRevokedPackage extends SgxError {}
class InvalidRegistrationServer extends SgxError {}
class InvalidRequestSyntax extends SgxError {}

class InternalError extends SgxError {
    constructor(message, cause) {
        super(message);
        this.cause = () => cause;
    }
}

class InternalErrorWithNoRetryStatus extends SgxError {
    constructor(body) {
        super(undefined);
        this.body = body;
    }
}

module.exports = {
    InternalError,
    InternalErrorWithNoRetryStatus,
    TcbOutOfDate,
    PpidNotFound,
    DeviceKeyNotFound,
    FmspNotFound,
    EnclaveTcbNotFound,
    EnclaveIdentityNotFound,
    EventDataNotFound,
    InvalidPlatformManifest,
    IncompatiblePackage,
    PackageNotFound,
    InvalidOrRevokedPackage,
    InvalidRegistrationServer,
    InvalidRequestSyntax
};
