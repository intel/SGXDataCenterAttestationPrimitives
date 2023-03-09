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

const errors = require('../../src/koa/errors');
const assert = require('assert');

describe('Error test', () => {
    it('Should call TcbOutOfDate error with expected message', () => {
        // GIVEN
        const msg = 'TcbOutOfDate error';
        // WHEN
        const error = new errors.TcbOutOfDate(msg);

        // THEN
        assert.strictEqual(error.name, 'TcbOutOfDate');
        assert.strictEqual(error.message, msg);
    });

    it('Should call PpidNotFound error with expected message', () => {
        // GIVEN
        const msg = 'PpidNotFound error';
        // WHEN
        const error = new errors.PpidNotFound(msg);

        // THEN
        assert.strictEqual(error.name, 'PpidNotFound');
        assert.strictEqual(error.message, msg);
    });

    it('Should call InternalError error with expected message', () => {
        // GIVEN
        const msg = 'InternalError error';
        // WHEN
        const error = new errors.InternalError(msg);

        // THEN
        assert.strictEqual(error.name, 'InternalError');
        assert.strictEqual(error.message, msg);
        assert.strictEqual(typeof error.cause(), 'undefined');
    });

    it('Should call FmspNotFound error with expected message', () => {
        // GIVEN
        const msg = 'FmspNotFound error';
        // WHEN
        const error = new errors.FmspNotFound(msg);

        // THEN
        assert.strictEqual(error.name, 'FmspNotFound');
        assert.strictEqual(error.message, msg);
    });

    it('Should call DeviceKeyNotFound error with expected message', () => {
        // GIVEN
        const msg = 'DeviceKeyNotFound error';
        // WHEN
        const error = new errors.DeviceKeyNotFound(msg);

        // THEN
        assert.strictEqual(error.name, 'DeviceKeyNotFound');
        assert.strictEqual(error.message, msg);
    });

    it('Should call EventDataNotFound error with expected message', () => {
        // GIVEN
        const msg = 'EventDataNotFound error';
        // WHEN
        const error = new errors.EventDataNotFound(msg);

        // THEN
        assert.strictEqual(error.name, 'EventDataNotFound');
        assert.strictEqual(error.message, msg);
    });

    it('Should call EnclaveTcbNotFound error with expected message', () => {
        // GIVEN
        const msg = 'EnclaveTcbNotFound error';
        // WHEN
        const error = new errors.EnclaveTcbNotFound(msg);

        // THEN
        assert.strictEqual(error.name, 'EnclaveTcbNotFound');
        assert.strictEqual(error.message, msg);
    });

    it('Should call EnclaveIdentityNotFound error with expected message', () => {
        // GIVEN
        const msg = 'EnclaveIdentityNotFound error';
        // WHEN
        const error = new errors.EnclaveIdentityNotFound(msg);

        // THEN
        assert.strictEqual(error.name, 'EnclaveIdentityNotFound');
        assert.strictEqual(error.message, msg);
    });

    it('Should call InternalErrorWithNoRetryStatus error with expected message', () => {
        // GIVEN
        const msg = 'InternalErrorWithNoRetryStatus error';
        // WHEN
        const error = new errors.InternalErrorWithNoRetryStatus(msg);

        // THEN
        assert.strictEqual(error.name, 'InternalErrorWithNoRetryStatus');
        assert.strictEqual(error.body, msg);
    });
});
