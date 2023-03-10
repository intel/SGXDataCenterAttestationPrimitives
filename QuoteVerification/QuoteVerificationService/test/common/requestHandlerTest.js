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

const proxyquire = require('proxyquire');
const assert = require('assert');
const sinon = require('sinon');
const _ = require('lodash');

const clientErrors =  require('./../../src/common/restClientErrors');

const logger = {
    error() {},
    info() {},
    trace() {},
    warn() {},
    isTraceEnabled: sinon.stub().returns(true)
};

class TestCaseSetup {
    constructor() {
        this.resetDefaults();
    }

    resetDefaults() {

        this.default = {
            protocol:                   'https',
            method:                     'GET',
            path:                       '/path',
            bodySent:                   { test: 'field' },
            headersSent:                { 'content-length': 'testLength', 'testField': 'testLValue' },
            queryParamsSent:            { q: 'value' },
            destroyedJson:              '{wrongJson',
            bodyReceived:               { testField: 'exampleValue' },
            headersSentWithContentType: { 'content-type': 'application/x-pem-file', 'content-length': 'testLength', 'testField': 'testLValue' },
            headersSentJson:            { 'content-type': 'application/json', 'content-length': 'testLength', 'testField': 'testLValue' },
            xPemFile:                   'some_pck_crl'
        };

        const options = {
            ca:                 [],
            secureProtocol:     'TLSv1_2_method',
            ciphers:            'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256',
            requestCert:        true,
            rejectUnauthorized: true,
            agent:              false,
            strictSSL:          false,
            checkForDnsChanges: () => {}
        };

        this.config = {
            protocol:      'https',
            host:          'localhost',
            port:          8081,
            retryCount:    0,
            retryDelay:    0,
            retryMaxDelay: 0,
            options
        };
    }

    setupTestDoubles(err, statusCode, body, headers) {
        const response = {
            statusCode,
            body,
            headers
        };

        const requestStub = sinon.stub();
        const handlerStubs = {
            './nodeRequestHandler': (options) => {

                requestStub(options);
                if (err) {
                    return new Promise((resolve, reject) => reject(err));
                }
                else {
                    return new Promise((resolve) => resolve(response));
                }
            }
        };

        const RequestHandler =  proxyquire('./../../src/common/requestHandler', handlerStubs);
        this.requestHandler = new RequestHandler(_.clone(this.config));
        this.requestSpy = requestStub;
    }

    get retryCount() {
        return this.requestHandler.config.retryCount;
    }

    set retryCount(value) {
        this.requestHandler.config.retryCount = value;
    }

    get expectedOptions() {
        const options = _.clone(this.config.options);
        options.protocol = this.default.protocol + ':';
        options.method = this.default.method;
        options.headers = this.default.headersSent;
        delete options.headers['content-length'];
        options.host = this.config.host;
        options.port = this.config.port;
        options.path = this.default.path + '?q=value';
        return options;
    }
}

class PerformRequestScenarios {

    static callPerformRequest(currentSetup) {

        return currentSetup.requestHandler.sendRequestWithRetries(
            logger,
            currentSetup.default.method,
            currentSetup.default.path,
            currentSetup.default.bodySent,
            currentSetup.default.headersSent,
            currentSetup.default.queryParamsSent
        );
    }
}

describe('requestHandlerTests', () => {
    let currentSetup = null;

    beforeEach(() => {
        currentSetup = new TestCaseSetup();
    });

    describe('removeHeaderContentLength', () => {

        it('should change null header to empty object', (done) => {
            // GIVEN
            currentSetup.setupTestDoubles(null, 200, currentSetup.default.bodyReceived);
            // WHEN / THEN
            assert.deepEqual(currentSetup.requestHandler.removeHeaderContentLength(null), done());
        });
    });

    describe('sendRequest', () => {

        it('should call then callback with expected parameters', async() => {
            // GIVEN
            currentSetup.setupTestDoubles(null, 200, currentSetup.default.bodyReceived, currentSetup.default.headersSentJson);
            // WHEN
            const result = await currentSetup.requestHandler.sendRequest(
                logger,
                currentSetup.default.method,
                currentSetup.default.path,
                currentSetup.default.bodySent,
                currentSetup.default.headersSent);
            //THEN
            assert.deepEqual(result.body, currentSetup.default.bodyReceived);
            assert.deepEqual(result, {
                body:    currentSetup.default.bodyReceived,
                status:  200,
                headers: currentSetup.default.headersSentJson
            });
        });

        it('should not retry if error or error status detected', async() => {
            // GIVEN
            const errMsg = 'errorMessage';
            currentSetup.setupTestDoubles(new Error(errMsg), 'statusExample', currentSetup.default.bodyReceived);
            currentSetup.retryCount = 2;
            try {
                //WHEN
                await currentSetup.requestHandler.sendRequest(
                    logger,
                    currentSetup.default.method,
                    currentSetup.default.path,
                    currentSetup.default.bodySent,
                    currentSetup.default.headersSent);
                assert.fail('Should throw error');
            }
            catch (err) {
                //THEN
                assert.equal(currentSetup.requestSpy.callCount, 1);
                assert.strictEqual(err.message, errMsg);
            }
        });

        it('should call request module with expected parameters', async() => {
            // GIVEN
            currentSetup.setupTestDoubles(null, 200, currentSetup.default.bodyReceived);
            currentSetup.retryCount = 2;
            // WHEN
            await currentSetup.requestHandler
                .sendRequest(
                    logger,
                    currentSetup.default.method,
                    currentSetup.default.path,
                    currentSetup.default.bodySent,
                    currentSetup.default.headersSent,
                    currentSetup.default.queryParamsSent
                );
            //THEN
            assert(currentSetup.requestSpy.calledWithExactly(currentSetup.expectedOptions));
        });

        it('should throw HttpError when status received is not successful', async() => {
            // GIVEN
            currentSetup.setupTestDoubles(null, 220, currentSetup.default.bodyReceived);
            try {
                //WHEN
                await currentSetup.requestHandler.sendRequest(
                    logger,
                    currentSetup.default.method,
                    currentSetup.default.path,
                    currentSetup.default.bodySent,
                    currentSetup.default.headersSent);
                assert.fail('Should throw error');
            }
            catch (err) {
                //THEN
                assert.equal(err instanceof clientErrors.HttpError, true);
                assert.deepEqual(err.status, 220);
                assert.deepEqual(err.body, currentSetup.default.bodyReceived);
            }
        });

    });

    describe('performRequest', () => {
        it('should resolve with expected status and body when status success', async() => {
            // GIVEN
            currentSetup.setupTestDoubles(null, 200, currentSetup.default.bodyReceived);
            // WHEN /THEN
            const result = await PerformRequestScenarios.callPerformRequest(currentSetup);
            assert(currentSetup.requestSpy.calledOnce);
            assert(currentSetup.requestSpy.calledWithExactly(currentSetup.expectedOptions));
            assert.equal(result.status, 200);
            assert.deepEqual(result.body, currentSetup.default.bodyReceived);
        });

        it('should resolve with expected status and body when status created', async() => {
            // GIVEN
            currentSetup.setupTestDoubles(null, 201, currentSetup.default.bodyReceived);
            // WHEN / THEN
            const result = await PerformRequestScenarios.callPerformRequest(currentSetup);
            assert(currentSetup.requestSpy.calledOnce);
            assert(currentSetup.requestSpy.calledWithExactly(currentSetup.expectedOptions));
            assert.equal(result.status, 201);
            assert.deepEqual(result.body, currentSetup.default.bodyReceived);
        });

        it('should log warning on retry', async() => {
            // GIVEN
            const loggerStub = {
                error() {},
                info() {},
                trace() {},
                warn: sinon.stub()
            };
            loggerStub.warn.callsFake(() => {});

            const errMsg = 'request rejected';
            currentSetup.setupTestDoubles(new Error(errMsg));
            currentSetup.retryCount = 1;
            try {
                //WHEN
                await currentSetup.requestHandler.sendRequestWithRetries(
                    loggerStub,
                    currentSetup.default.method,
                    currentSetup.default.path,
                    currentSetup.default.bodySent,
                    currentSetup.default.headersSent);
                assert.fail('Should throw error');
            }
            catch (err) {
                //THEN
                sinon.assert.calledOnce(loggerStub.warn);
                assert.strictEqual(err.message, errMsg);
            }
        });

        it('should resolve with expected status and body when content-type is x-pem-file', async() => {
            // GIVEN
            currentSetup.setupTestDoubles(null, 200, currentSetup.default.xPemFile, currentSetup.default.headersSentWithContentType);
            // WHEN /THEN

            const result = await
                currentSetup.requestHandler.sendRequestWithRetries(
                logger,
                currentSetup.default.method,
                currentSetup.default.path,
                currentSetup.default.headersSentWithContentType
            );
            assert(currentSetup.requestSpy.calledOnce);
            assert.equal(result.status, 200);
            assert.deepEqual(result.body, currentSetup.default.xPemFile);
        });

        it('should reject with expected error report when empty status returned', async() => {
            //GIVEN
            currentSetup.setupTestDoubles(null, null, currentSetup.default.bodyReceived);
            try {
                //WHEN
                await PerformRequestScenarios.callPerformRequest(currentSetup);
                assert.fail('Should throw error');
            }
            catch (err) {
                //THEN
                assert.deepEqual(err.body, undefined);
                assert(err instanceof clientErrors.RuntimeError);
            }
        });

        /*** RETRY SCENARIOS ***/

        it('should retry expected times when unknown error occurrs', async() => {
            // GIVEN
            const error = new Error('unknown error');
            currentSetup.setupTestDoubles(error);
            currentSetup.retryCount = 2;
            try {
                //WHEN
                await PerformRequestScenarios.callPerformRequest(currentSetup);
                assert.fail('Should throw error');
            }
            catch (err) {
                //THEN
                assert.equal(currentSetup.requestSpy.callCount, 3);
                assert(err instanceof clientErrors.RuntimeError);
            }
        });
    });

    describe('sendRequestWithRetries', () => {
        it('should call callback with expected parameters', async() => {
            // GIVEN
            const errMsg = 'errorMessage';
            currentSetup.setupTestDoubles(new Error(errMsg), 509, currentSetup.default.bodyReceived);
            try {
                //WHEN
                await currentSetup.requestHandler.sendRequestWithRetries(
                    logger,
                    currentSetup.default.method,
                    currentSetup.default.path,
                    currentSetup.default.bodySent,
                    currentSetup.default.headersSent);
                assert.fail('Should throw error');
            }
            catch (err) {
                //THEN
                assert.equal(currentSetup.requestSpy.callCount, 1);
                assert.strictEqual(err.message, errMsg);
            }
        });

        it('should not retry when success status received', async() => {
            // GIVEN
            currentSetup.setupTestDoubles(null, 200, currentSetup.default.bodyReceived, currentSetup.default.headersSentJson);
            currentSetup.retryCount = 2;
            // WHEN / THEN
            const result = await currentSetup.requestHandler.sendRequestWithRetries(
                logger,
                currentSetup.default.method,
                currentSetup.default.path,
                currentSetup.default.bodySent,
                currentSetup.default.headersSent);
            assert.equal(currentSetup.requestSpy.callCount, 1);
            assert.deepEqual(result.body, currentSetup.default.bodyReceived);
            assert.deepEqual(result, {
                body:    currentSetup.default.bodyReceived,
                status:  200,
                headers: currentSetup.default.headersSentJson
            });
        });

        it('should retry when error occurred', async() => {
            // GIVEN
            const errMsg = 'errMsg';
            currentSetup.setupTestDoubles(new Error(errMsg), 200, currentSetup.default.bodyReceived);
            currentSetup.retryCount = 2;
            try {
                //WHEN
                await currentSetup.requestHandler.sendRequestWithRetries(
                    logger,
                    currentSetup.default.method,
                    currentSetup.default.path,
                    currentSetup.default.bodySent,
                    currentSetup.default.headersSent);
                assert.fail('Should throw error');
            }
            catch (err) {
                //THEN
                assert.equal(currentSetup.requestSpy.callCount, 3);
                assert.strictEqual(err.message, errMsg);
            }
        });

        it('should retry when internal error status received', async() => {
            // GIVEN
            currentSetup.setupTestDoubles(new Error('request rejected'));
            currentSetup.retryCount = 2;
            try {
                //WHEN
                await currentSetup.requestHandler.sendRequestWithRetries(
                    logger,
                    currentSetup.default.method,
                    currentSetup.default.path,
                    currentSetup.default.bodySent,
                    currentSetup.default.headersSent);
                assert.fail('Should throw error');
            }
            catch (err) {
                //THEN
                assert.equal(currentSetup.requestSpy.callCount, 3);
            }
        });

        it('should retry when no status received', async() => {
            // GIVEN
            currentSetup.setupTestDoubles(null, null, currentSetup.default.bodyReceived);
            currentSetup.retryCount = 2;
            try {
                //WHEN
                await currentSetup.requestHandler.sendRequestWithRetries(
                    logger,
                    currentSetup.default.method,
                    currentSetup.default.path,
                    currentSetup.default.bodySent,
                    currentSetup.default.headersSent);
                assert.fail('Should throw error');
            }
            catch (err) {
                //THEN
                assert.equal(currentSetup.requestSpy.callCount, 3);
            }
        });

        it('should not retry when no success status received', async() => {
            // GIVEN
            currentSetup.setupTestDoubles(null, 220, currentSetup.default.bodyReceived);
            currentSetup.retryCount = 2;
            try {
                //WHEN
                await currentSetup.requestHandler.sendRequestWithRetries(
                    logger,
                    currentSetup.default.method,
                    currentSetup.default.path,
                    currentSetup.default.bodySent,
                    currentSetup.default.headersSent);
                assert.fail('Should throw error');
            }
            catch (err) {
                //THEN
                assert.equal(err instanceof clientErrors.HttpError, true);
                assert.deepEqual(err.status, 220);
                assert.deepEqual(err.body, currentSetup.default.bodyReceived);
                assert.equal(currentSetup.requestSpy.callCount, 1);
            }
        });

        it('should not retry when no success status received with no body', async() => {
            // GIVEN
            currentSetup.setupTestDoubles(null, 220, null);
            currentSetup.retryCount = 2;
            try {
                //WHEN
                await currentSetup.requestHandler.sendRequestWithRetries(
                    logger,
                    currentSetup.default.method,
                    currentSetup.default.path,
                    currentSetup.default.bodySent,
                    currentSetup.default.headersSent);
                assert.fail('Should throw error');
            }
            catch (err) {
                //THEN
                assert.equal(err instanceof clientErrors.HttpError, true);
                assert.deepEqual(err.status, 220);
                assert.deepEqual(err.body, {});
                assert.equal(currentSetup.requestSpy.callCount, 1);
            }
        });

        it('should call request module with expected parameters', async() => {
            // GIVEN
            currentSetup.setupTestDoubles(null, 200, currentSetup.default.bodyReceived);
            currentSetup.retryCount = 2;
            // WHEN / THEN
            await currentSetup.requestHandler
                .sendRequestWithRetries(
                    logger,
                    currentSetup.default.method,
                    currentSetup.default.path,
                    currentSetup.default.bodySent,
                    currentSetup.default.headersSent,
                    currentSetup.default.queryParamsSent
                );
            assert(currentSetup.requestSpy.calledWithExactly(currentSetup.expectedOptions));
        });
    });

    describe('sendRequestWithRetriesOnConnectionReset', () => {
        function getSocketHangUpError() {
            const err = new Error('socket hang up');
            err.code = 'ECONNRESET';
            return err;
        }

        it('should call callback with expected parameters', async() => {
            // GIVEN
            const errMsg = 'errorMessage';
            currentSetup.setupTestDoubles(new Error(errMsg), 509, currentSetup.default.bodyReceived);
            try {
                //WHEN
                await currentSetup.requestHandler.sendRequestWithRetriesOnConnectionReset(
                    logger,
                    currentSetup.default.method,
                    currentSetup.default.path,
                    currentSetup.default.bodySent,
                    currentSetup.default.headersSent);
                assert.fail('Should throw error');
            }
            catch (err) {
                //THEN
                assert.equal(currentSetup.requestSpy.callCount, 1);
                assert.strictEqual(err.message, errMsg);
            }
        });

        it('should not retry when success status received', async() => {
            // GIVEN
            currentSetup.setupTestDoubles(null, 200, currentSetup.default.bodyReceived, currentSetup.default.headersSentJson);
            currentSetup.retryCount = 2;
            // WHEN / THEN
            const result = await currentSetup.requestHandler.sendRequestWithRetriesOnConnectionReset(
                logger,
                currentSetup.default.method,
                currentSetup.default.path,
                currentSetup.default.bodySent,
                currentSetup.default.headersSent);
            assert.equal(currentSetup.requestSpy.callCount, 1);
            assert.deepEqual(result.body, currentSetup.default.bodyReceived);
            assert.deepEqual(result, {
                body:    currentSetup.default.bodyReceived,
                status:  200,
                headers: currentSetup.default.headersSentJson
            });
        });

        it('should retry when ECONNRESET error occurred', async() => {
            // GIVEN
            const errThrown = getSocketHangUpError();
            currentSetup.setupTestDoubles(errThrown, undefined, undefined);
            currentSetup.retryCount = 2;
            try {
                //WHEN
                await currentSetup.requestHandler.sendRequestWithRetriesOnConnectionReset(
                    logger,
                    currentSetup.default.method,
                    currentSetup.default.path,
                    currentSetup.default.bodySent,
                    currentSetup.default.headersSent);
                assert.fail('Should throw error');
            }
            catch (err) {
                //THEN
                assert.equal(currentSetup.requestSpy.callCount, 3);
                assert.strictEqual(err.message, errThrown.message);
                assert.deepStrictEqual(err.details.code, errThrown.code);
            }
        });

        it('should NOT retry when non-ECONNRESET error occurred', async() => {
            // GIVEN
            const errThrown = new Error('errMsg');
            errThrown.code = 'ECONNREFUSED';
            currentSetup.setupTestDoubles(errThrown, 200, currentSetup.default.bodyReceived);
            currentSetup.retryCount = 2;
            try {
                //WHEN
                await currentSetup.requestHandler.sendRequestWithRetriesOnConnectionReset(
                    logger,
                    currentSetup.default.method,
                    currentSetup.default.path,
                    currentSetup.default.bodySent,
                    currentSetup.default.headersSent);
                assert.fail('Should throw error');
            }
            catch (err) {
                //THEN
                assert.equal(currentSetup.requestSpy.callCount, 1);
                assert.strictEqual(err.message, errThrown.message);
                assert.deepStrictEqual(err.details.code, errThrown.code);
            }
        });

        it('should NOT retry when internal error status received', async() => {
            // GIVEN
            currentSetup.setupTestDoubles(new Error('request rejected'));
            currentSetup.retryCount = 2;
            try {
                //WHEN
                await currentSetup.requestHandler.sendRequestWithRetriesOnConnectionReset(
                    logger,
                    currentSetup.default.method,
                    currentSetup.default.path,
                    currentSetup.default.bodySent,
                    currentSetup.default.headersSent);
                assert.fail('Should throw error');
            }
            catch (err) {
                //THEN
                assert.equal(currentSetup.requestSpy.callCount, 1);
            }
        });

        it('should NOT retry when no status received', async() => {
            // GIVEN
            currentSetup.setupTestDoubles(null, null, currentSetup.default.bodyReceived);
            currentSetup.retryCount = 2;
            try {
                //WHEN
                await currentSetup.requestHandler.sendRequestWithRetriesOnConnectionReset(
                    logger,
                    currentSetup.default.method,
                    currentSetup.default.path,
                    currentSetup.default.bodySent,
                    currentSetup.default.headersSent);
                assert.fail('Should throw error');
            }
            catch (err) {
                //THEN
                assert.equal(currentSetup.requestSpy.callCount, 1);
            }
        });

        it('should not retry when no success status received', async() => {
            // GIVEN
            currentSetup.setupTestDoubles(null, 220, currentSetup.default.bodyReceived);
            currentSetup.retryCount = 2;
            try {
                //WHEN
                await currentSetup.requestHandler.sendRequestWithRetriesOnConnectionReset(
                    logger,
                    currentSetup.default.method,
                    currentSetup.default.path,
                    currentSetup.default.bodySent,
                    currentSetup.default.headersSent);
                assert.fail('Should throw error');
            }
            catch (err) {
                //THEN
                assert.equal(err instanceof clientErrors.HttpError, true);
                assert.deepEqual(err.status, 220);
                assert.deepEqual(err.body, currentSetup.default.bodyReceived);
                assert.equal(currentSetup.requestSpy.callCount, 1);
            }
        });

        it('should not retry when no success status received with no body', async() => {
            // GIVEN
            currentSetup.setupTestDoubles(null, 220, null);
            currentSetup.retryCount = 2;
            try {
                //WHEN
                await currentSetup.requestHandler.sendRequestWithRetriesOnConnectionReset(
                    logger,
                    currentSetup.default.method,
                    currentSetup.default.path,
                    currentSetup.default.bodySent,
                    currentSetup.default.headersSent);
                assert.fail('Should throw error');
            }
            catch (err) {
                //THEN
                assert.equal(err instanceof clientErrors.HttpError, true);
                assert.deepEqual(err.status, 220);
                assert.deepEqual(err.body, {});
                assert.equal(currentSetup.requestSpy.callCount, 1);
            }
        });

        it('should call request module with expected parameters', async() => {
            // GIVEN
            currentSetup.setupTestDoubles(null, 200, currentSetup.default.bodyReceived);
            currentSetup.retryCount = 2;
            // WHEN / THEN
            await currentSetup.requestHandler
                .sendRequestWithRetriesOnConnectionReset(
                    logger,
                    currentSetup.default.method,
                    currentSetup.default.path,
                    currentSetup.default.bodySent,
                    currentSetup.default.headersSent,
                    currentSetup.default.queryParamsSent
                );
            assert(currentSetup.requestSpy.calledWithExactly(currentSetup.expectedOptions));
        });
    });
});
