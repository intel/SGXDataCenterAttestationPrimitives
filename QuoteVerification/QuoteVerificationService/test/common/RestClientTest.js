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


const proxyquire = require('proxyquire').noCallThru().noPreserveCache();
const logger = require('../../src/common/logger').genericLogger;
const retry = require('retry');

const assert = require('assert');
const sinon = require('sinon');


class TestContext {

    constructor(mockResponse) {

        this.mockResponse = mockResponse;
        this.mockCertificates = sinon.fake(x => x);
        this.mockReadfile = sinon.fake(() => []);

        this.RestClient = proxyquire('../../src/common/RestClient', {
            './getCACertificatesSync':  this.mockCertificates,
            '../common/readFileSafely': this.mockReadfile,
            '../configLoader':          {
                getConfig: () => ({
                    service: {
                        restClientTimeout: 5000
                    }
                })
            },
            './requestHandler': proxyquire('../../src/common/requestHandler', {
                './nodeRequestHandler': async(options, body) => {
                    return mockResponse(options, body);
                },
                'createRetryOperation': () => retry.operation({
                    maxTimeout: 100,
                    minTimeout: 100,
                    retries:    1,
                    factor:     2
                })
            }),
        });
    }

    static okJson200(body) {
        return { statusCode: 200, body, headers: { 'content-type': 'application/json' } };
    }
}


describe('RestClientTests', () => {

    describe('validate', () => {
        it('execution flow during requesting health method', async() => {
            // GIVEN
            const defaultBody = { testField: 'testFieldValue' };
            const responseFake = sinon.fake.resolves(TestContext.okJson200(defaultBody));
            const context = new TestContext(responseFake);
            const target = new context.RestClient('MTLS', '127.0.0.1', 'aPort', 2, 0, 3, 'cert.crt', 'cert.key', ['CA/ca.crt']);
            // WHEN
            const result = await target.health(logger, {});

            // THEN
            assert.deepEqual(result.body, defaultBody);
            assert.equal(context.mockCertificates.callCount, 1);
            assert.equal(context.mockReadfile.callCount, 3);
            assert.equal(responseFake.callCount, 1);
        });

        it('error during requesting health method - internal error', async() => {
            // GIVEN
            const responseFake = sinon.fake.rejects(new Error('request rejected'));
            const context = new TestContext(responseFake);
            const target = new context.RestClient('MTLS', '127.0.0.1', 'aPort', 2, 0, 3, 'cert.crt', 'cert.key', ['CA/ca.crt']);
            // WHEN, THEN
            try {
                await target.health(logger, {});

            }
            catch (err) {
                assert.equal(err.message, 'request rejected');
                assert.equal(responseFake.callCount, 1);
                assert.equal(context.mockCertificates.callCount, 1);
                assert.equal(context.mockReadfile.callCount, 3);
            }
            sinon.restore();
        });
    });

    describe('getRequestPromised', () => {
        it('should resolve when receives success response with body', async() => {
            // GIVEN
            const body =  { testField: 'testFieldValue' };
            const responseFake = sinon.fake.resolves(TestContext.okJson200(body));
            const context = new TestContext(responseFake);
            const target = new context.RestClient('MTLS', '127.0.0.1', 'aPort', 2, 0, 3, 'cert.crt', 'cert.key', ['CA/ca.crt']);

            // WHEN
            const result = await target.getRequestPromised(1, logger, { body }, 'path', {}, {});


            // THEN
            assert.deepEqual(result.body, body);
            assert.deepEqual(result.status, 200);
            assert(responseFake.calledOnce);
        });

        it('should resolve when receives success response without body', async() => {
            // GIVEN
            const responseFake = sinon.fake.resolves(TestContext.okJson200(null));
            const context = new TestContext(responseFake);
            const target = new context.RestClient('MTLS', '127.0.0.1', 'aPort', 2, 0, 3, 'cert.crt', 'cert.key', ['CA/ca.crt']);
            // WHEN
            const result = await target.getRequestPromised(1, logger, { body: null }, 'path', {}, {});

            // THEN
            assert.deepEqual(result.body, null);
            assert.deepEqual(result.status, 200);
            assert(responseFake.calledOnce);
        });


        it('should resolve when receives success response with serialized body', async() => {
            // GIVEN
            const body = '{"serialized": "true"}';
            const responseFake = sinon.fake.resolves(TestContext.okJson200(body));
            const context = new TestContext(responseFake);
            const target = new context.RestClient('MTLS', '127.0.0.1', 'aPort', 2, 0, 3, 'cert.crt', 'cert.key', ['CA/ca.crt']);

            // WHEN
            const result = await target.getRequestPromised(1, logger, { body }, 'path', {}, {});

            // THEN
            assert.deepEqual(result.body, body);
            assert.deepEqual(result.status, 200);
            assert(responseFake.calledOnce);
        });

        it('should reject when receives response with wrong body format', async() => {
            // GIVEN
            const body = '{ unexpectedField }';
            const responseFake = sinon.fake.resolves(TestContext.okJson200(body));
            const context = new TestContext(responseFake);
            const target = new context.RestClient('MTLS', '127.0.0.1', 'aPort', 2, 0, 3, 'cert.crt', 'cert.key', ['CA/ca.crt']);

            // WHEN
            try {
                await target.getRequestPromised(1, logger, { body }, 'path', {}, {});
                assert.fail('Should throw error');
            }
            catch (err) {
                assert(err instanceof Error);
            }
        });

        it('should reject with error when error occurred', async() => {
            // GIVEN
            const responseFake = sinon.fake.rejects(new Error('error example'));
            const context = new TestContext(responseFake);
            const target = new context.RestClient('MTLS', '127.0.0.1', 'aPort', 2, 0, 3, 'cert.crt', 'cert.key', ['CA/ca.crt']);

            // WHEN
            try {
                await target.getRequestPromised(1, logger, { body: 'request' }, 'path', {}, {});
                assert.fail('Should throw error');
            }
            catch (err) {
                assert(err instanceof Error);
            }
        });


        it('should call internal method with expected arguments (GET)', async() => {
            // GIVEN
            const body = 'request';
            const context = new TestContext(sinon.fake());
            const target = new context.RestClient('MTLS', '127.0.0.1', 'aPort', 2, 0, 3, 'cert.crt', 'cert.key', ['CA/ca.crt']);
            const stub = sinon.stub(target, 'requestPromised').returns();

            // WHEN
            await target.getRequestPromised(1, logger, { body }, 'path');

            // THEN
            assert(stub.calledWithExactly(logger, 'GET', 'path', { body }, 1, {}, {}));
        });

        it('should call internal method with expected arguments (POST)', async() => {
            // GIVEN
            const body = 'request';
            const context = new TestContext(sinon.fake());
            const target = new context.RestClient('MTLS', '127.0.0.1', 'aPort', 2, 0, 3, 'cert.crt', 'cert.key', ['CA/ca.crt']);
            const stub = sinon.stub(target, 'requestPromised').returns();

            // WHEN
            await target.postRequestPromised(1, logger, { body }, 'path');

            // THEN
            assert(stub.calledWithExactly(logger, 'POST', 'path', { body }, 1, {}, {}, false));
        });

        it('should call internal method with expected arguments (PUT)', async() => {
            // GIVEN
            const body = 'request';
            const context = new TestContext(sinon.fake());
            const target = new context.RestClient('MTLS', '127.0.0.1', 'aPort', 2, 0, 3, 'cert.crt', 'cert.key', ['CA/ca.crt']);
            const stub = sinon.stub(target, 'requestPromised').returns();

            // WHEN
            await target.putRequestPromised(1, logger, { body }, 'path');

            // THEN
            assert(stub.calledWithExactly(logger, 'PUT', 'path', { body }, 1, {}, {}));
        });
    });
});
