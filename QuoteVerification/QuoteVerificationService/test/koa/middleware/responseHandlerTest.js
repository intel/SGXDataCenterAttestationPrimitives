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
const sinon = require('sinon');
const assert = require('assert');
const _ = require('lodash');
global.configPath = './configuration-default/';

const assertMockCalledOnceWithArgs = require('../../mocks/helpers').assertMockCalledOnceWithArgs;

class TestContext {
    getTarget() {
        return proxyquire('../../../src/koa/middleware/responseHandler', {});
    }
}

function createContextStub() {
    return {
        log: {
            info:  sinon.stub(),
            warn:  sinon.stub(),
            error: sinon.stub()
        },
        set: sinon.stub()

    };
}

function createResponseStub(status, body, headers) {
    return {
        httpCode: status,
        jsonBody: body,
        headers
    };
}

function getHandlerFromTarget(target, hasBody) {
    if (hasBody) {
        return target.withBodyOnError;
    }
    return target.withNoBodyOnError;
}

describe('requestHandlerTest', () => {

    let ctx = null;
    let target = null;

    beforeEach(() => {
        target = new TestContext().getTarget();
        ctx = createContextStub();
    });

    describe('BaseResponseHandler', () => {
        it('should initialize BaseResponseHandler with expected status and body', async() => {
            // GIVEN
            const handler = getHandlerFromTarget(target, true);
            await handler(ctx, () => {});

            // WHEN
            ctx.setBadRequest();

            // THEN
            assert.strictEqual(ctx.status, 400);
            assert.strictEqual(_.isUndefined(ctx.body), false);
        });

        it('should throw ErrorResponse when required response params are missing', async() => {
            // GIVEN
            const handler = getHandlerFromTarget(target, true);
            await handler(ctx, () => {});

            // WHEN
            const responseStub = createResponseStub(undefined, undefined);

            // THEN
            assert.throws(() => {
                ctx.setResponse(responseStub);
            }, Object);

        });

        it('should setInternalError with expected status and set body', async() => {
            // GIVEN
            const handler = getHandlerFromTarget(target, true);
            await handler(ctx, () => {});

            // WHEN
            ctx.setInternalError();

            // THEN
            assert.strictEqual(ctx.status, 500);
            assert.strictEqual(_.isUndefined(ctx.body), false);

        });

        it('should initialize BaseResponseHandler with expected headers', async() => {
            // GIVEN
            const handler = getHandlerFromTarget(target, true);
            await handler(ctx, () => {});
            const responseStub = createResponseStub(200, {}, new Map([['header_1', 'value_1'], ['header_2', 'value_2']]));

            // WHEN
            ctx.setResponse(responseStub);

            // THEN
            assert.strictEqual(ctx.status, 200);
            assert.deepStrictEqual(ctx.body, {});

            assertMockCalledOnceWithArgs(ctx.set, 'header_1', 'value_1');
            assertMockCalledOnceWithArgs(ctx.set, 'header_2', 'value_2');

        });

    });

    describe('NoBodyOnErrorResponseHandler', () => {

        it('should initialize NoBodyOnErrorResponseHandler with expected body', async() => {
            // GIVEN
            const handler = getHandlerFromTarget(target, false);
            await handler(ctx, () => {});

            // WHEN
            ctx.setBadRequest();

            // THEN
            assert.strictEqual(ctx.status, 400);
            assert.strictEqual(ctx.body, '');

        });

        it('should initialize NoBodyOnErrorResponseHandler with response body', async() => {
            // GIVEN
            const handler = getHandlerFromTarget(target, false);
            await handler(ctx, () => {});
            const jsonBodyStub = {
                test: 'case'
            };
            const responseStub = createResponseStub(200, jsonBodyStub);

            // WHEN
            ctx.setResponse(responseStub);

            // THEN
            assert.strictEqual(ctx.status, 200);
            assert.deepStrictEqual(ctx.body, jsonBodyStub);

        });


        it('should throw ErrorResponse required response params are missing', async() => {
            // GIVEN
            const handler = getHandlerFromTarget(target, false);
            await handler(ctx, () => {});

            const responseStub = createResponseStub(undefined, undefined);

            // WHEN
            const callSetResponse = () => {
                ctx.setResponse(responseStub);
            };

            // THEN
            assert.throws(callSetResponse, Object);

        });

        it('should throw ErrorResponse when response body is missing', async() => {

            // GIVEN
            const handler = getHandlerFromTarget(target, false);
            await handler(ctx, () => {});

            const responseStub = createResponseStub(200, undefined);

            // THEN
            assert.throws(() => {
                // WHEN
                ctx.setResponse(responseStub);
            }, Object);

        });

        it('should extend context with expected body and status', async() => {
            // GIVEN
            const handler = getHandlerFromTarget(target, false);
            await handler(ctx, () => {});

            // WHEN
            ctx.setInternalError();

            // THEN
            assert.strictEqual(ctx.status, 500);
            assert.strictEqual(ctx.body, '');

        });

    });

});
