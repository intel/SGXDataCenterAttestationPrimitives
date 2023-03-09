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

const helpers = require('../../mocks/helpers');

class TestContext {
    constructor() {
        this.rawBodyParser = sinon.stub().returns(Buffer.from('body'));
        this.ctx = {
            'log': {
                error: sinon.stub()
            },
            'request': {
                req: {
                    on: () => { // simulate wrapping stream
                        return {
                            pipe: () => sinon.stub(),
                        };
                    }
                },
                headers: {
                    'content-length': 123
                }
            },
            'body':  '',
            'throw': sinon.stub(),
            'set':   sinon.stub(),
        };
        this.config = {
            service: {
                bodySizeLimits: {
                    blob: '32kb'
                }
            }
        };
        this.next = sinon.stub();
    }

    getTarget() {
        return proxyquire('../../../src/koa/middleware/rawBodyParser', {
            'raw-body': this.rawBodyParser
        });
    }
}

describe('raw body parser middleware tests', () => {

    it('positive', async() => {
        // GIVEN
        const c = new TestContext();
        const getConfiguredRawBodyParser = c.getTarget().getConfiguredRawBodyParser(c.config);
        // WHEN
        await getConfiguredRawBodyParser(c.ctx, c.next);
        // THEN
        assert.deepEqual(c.ctx.request.body, Buffer.from('body'));
        assert.ok(c.next.calledOnce);
        assert.ok(c.ctx.log.error.notCalled);
        assert.ok(c.ctx.throw.notCalled);
    });

    it('negative with error code', async() => {
        // GIVEN
        const c = new TestContext();
        const error = { statusCode: 413 };
        c.rawBodyParser = sinon.stub().throws(error);
        const getConfiguredRawBodyParser = c.getTarget().getConfiguredRawBodyParser(c.config);
        // WHEN
        await getConfiguredRawBodyParser(c.ctx, c.next);
        // THEN
        assert.deepEqual(c.ctx.body, '');
        assert.ok(c.next.notCalled);
        helpers.assertMockCalledOnceWithArgs(c.ctx.log.error, error);
        helpers.assertMockCalledOnceWithArgs(c.ctx.throw, 413);
    });

    it('negative without error code', async() => {
        // GIVEN
        const c = new TestContext();
        const error = new Error('someError');
        c.rawBodyParser = sinon.stub().throws(error);
        const getConfiguredRawBodyParser = c.getTarget().getConfiguredRawBodyParser(c.config);
        // WHEN
        await getConfiguredRawBodyParser(c.ctx, c.next);
        // THEN
        assert.deepEqual(c.ctx.body, '');
        assert.ok(c.next.notCalled);
        helpers.assertMockCalledOnceWithArgs(c.ctx.log.error, error);
        helpers.assertMockCalledOnceWithArgs(c.ctx.throw, 500);
    });

});
