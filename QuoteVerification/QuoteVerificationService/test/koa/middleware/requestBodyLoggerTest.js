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

const assertMockFirstCalledWithArgs = require('../../mocks/helpers').assertMockFirstCalledWithArgs;

class TestContext {
    constructor() {
        this.ctx = {
            log: {
                info: sinon.stub()
            },
            request: {
                body: 'requestBody'
            }
        };
        this.next = sinon.stub();
    }

    getTarget() {
        return proxyquire('../../../src/koa/middleware/requestBodyLogger', {});
    }
}

describe('requestBodyLoggerTest', () => {
    describe('Body printed', () => {
        it('text', async() => {
            // GIVEN
            const c = new TestContext();
            // WHEN
            await c.getTarget()(c.ctx, c.next);
            // THEN
            assertMockFirstCalledWithArgs(c.ctx.log.info, '      [body=\'requestBody\']');
            assert(c.next.calledOnce);
        });

        it('json', async() => {
            // GIVEN
            const c = new TestContext();
            c.ctx.request.body = { key: 'value' };
            // WHEN
            await c.getTarget()(c.ctx, c.next);
            // THEN
            assertMockFirstCalledWithArgs(c.ctx.log.info, '      [body={"key":"value"}]');
            assert(c.next.calledOnce);
        });
    });

    describe('Empty body', () => {
        it('no logs', async() => {
            // GIVEN
            const c = new TestContext();
            c.ctx.request.body = undefined;
            // WHEN
            await c.getTarget()(c.ctx, c.next);
            // THEN
            assert(c.ctx.log.info.notCalled);
            assert(c.next.calledOnce);
        });
    });
});
