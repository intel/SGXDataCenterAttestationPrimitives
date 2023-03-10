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
const Buffer = require('safe-buffer').Buffer;

const assertMockFirstCalledWithArgs = require('../../mocks/helpers').assertMockFirstCalledWithArgs;

class TestContext {
    constructor() {
        this.uuid = {
            bin: sinon.stub().returns(Buffer.from('aaaaaaaabbbbccccddddeeeeeeeeeeee', 'hex'))
        };
        this.logger = {
            error: sinon.stub(),
            warn:  sinon.stub(),
            info:  sinon.stub(),
            debug: sinon.stub()
        };
        this.ctx = {
            log: {
                scoped: sinon.stub().returns(this.logger),
                error:  sinon.stub(),
                warn:   sinon.stub(),
                info:   sinon.stub(),
                debug:  sinon.stub()
            },
            set: sinon.stub(),
            req: {
                headers: []
            },
            request: {}
        };
        this.next = sinon.stub();
        this.serverLevel = { isTopLevel: false };
    }

    getTarget() {
        return proxyquire('../../../src/koa/middleware/requestId', {
            'uuid-random': this.uuid
        });
    }
}

describe('requestIdTest', () => {
    it('generated reqId is in correct format, without dashes', async() => {
        // GIVEN
        const c = new TestContext();
        // WHEN
        await c.getTarget()(c.serverLevel)(c.ctx, c.next);
        // THEN
        assert.strictEqual(c.ctx.reqId, 'aaaaaaaabbbbccccddddeeeeeeeeeeee');
        assert.strictEqual(c.ctx.request.reqId, 'aaaaaaaabbbbccccddddeeeeeeeeeeee');
    });

    it('Request-ID header is set correctly', async() => {
        // GIVEN
        const c = new TestContext();
        // WHEN
        await c.getTarget()(c.serverLevel)(c.ctx, c.next);
        // THEN
        assertMockFirstCalledWithArgs(c.ctx.set, 'Request-ID', 'aaaaaaaabbbbccccddddeeeeeeeeeeee');
    });

    it('Request has no Request-ID header', async() => {
        // GIVEN
        const expectedMsg = 'No Request-ID header. New Request-ID is: [aaaaaaaabbbbccccddddeeeeeeeeeeee]';
        const c = new TestContext();
        // WHEN
        await c.getTarget()(c.serverLevel)(c.ctx, c.next);
        // THEN
        assertMockFirstCalledWithArgs(c.logger.debug, expectedMsg);
        assert(c.next.calledOnce);
    });

    it('Request has empty Request-ID header', async() => {
        // GIVEN
        const expectedMsg = 'No Request-ID header. New Request-ID is: [aaaaaaaabbbbccccddddeeeeeeeeeeee]';
        const c = new TestContext();
        c.ctx.req.headers['request-id'] = '';
        // WHEN
        await c.getTarget()(c.serverLevel)(c.ctx, c.next);
        // THEN
        assertMockFirstCalledWithArgs(c.logger.debug, expectedMsg);
        assert(c.next.calledOnce);
    });

    it('Request has valid Request-ID header but not top level', async() => {
        // GIVEN
        const expectedMsg = 'Using received Request-ID: [00000000111122223333444444444444]';
        const c = new TestContext();
        c.ctx.req.headers['request-id'] = '00000000111122223333444444444444';
        // WHEN
        await c.getTarget()(c.serverLevel)(c.ctx, c.next);
        // THEN
        assertMockFirstCalledWithArgs(c.logger.debug, expectedMsg);
        assert(c.next.calledOnce);
    });

    it('Request-ID header is not hexadecimal format and not top level', async() => {
        // GIVEN
        const expectedMsg = 'Received own Request-ID header: [XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX] has incorrect format (must be 32-sign hexadecimal). New Request-ID is: [aaaaaaaabbbbccccddddeeeeeeeeeeee]';
        const c = new TestContext();
        c.ctx.req.headers['request-id'] = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
        // WHEN
        await c.getTarget()(c.serverLevel)(c.ctx, c.next);
        // THEN
        assertMockFirstCalledWithArgs(c.logger.warn, expectedMsg);
        assert(c.next.calledOnce);
    });

    it('Request-ID header is too short and not top level', async() => {
        // GIVEN
        const expectedMsg = 'Received own Request-ID header: [aaaaaaaabbbbccccddddeeeeeeeeeee] has incorrect format (must be 32-sign hexadecimal). New Request-ID is: [aaaaaaaabbbbccccddddeeeeeeeeeeee]';
        const c = new TestContext();
        c.ctx.req.headers['request-id'] = 'aaaaaaaabbbbccccddddeeeeeeeeeee';
        // WHEN
        await c.getTarget()(c.serverLevel)(c.ctx, c.next);
        // THEN
        assertMockFirstCalledWithArgs(c.logger.warn, expectedMsg);
        assert(c.next.calledOnce);
    });

    it('Request-ID header is too long and not top level', async() => {
        // GIVEN
        const expectedMsg = 'Received own Request-ID header: [aaaaaaaabbbbccccddddeeeeeeeeeeeee] has incorrect format (must be 32-sign hexadecimal). New Request-ID is: [aaaaaaaabbbbccccddddeeeeeeeeeeee]';
        const c = new TestContext();
        c.ctx.req.headers['request-id'] = 'aaaaaaaabbbbccccddddeeeeeeeeeeeee';
        // WHEN
        await c.getTarget()(c.serverLevel)(c.ctx, c.next);
        // THEN
        assertMockFirstCalledWithArgs(c.logger.warn, expectedMsg);
        assert(c.next.calledOnce);
    });


    it('Request has Request-ID header and top level', async() => {
        // GIVEN
        const expectedMsg = 'Received own Request-ID header: [00000000111122223333444444444444]. New Request-ID is: [aaaaaaaabbbbccccddddeeeeeeeeeeee]';
        const c = new TestContext();
        c.ctx.req.headers['request-id'] = '00000000111122223333444444444444';
        c.serverLevel.isTopLevel = true;
        // WHEN
        await c.getTarget()(c.serverLevel)(c.ctx, c.next);
        // THEN
        assertMockFirstCalledWithArgs(c.logger.info, expectedMsg);
        assert(c.next.calledOnce);
    });
});
