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

const sinon = require('sinon');
const assert = require('assert');

const assertMockCalledOnceWithArgs = require('../../mocks/helpers').assertMockCalledOnceWithArgs;

class TestContext {

    constructor() {
        this.next = sinon.stub().returns(0);
        this.set = sinon.stub();
        this.log = {
            warn: sinon.stub()
        };
    }

    getTarget() {
        return require('../../../src/koa/middleware/requestControl');
    }

    getContext(input, router) {
        return {
               'req': {
                   method: input.method
               },
               'is':    sinon.stub().returns(input.isResult),
               'set':   this.set,
               'log':   this.log,
               'path':  '/',
               'throw': (err) => { throw (err); },
               'app':   { middleware: [{ name: 'dispatch', router }] },
            };
    }

    getRouter(otp) {
        const output = otp || {
            path:        [{ path: '/', methods: ['GET', 'POST'] }],
            route:       true,
            contentType: 'application/json'
        };

        return {
            match: sinon.stub().returns(output)
        };
    }
}

describe('request body control middleware tests', () => {

    it('should call next when POST request contain application/json content type', async() => {
        // GIVEN
        const ctx = new TestContext();
        const ctxInput = {
            method:   'POST',
            isResult: true
        };

        // WHEN
        await ctx.getTarget().requestControl(ctx.rbcInput)(ctx.getContext(ctxInput, ctx.getRouter()), ctx.next);
        // THEN
        assert(ctx.next.calledOnce);
        assert(ctx.log.warn.notCalled);
    });

    it('should call next when GET request not contain content type', async() => {
        // GIVEN
        const ctx = new TestContext();
        const ctxInput = {
            method:   'GET',
            isResult: null
        };

        // WHEN
        await ctx.getTarget().requestControl(ctx.rbcInput)(ctx.getContext(ctxInput, ctx.getRouter()), ctx.next);
        // THEN
        assert(ctx.next.calledOnce);
        assert(ctx.log.warn.notCalled);
    });

    it('should call throw 415 when POST request contain wrong content type', async() => {
        // GIVEN
        const ctx = new TestContext();
        const expWarnMsg = 'Only application/json content type is supported. Return 415 Unsupported Media Type.';
        const ctxInput = {
            method:   'POST',
            isResult: false
        };

        // WHEN
        try {
            await ctx.getTarget().requestControl(ctx.rbcInput)(ctx.getContext(ctxInput, ctx.getRouter()), ctx.next);
        }
        // THEN
        catch (err) {
            assert.equal(err, 415);
        }
        assert(ctx.next.notCalled);
        assert(ctx.log.warn.calledOnce);
        assertMockCalledOnceWithArgs(ctx.log.warn, expWarnMsg);
    });

    it('should throw 415 when GET request contain content type', async() => {
        // GIVEN
        const expWarnMsg = 'Incoming request has not empty body for GET method. Return 415 Unsupported Media Type.';
        const ctx = new TestContext();
        const ctxInput = {
            method: 'GET'
        };

        // WHEN
        try {
            await ctx.getTarget().requestControl(ctx.rbcInput)(ctx.getContext(ctxInput, ctx.getRouter()), ctx.next);
        }
        // THEN
        catch (err) {
            assert.equal(err, 415);
        }
        assert(ctx.next.notCalled);
        assert(ctx.log.warn.calledOnce);
        assertMockCalledOnceWithArgs(ctx.log.warn, expWarnMsg);
    });

    it('should throw 405 when incoming method is not allowed', async() => {
        const ctx = new TestContext();
        const ctxInput = {
            method: 'TRACE',
        };
        // GIVEN
        const expWarnMsg = `Method: ${ctxInput.method} is not allowed.`;

        // WHEN
        try {
            await ctx.getTarget().requestControl(ctx.rbcInput)(ctx.getContext(ctxInput, ctx.getRouter()), ctx.next);
        }
        // THEN
        catch (err) {
            assert.equal(err, 405);
        }
        assert(ctx.next.notCalled);
        assert(ctx.log.warn.calledOnce);
        assertMockCalledOnceWithArgs(ctx.log.warn, expWarnMsg);
    });

    it('should call throw 404 when route does not match', async() => {
        // GIVEN
        const ctx = new TestContext();
        const expWarnMsg = 'Path: / is not allowed.';
        const ctxInput = {
            method:   'POST',
            isResult: false
        };
        const match = {
            path:        [],
            route:       false,
            contentType: 'application/json'
        };


        // WHEN
        try {
            await ctx.getTarget().requestControl(ctx.rbcInput)(ctx.getContext(ctxInput, ctx.getRouter(match)), ctx.next);
        }
            // THEN
        catch (err) {
            assert.equal(err, 404);
        }
        assert(ctx.next.notCalled);
        assert(ctx.log.warn.calledOnce);
        assertMockCalledOnceWithArgs(ctx.log.warn, expWarnMsg);
    });

    it('should call throw 405 when method does not match', async() => {
        // GIVEN
        const ctx = new TestContext();
        const expWarnMsg = 'Method: POST is not allowed.';
        const ctxInput = {
            method:   'POST',
            isResult: false
        };
        const match = {
            path:        [{ path: '/', methods: ['GET'] }],
            route:       false,
            contentType: 'application/json'
        };


        // WHEN
        try {
            await ctx.getTarget().requestControl(ctx.rbcInput)(ctx.getContext(ctxInput, ctx.getRouter(match)), ctx.next);
        }
            // THEN
        catch (err) {
            assert.equal(err, 405);
        }
        assert(ctx.next.notCalled);
        assert(ctx.log.warn.calledOnce);
        assertMockCalledOnceWithArgs(ctx.set, 'Allow', 'GET'); // assert that 'Allowed' header has been set
        assertMockCalledOnceWithArgs(ctx.log.warn, expWarnMsg);
    });

    it('should call throw 404 when router has no allowed methods', async() => {
        // GIVEN
        const ctx = new TestContext();
        const expWarnMsg = 'Path: / is not allowed.';
        const ctxInput = {
            method:   'POST',
            isResult: false
        };
        const match = {
            path:        [{ path: '/', methods: [] }],
            route:       false,
            contentType: 'application/json'
        };


        // WHEN
        try {
            await ctx.getTarget().requestControl(ctx.rbcInput)(ctx.getContext(ctxInput, ctx.getRouter(match)), ctx.next);
        }
            // THEN
        catch (err) {
            assert.equal(err, 404);
        }
        assert(ctx.next.notCalled);
        assert(ctx.log.warn.calledOnce);
        assertMockCalledOnceWithArgs(ctx.log.warn, expWarnMsg);
    });
});
