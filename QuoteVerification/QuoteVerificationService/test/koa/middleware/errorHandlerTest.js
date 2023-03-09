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

const assertMockFirstCalledWithArgs = require('../../mocks/helpers').assertMockFirstCalledWithArgs;

class TestContext {
    getTarget() {
        return require('../../../src/koa/middleware/errorHandler');
    }
}

describe('error handler middleware tests', () => {
    function getContext(errStatus) {
        return {
            'log': {
                error: sinon.stub()
            },
            'set':      sinon.stub(),
            'response': {
                get: sinon.stub().returns('application/json; charset=utf-8')
            },
            'throw': sinon.stub().throws({ status: (errStatus || 404) })
        };
    }

    it('positive', async() => {
        // GIVEN
        const next = sinon.stub().returns(0);
        const ctx = getContext();
        const errorHandler = new TestContext().getTarget().withBodyOnError;
        // WHEN
        await errorHandler(ctx, next);
        // THEN
        assert(next.calledOnce);
        assert(ctx.response.get.calledOnce);
        assertMockFirstCalledWithArgs(ctx.set, 'Content-Type', 'application/json');
        assert(ctx.log.error.notCalled);
    });

    it('positive when status created', async() => {
        // GIVEN
        const next = sinon.stub().returns(0);
        const ctx = getContext();
        const body = 'test';
        ctx.status = 201;
        ctx.body = body;
        const errorHandler = new TestContext().getTarget().withNoBodyOnError;
        // WHEN
        await errorHandler(ctx, next);
        // THEN
        assert(next.calledOnce);
        assert(ctx.response.get.calledOnce);
        assert.strictEqual(ctx.body, body);
        assert(ctx.log.error.notCalled);
    });

    it('positive when status bad request and body', async() => {
        // GIVEN
        const next = sinon.stub().returns(0);
        const ctx = getContext(400);
        const body = 'errorReason';
        ctx.status = 400;
        ctx.body = body;
        const errorHandler = new TestContext().getTarget().withBodyOnError;
        // WHEN
        await errorHandler(ctx, next);
        // THEN
        assert(next.calledOnce);
        assert(ctx.response.get.calledOnce);
        assert.strictEqual(ctx.body, body);
        assert(ctx.log.error.notCalled);
    });

    it('no body when status not allowed', async() => {
        // GIVEN
        const next = sinon.stub().returns(0);
        const ctx = getContext(405);
        ctx.status = 405;
        ctx.body = 'NotAllowed';
        const errorHandler = new TestContext().getTarget().withNoBodyOnError;
        // WHEN
        await errorHandler(ctx, next);
        // THEN
        assert(next.calledOnce);
        assert(ctx.response.get.calledOnce);
        assert.strictEqual(ctx.body, '');
        assert(ctx.log.error.notCalled);
    });


    it('clears body on error withNoBodyOnError', async() => {
        // GIVEN
        const next = sinon.stub().returns(0);
        const ctx = getContext(401);
        ctx.status = 401;
        ctx.body = 'unauthorized';
        const errorHandler = new TestContext().getTarget().withNoBodyOnError;
        // WHEN
        await errorHandler(ctx, next);
        // THEN
        assert(next.calledOnce);
        assert(ctx.response.get.calledOnce);
        assert.strictEqual(ctx.body, '');
        assert(ctx.log.error.notCalled);
    });

    it('content-type without charset is kept untouched', async() => {
        // GIVEN
        const next = sinon.stub().returns(0);
        const ctx = getContext();
        const contentType = 'application/x-pem-file';
        ctx.response.get = sinon.stub().returns(contentType);
        const errorHandler = new TestContext().getTarget().withBodyOnError;
        // WHEN
        await errorHandler(ctx, next);
        // THEN
        assert(next.calledOnce);
        assert(ctx.response.get.calledOnce);
        assertMockFirstCalledWithArgs(ctx.set, 'Content-Type', contentType);
        assert(ctx.log.error.notCalled);
    });

    it('no content-type is not causing issue', async() => {
        // GIVEN
        const next = sinon.stub().returns(0);
        const ctx = getContext();
        ctx.response.get = sinon.stub().returns(undefined);
        const errorHandler = new TestContext().getTarget().withBodyOnError;
        // WHEN
        await errorHandler(ctx, next);
        // THEN
        assert(next.calledOnce);
        assert(ctx.response.get.calledOnce);
        assert(ctx.log.error.notCalled);
    });

    it('catch http error with status 404', async() => {
        // GIVEN
        const err = new Error('Not found');
        err.status = 404;
        const next = sinon.stub().throws(err);
        const ctx = getContext();
        const errorHandler = new TestContext().getTarget().withBodyOnError;
        // WHEN
        await errorHandler(ctx, next);
        // THEN
        assert(next.calledOnce);
        assert(ctx.log.error.notCalled);
    });

    it('catch http error with statusCode', async() => {
        // GIVEN
        const err = new Error('Not found');
        err.statusCode = 404;
        const next = sinon.stub().throws(err);
        const ctx = getContext();
        const errorHandler = new TestContext().getTarget().withBodyOnError;
        // WHEN
        await errorHandler(ctx, next);
        // THEN
        assert(next.calledOnce);
        assert(ctx.log.error.notCalled);
    });

    it('catch other error and log stacktrace', async() => {
        // GIVEN
        const err = new Error('Other error');
        const next = sinon.stub().throws(err);
        const ctx = getContext();
        const errorHandler = new TestContext().getTarget().withBodyOnError;
        // WHEN
        await errorHandler(ctx, next);
        // THEN
        assert(next.calledOnce);
        assertMockFirstCalledWithArgs(ctx.log.error, err);
    });

    it('Default NotFound text is not returned in body when status is 404', async() => {
        // GIVEN
        const err = new Error('Not found');
        err.statusCode = 404;
        const next = sinon.stub().throws(err);
        const ctx = getContext();
        ctx.body = ctx.body = 'NotFound';
        const errorHandler = new TestContext().getTarget().withBodyOnError;
        // WHEN
        await errorHandler(ctx, next);
        // THEN
        assert(next.calledOnce);
        assert(ctx.log.error.notCalled);
        assert.strictEqual(ctx.body, '');
    });

    it('BadRequest passes reason to the user', async() => {
        // GIVEN
        const err = new Error('Bad Request');
        const reason = 'EMPTY_NAME';
        err.statusCode = 400;
        const next = sinon.stub().throws(err);
        const ctx = getContext(400);
        ctx.body = reason;
        const errorHandler = new TestContext().getTarget().withBodyOnError;
        // WHEN
        await errorHandler(ctx, next);
        // THEN
        assert(next.calledOnce);
        assertMockFirstCalledWithArgs(ctx.set, 'Content-Type', 'application/json');
        assert(ctx.log.error.notCalled);
        assert.strictEqual(ctx.body.status, err.message);
    });

    it("BadRequest should not pass body if 'withNoBodyOnError' handler is used", async() => {
        // GIVEN
        const err = new Error('Bad Request');
        const reason = 'EMPTY_NAME';
        err.statusCode = 400;
        const next = sinon.stub().throws(err);
        const ctx = getContext(400);
        ctx.body = reason;
        const errorHandler = new TestContext().getTarget().withNoBodyOnError;
        // WHEN
        await errorHandler(ctx, next);
        // THEN
        assert(next.calledOnce);
        assert(ctx.log.error.notCalled);
        assert.strictEqual(ctx.body, '');
    });
});
