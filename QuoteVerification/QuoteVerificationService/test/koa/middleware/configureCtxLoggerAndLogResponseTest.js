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
const assert = require('chai').assert;
const events = require('events');
const helpers = require('../../mocks/helpers');
const {
    STATUS_OK,
    STATUS_BAD_REQUEST,
    STATUS_INTERNAL_ERROR
} = require('../../../src/koa/response').STATUSES;


class TestContext {
    constructor() {
        this.ctx = {
            status:  STATUS_OK.httpCode,
            request: {
                method:      'POST',
                originalUrl: 'dummyUrl'
            },
            response: {
                headers: {
                    dummyHeaders: 'value'
                },
                body: 'dummy body'
            },
            res: new events.EventEmitter(),
        };
        this.log = {
            info:  sinon.stub(),
            warn:  sinon.stub(),
            error: sinon.stub()
        };
        this.requestLogFormatter = {
            formatResponseMessage: sinon.stub().returns(['msg to log'])
        };
    }

    getTarget() {
        return proxyquire('../../../src/koa/middleware/configureCtxLoggerAndLogResponse.js', {
            '../../common/requestLogFormatter': this.requestLogFormatter
        });
    }
}

describe('configureCtxLoggerAndLogResponse middleware', () => {

    it('should log on info level when finished emitted and status < 400', async() => {
        // GIVEN
        const c = new TestContext();
        const target = c.getTarget();
        // WHEN
        await target(c.log)(c.ctx, () => {});
        c.ctx.res.emit('finish');

        // THEN
        assert.ok(c.requestLogFormatter.formatResponseMessage.calledOnce);
        helpers.assertMockCalledOnceWithArgs(c.ctx.log.info, 'msg to log');
        assert.ok(c.ctx.log.warn.notCalled);
        assert.ok(c.ctx.log.error.notCalled);
    });

    it('should log on warn level when finished emitted and status >= 400', async() => {
        // GIVEN
        const c = new TestContext();
        const target = c.getTarget();
        // WHEN
        c.ctx.status = STATUS_BAD_REQUEST.httpCode;
        await target(c.log)(c.ctx, () => {});
        c.ctx.res.emit('finish');

        // THEN
        assert.ok(c.requestLogFormatter.formatResponseMessage.calledOnce);
        assert.ok(c.ctx.log.info.notCalled);
        helpers.assertMockCalledOnceWithArgs(c.ctx.log.warn, 'msg to log');
        assert.ok(c.ctx.log.error.notCalled);
    });

    it('should log on error level when finished emitted and status >= 500', async() => {
        // GIVEN
        const c = new TestContext();
        const target = c.getTarget();
        // WHEN
        c.ctx.status = STATUS_INTERNAL_ERROR.httpCode;
        await target(c.log)(c.ctx, () => {});
        c.ctx.res.emit('finish');

        // THEN
        assert.ok(c.requestLogFormatter.formatResponseMessage.calledOnce);
        assert.ok(c.ctx.log.info.notCalled);
        assert.ok(c.ctx.log.warn.notCalled);
        helpers.assertMockCalledOnceWithArgs(c.ctx.log.error, 'msg to log');
    });
});
