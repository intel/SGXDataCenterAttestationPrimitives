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
const _ = require('lodash');
const events = require('events');
const {
    STATUS_OK,
    STATUS_SERVICE_UNAVAILABLE
} = require('../../src/koa/response').STATUSES;

const stubs = {
     response: {
        send() {
            return this;
        },
        end() {
            return this;
        },
        setHeader() {
            return this;
        },
        status() {
            return this;
        }
    }
};

class TestContext {
    constructor() {
        this.ctx = {
            status: STATUS_OK.httpCode,
            reqId:  {},
            body:   {},
            log:    {
                error: sinon.stub(),
                info:  sinon.stub(),
                debug: sinon.stub(),
                trace: sinon.stub()
            },
            state:   {},
            params:  {},
            req:     _.extend(stubs.request),
            request: _.extend(stubs.request),
            set:     sinon.stub(),
            get() {}
        };
    }

    getTarget() {
        return proxyquire('../../src/koa/maxClientsHandler', {});
    }
}

describe('decorators', () => {

    it('test_maxClientsHandler_too_many_clients_negative', async() => {
        // GIVEN
        const c = new TestContext();
        const target = c.getTarget();
        // WHEN
        const serviceName = 'AS';
        const taskType = 'as_task_type_name';
        const maxClients = 4;
        global.currentClients = 100;

        await target.createRequestManager(serviceName, maxClients).manageRequest(taskType, () => {})(c.ctx, () => {});

        // THEN
        assert.strictEqual(c.ctx.status, STATUS_SERVICE_UNAVAILABLE.httpCode);
        assert.deepEqual(c.ctx.body, { code: 'KO.', message: 'Server too busy.' });
    });

    async function testEventEmmitCommon(inputData) {
        // GIVEN
        const c = new TestContext();
        const target = c.getTarget();
        // WHEN
        const taskType = 'as_task_type_name';
        const maxClients = 4;

        const ctx = {
            res: new events.EventEmitter(),
            log: {
                error: sinon.stub(),
                info:  sinon.stub(),
                debug: sinon.stub(),
                trace: sinon.stub()
            },
        };

        ctx.res.writableFinished = inputData.writableFinished;

        await target.createRequestManager(inputData.serviceName, maxClients).manageRequest(taskType, () => {})(ctx, () => {});

        assert.strictEqual(global.currentClients, inputData.expectedClients.beforeEmit);
        ctx.res.emit(inputData.event);
        // THEN
        assert.strictEqual(global.currentClients, inputData.expectedClients.afterEmit);
    }

    it('test_maxClientsHandler_event_finish_positive', async() => {
        const inputData = {
            event:            'finish',
            serviceName:      'AS',
            writableFinished: false,
            expectedClients:  { beforeEmit: 1, afterEmit: 0 }
        };

        return testEventEmmitCommon(inputData);
    });

    it('test_maxClientsHandler_event_close_positive', async() => {
        const inputData = {
            event:            'close',
            serviceName:      'PS',
            writableFinished: false,
            expectedClients:  { beforeEmit: 1, afterEmit: 0 }
        };

        return testEventEmmitCommon(inputData);
    });

    it('test_maxClientsHandler_event_close_writable_not_finished_negative', async() => {
        const inputData = {
            event:            'close',
            serviceName:      'AS',
            writableFinished: true,
            expectedClients:  { beforeEmit: 1, afterEmit: 1 }
        };

        return testEventEmmitCommon(inputData);
    });
});
