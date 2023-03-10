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
const helpers = require('./mocks/helpers');

class TestContext {
    constructor() {
        this.process = {
            exit: sinon.stub()
        };
        this.path = {
            join: sinon.stub().returns('/path')
        };
        this.commonLogger = {
            genericLogger: {
                error: sinon.stub()
            }
        };
        this.server = 'server';
    }

    async getTarget(initStub) {
        return proxyquire('../src/bootstrap', {
            './common/logger': this.commonLogger,
            'path':            this.path,
            'process':         this.process,
            './configLoader':  {
                init: initStub
            },
            './server': this.server,
        });
    }
}

describe('bootstrapTest', () => {

    describe('positive', () => {
        it('config processed, server run', async() => {
            // GIVEN
            const c = new TestContext();
            const init = sinon.stub().resolves();
            // WHEN
            const run = await c.getTarget(init);
            // THEN
            assert(init.calledOnce);
            assert.strictEqual(run, c.server);
        });


    });

    describe('negative', () => {
        it('error processing config', async() => {
            // GIVEN
            const c = new TestContext();
            const init = sinon.stub().rejects(new Error('Error processing config'));
            // WHEN
            const run = await c.getTarget(init);
            // THEN
            assert(init.calledOnce);
            assert(c.commonLogger.genericLogger.error.calledOnce);
            assert.strictEqual(c.commonLogger.genericLogger.error.args[0][0],
                'During loading config and parsing templates occurred an');
            helpers.assertMockFirstCalledWithArgs(c.process.exit, 1);
            assert.strictEqual(run, undefined);
        });
    });
});
