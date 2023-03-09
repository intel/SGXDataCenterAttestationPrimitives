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
const _ = require('lodash');
const Promise = require('bluebird');

class TestContext {
    constructor() {
        this.addComponentHealthCondition = sinon.stub();
        this.HealthCache = sinon.stub().returns({
            addComponentHealthCondition: this.addComponentHealthCondition,
            status:                      { OK: 'OK' }
        });
        this.logger = {
            trace: () => {},
            debug: () => {},
            info:  () => {},
            error: () => {},
        };
        this.version = {
            version: '123'
        };
        this.config = {
            healthCheck: {
                intervalMs:  1500,
                freshnessMs: 1500
            }
        };
        this.configLoader = {
            getConfig: () => this.config
        };
        this.client = { getHealth: sinon.stub() };
        this.callback = sinon.stub();
        this.response = {
            body: {
                status: 'OK'
            }
        };
    }

    getTarget() {
        return proxyquire('../src/healthChecker', {
            './koa/koaHealthCache':               this.HealthCache,
            './configLoader':                     this.configLoader,
            './logger':                           () => this.logger,
            './package.json':                     this.version,
            './clients/pcsAccessLayer/PCSClient': this.client,
            './clients/vcsAccessLayer/VCSClient': this.client,
            './qvl':                              { getVersion: this.client.getHealth }
        });
    }
}

describe('healthChecker', () => {

    it('configuration passed to HealthCache', async() => {
        // GIVEN
        const testCtx = new TestContext();
        const expectedConfiguration = {
            frequencyMS: testCtx.config.healthCheck.intervalMs,
            validityMS:  testCtx.config.healthCheck.freshnessMs,
            version:     testCtx.version.version,
            logger:      testCtx.logger
        };

        // WHEN
        await testCtx.getTarget();

        // THEN
        helpers.assertMockFirstCalledWithArgs(testCtx.HealthCache, expectedConfiguration);
    });

    async function awaitHealthConditions(testCtx, howMany) {
        assert.strictEqual(testCtx.addComponentHealthCondition.callCount, howMany);
        const conditions = _.range(howMany)
            .map(index => testCtx.addComponentHealthCondition.args[index][1])
            .map(componentHealth => componentHealth(testCtx.logger, 'reqId', testCtx.callback));
        await Promise.all(conditions);
    }

    const healthConditionsCount = 3;

    it('Positive', async() => {
        // GIVEN
        const testCtx = new TestContext();

        testCtx.client.getHealth = sinon.stub().resolves(testCtx.response);

        // WHEN
        await testCtx.getTarget();
        await awaitHealthConditions(testCtx, healthConditionsCount);

        // THEN
        const hcStatuses = testCtx.callback.args.map(args => args[1].status);
        assert.strictEqual(hcStatuses.length, healthConditionsCount);
        assert.ok((hcStatuses).every(status => status === 'OK'), 'Each status should be OK');
    });

    it('Negative', async() => {
        // GIVEN
        const testCtx = new TestContext();
        testCtx.client.getHealth = sinon.stub().rejects({
            body: {
                status: 'FAILED'
            }
        });

        // WHEN
        await testCtx.getTarget();
        await awaitHealthConditions(testCtx, healthConditionsCount);

        // THEN
        const hcStatuses = testCtx.callback.args.map(args => args[1].status);
        assert.strictEqual(hcStatuses.length, healthConditionsCount);
        assert.ok((hcStatuses).some(status => status === 'FAILED'), 'Some HC should fail');
    });
});
