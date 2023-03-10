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

class TestContext {
    constructor() {
        this.config = {
            vcsClient: {},
        };
        this.configLoader = {
            getConfig: () => this.config
        };
        const restClient = {
            getRequestPromisedStub:  sinon.stub(),
            postRequestPromisedStub: sinon.stub(),
            healthStub:              sinon.stub()
        };
        this.RestClientMock = function construct() {
            this.getRequestPromised = restClient.getRequestPromisedStub;
            this.postRequestPromised = restClient.postRequestPromisedStub;
            this.health = restClient.healthStub;
        };
        this.restClient = restClient;
        this.logger = {
            info: sinon.stub()
        };
        const nodeCache = {
            getStub: sinon.stub(),
            setStub: sinon.stub()
        };
        this.NodeCacheMock = function construct(config) {
            assert.equal(typeof config.stdTTL, 'number');
            assert.equal(typeof config.checkperiod, 'number');
            assert.equal(typeof config.maxKeys, 'number');

            this.get = nodeCache.getStub;
            this.set = nodeCache.setStub;
        };
        this.nodeCache = nodeCache;
    }

    async getTarget() {
        return proxyquire('../../src/clients/vcsAccessLayer/VCSClient', {
            '../../configLoader':      this.configLoader,
            '../../common/RestClient': this.RestClientMock
        });
    }
}

describe('VCSClient tests', () => {

    describe('signVerificationReport', () => {

        it('positive response', async() => {
            // GIVEN
            const testCtx = new TestContext();
            const mockedResponse = { status: 200 };
            testCtx.restClient.postRequestPromisedStub.returns(mockedResponse);
            const target = await testCtx.getTarget();
            // WHEN
            const response = await target.signVerificationReport({}, 'reqId', testCtx.logger);
            // THEN
            assert.deepStrictEqual(response, mockedResponse);
        });

        it('error response', async() => {
            // GIVEN
            const testCtx = new TestContext();
            const err = new Error('Signing failed');
            testCtx.restClient.postRequestPromisedStub.rejects(err);
            const target = await testCtx.getTarget();
            const response = await target.signVerificationReport({}, 'reqId', testCtx.logger);
            assert.deepStrictEqual(response, err);
        });
    });

    describe('getHealth call', () => {

        it('response with body.status from checked service', async() => {
            // GIVEN
            const testCtx = new TestContext();
            const mockedResponse = { status: 200, body: { status: 'OK' } };
            testCtx.restClient.healthStub.returns(mockedResponse);
            const target = await testCtx.getTarget();
            // WHEN
            const response = target.getHealth(null, {});

            // THEN
            assert.deepStrictEqual(response, mockedResponse);
        });
    });
});
