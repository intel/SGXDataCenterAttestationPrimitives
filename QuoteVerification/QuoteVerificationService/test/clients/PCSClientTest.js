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
const helpers = require('../mocks/helpers');

class TestContext {
    constructor() {
        this.config = {
            pcsClient: {},
            cache:     {
                ttl:         900,
                checkPeriod: 60,
                maxKeys:     1
            }
        };
        this.configLoader = {
            getConfig: () => this.config
        };
        const restClient = {
            getRequestPromisedStub: sinon.stub(),
            healthStub:             sinon.stub()
        };
        this.RestClientMock = function construct() {
            this.getRequestPromised = restClient.getRequestPromisedStub;
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
        return proxyquire('../../src/clients/pcsAccessLayer/PCSClient', {
            '../../configLoader':      this.configLoader,
            '../../common/RestClient': this.RestClientMock,
            'node-cache':              this.NodeCacheMock
        });
    }
}

describe('PCSClient tests', () => {

    describe('getSgxTcbInfo call', () => {
        it('response saved to cache', async() => {
            // GIVEN
            const testCtx = new TestContext();
            const reqId = 'requestId';
            const fmspc = 'fmspc';
            const mockedResponse = { status: 200, body: 'body', headers: ['header'] };
            testCtx.restClient.getRequestPromisedStub.resolves(mockedResponse);
            const target = await testCtx.getTarget();
            // WHEN
            const response = await target.getSgxTcbInfo(fmspc, reqId, testCtx.logger);
            // THEN
            assert.deepStrictEqual(response, mockedResponse);
            helpers.assertMockFirstCalledWithArgs(testCtx.restClient.getRequestPromisedStub,
                reqId, testCtx.logger, null, '/sgx/certification/v4/tcb', {}, { fmspc });
            helpers.assertMockFirstCalledWithArgs(testCtx.nodeCache.setStub, fmspc, mockedResponse);
            assert.equal(testCtx.logger.info.callCount, 1);
        });

        it('response read from cache', async() => {
            // GIVEN
            const testCtx = new TestContext();
            const fmspc = 'fmspc';
            const reqId = 'requestId';
            const mockedResponse = { status: 200, body: 'body', headers: ['header'] };
            testCtx.nodeCache.getStub.resolves(mockedResponse);
            const target = await testCtx.getTarget();
            // WHEN
            const response = await target.getSgxTcbInfo(fmspc, reqId, testCtx.logger);
            // THEN
            assert.deepStrictEqual(response, mockedResponse);
            assert.equal(testCtx.restClient.getRequestPromisedStub.callCount, 0);
            assert.equal(testCtx.nodeCache.setStub.callCount, 0);
            helpers.assertMockFirstCalledWithArgs(testCtx.logger.info,
                `SGX TcbInfo for FMSPC=${fmspc} taken from cache`);
        });

        it('error not cached', async() => {
            // GIVEN
            const testCtx = new TestContext();
            const fmspc = 'fmspc';
            const reqId = 'requestId';
            const mockedResponse = { status: 500, body: 'body', headers: ['header'] };
            testCtx.restClient.getRequestPromisedStub.rejects(mockedResponse);
            const target = await testCtx.getTarget();
            // WHEN
            const response = await target.getSgxTcbInfo(fmspc, reqId, testCtx.logger);
            // THEN
            assert.deepStrictEqual(response, mockedResponse);
            helpers.assertMockFirstCalledWithArgs(testCtx.restClient.getRequestPromisedStub,
                reqId, testCtx.logger, null, '/sgx/certification/v4/tcb', {}, { fmspc });
            assert.equal(testCtx.nodeCache.setStub.callCount, 0);
            assert.equal(testCtx.logger.info.callCount, 0);
        });
    });

    describe('getTdxTcbInfo call', () => {
        it('response saved to cache', async() => {
            // GIVEN
            const testCtx = new TestContext();
            const reqId = 'requestId';
            const fmspc = 'fmspc';
            const mockedResponse = { status: 200, body: 'body', headers: ['header'] };
            testCtx.restClient.getRequestPromisedStub.resolves(mockedResponse);
            const target = await testCtx.getTarget();
            // WHEN
            const response = await target.getTdxTcbInfo(fmspc, reqId, testCtx.logger);
            // THEN
            assert.deepStrictEqual(response, mockedResponse);
            helpers.assertMockFirstCalledWithArgs(testCtx.restClient.getRequestPromisedStub,
                reqId, testCtx.logger, null, '/tdx/certification/v4/tcb', {}, { fmspc });
            helpers.assertMockFirstCalledWithArgs(testCtx.nodeCache.setStub, fmspc, mockedResponse);
            assert.equal(testCtx.logger.info.callCount, 1);
        });

        it('response read from cache', async() => {
            // GIVEN
            const testCtx = new TestContext();
            const fmspc = 'fmspc';
            const reqId = 'requestId';
            const mockedResponse = { status: 200, body: 'body', headers: ['header'] };
            testCtx.nodeCache.getStub.resolves(mockedResponse);
            const target = await testCtx.getTarget();
            // WHEN
            const response = await target.getTdxTcbInfo(fmspc, reqId, testCtx.logger);
            // THEN
            assert.deepStrictEqual(response, mockedResponse);
            assert.equal(testCtx.restClient.getRequestPromisedStub.callCount, 0);
            assert.equal(testCtx.nodeCache.setStub.callCount, 0);
            helpers.assertMockFirstCalledWithArgs(testCtx.logger.info,
                `TDX TcbInfo for FMSPC=${fmspc} taken from cache`);
        });

        it('error not cached', async() => {
            // GIVEN
            const testCtx = new TestContext();
            const fmspc = 'fmspc';
            const reqId = 'requestId';
            const mockedResponse = { status: 500, body: 'body', headers: ['header'] };
            testCtx.restClient.getRequestPromisedStub.rejects(mockedResponse);
            const target = await testCtx.getTarget();
            // WHEN
            const response = await target.getTdxTcbInfo(fmspc, reqId, testCtx.logger);
            // THEN
            assert.deepStrictEqual(response, mockedResponse);
            helpers.assertMockFirstCalledWithArgs(testCtx.restClient.getRequestPromisedStub,
                reqId, testCtx.logger, null, '/tdx/certification/v4/tcb', {}, { fmspc });
            assert.equal(testCtx.nodeCache.setStub.callCount, 0);
            assert.equal(testCtx.logger.info.callCount, 0);
        });
    });

    describe('getSgxQeIdentity call', () => {
        it('response saved to cache', async() => {
            // GIVEN
            const testCtx = new TestContext();
            const reqId = 'requestId';
            const mockedResponse = { status: 200, body: 'body', headers: ['header'] };
            testCtx.restClient.getRequestPromisedStub.resolves(mockedResponse);
            const target = await testCtx.getTarget();
            // WHEN
            const response = await target.getSgxQeIdentity(reqId, testCtx.logger);
            // THEN
            assert.deepStrictEqual(response, mockedResponse);
            helpers.assertMockFirstCalledWithArgs(testCtx.restClient.getRequestPromisedStub,
                reqId, testCtx.logger, null, '/sgx/certification/v4/qe/identity');
            helpers.assertMockFirstCalledWithArgs(testCtx.nodeCache.setStub, 'sgxQeIdentity', mockedResponse);
            assert.equal(testCtx.logger.info.callCount, 1);
        });

        it('response read from cache', async() => {
            // GIVEN
            const testCtx = new TestContext();
            const reqId = 'requestId';
            const mockedResponse = { status: 200, body: 'body', headers: ['header'] };
            testCtx.nodeCache.getStub.resolves(mockedResponse);
            const target = await testCtx.getTarget();
            // WHEN
            const response = await target.getSgxQeIdentity(reqId, testCtx.logger);
            // THEN
            assert.deepStrictEqual(response, mockedResponse);
            assert.equal(testCtx.restClient.getRequestPromisedStub.callCount, 0);
            assert.equal(testCtx.nodeCache.setStub.callCount, 0);
            helpers.assertMockFirstCalledWithArgs(testCtx.logger.info, 'SGX QeIdentity taken from cache');
        });

        it('error not cached', async() => {
            // GIVEN
            const testCtx = new TestContext();
            const reqId = 'requestId';
            const mockedResponse = { status: 500, body: 'body', headers: ['header'] };
            testCtx.restClient.getRequestPromisedStub.rejects(mockedResponse);
            const target = await testCtx.getTarget();
            // WHEN
            const response = await target.getSgxQeIdentity(reqId, testCtx.logger);
            // THEN
            assert.deepStrictEqual(response, mockedResponse);
            helpers.assertMockFirstCalledWithArgs(testCtx.restClient.getRequestPromisedStub,
                reqId, testCtx.logger, null, '/sgx/certification/v4/qe/identity');
            assert.equal(testCtx.nodeCache.setStub.callCount, 0);
            assert.equal(testCtx.logger.info.callCount, 0);
        });
    });

    describe('getTdxQeIdentity call', () => {
        it('response saved to cache', async() => {
            // GIVEN
            const testCtx = new TestContext();
            const reqId = 'requestId';
            const mockedResponse = { status: 200, body: 'body', headers: ['header'] };
            testCtx.restClient.getRequestPromisedStub.resolves(mockedResponse);
            const target = await testCtx.getTarget();
            // WHEN
            const response = await target.getTdxQeIdentity(reqId, testCtx.logger);
            // THEN
            assert.deepStrictEqual(response, mockedResponse);
            helpers.assertMockFirstCalledWithArgs(testCtx.restClient.getRequestPromisedStub,
                reqId, testCtx.logger, null, '/tdx/certification/v4/qe/identity');
            helpers.assertMockFirstCalledWithArgs(testCtx.nodeCache.setStub, 'tdxQeIdentity', mockedResponse);
            assert.equal(testCtx.logger.info.callCount, 1);
        });

        it('response read from cache', async() => {
            // GIVEN
            const testCtx = new TestContext();
            const reqId = 'requestId';
            const mockedResponse = { status: 200, body: 'body', headers: ['header'] };
            testCtx.nodeCache.getStub.resolves(mockedResponse);
            const target = await testCtx.getTarget();
            // WHEN
            const response = await target.getTdxQeIdentity(reqId, testCtx.logger);
            // THEN
            assert.deepStrictEqual(response, mockedResponse);
            assert.equal(testCtx.restClient.getRequestPromisedStub.callCount, 0);
            assert.equal(testCtx.nodeCache.setStub.callCount, 0);
            helpers.assertMockFirstCalledWithArgs(testCtx.logger.info, 'TDX QeIdentity taken from cache');
        });

        it('error not cached', async() => {
            // GIVEN
            const testCtx = new TestContext();
            const reqId = 'requestId';
            const mockedResponse = { status: 500, body: 'body', headers: ['header'] };
            testCtx.restClient.getRequestPromisedStub.rejects(mockedResponse);
            const target = await testCtx.getTarget();
            // WHEN
            const response = await target.getTdxQeIdentity(reqId, testCtx.logger);
            // THEN
            assert.deepStrictEqual(response, mockedResponse);
            helpers.assertMockFirstCalledWithArgs(testCtx.restClient.getRequestPromisedStub,
                reqId, testCtx.logger, null, '/tdx/certification/v4/qe/identity');
            assert.equal(testCtx.nodeCache.setStub.callCount, 0);
            assert.equal(testCtx.logger.info.callCount, 0);
        });
    });
});
