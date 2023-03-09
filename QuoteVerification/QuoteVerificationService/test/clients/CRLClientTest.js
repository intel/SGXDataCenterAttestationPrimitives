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
          cache: {
              ttl:         900,
              checkPeriod: 60,
              maxKeys:     -1
          },
          crlClient: {
              retries:         3,
              initialInterval: 100,
              factor:          2
          }
      };
      this.configLoader = {
          getConfig: () => this.config
      };
      const restClient = {
          getRequestWithBinaryResponsePromised: sinon.stub()
      };
      this.RestClientMock = function construct(type, host, port, retryCount, retryDelay, factor, certFile, keyFile, caCertDirectories) {
          this.type = type;
          this.host = host;
          this.port = port;
          this.retryCount = retryCount;
          this.retryDelay = retryDelay;
          this.factor = factor;
          this.certFile = certFile;
          this.keyFile = keyFile;
          this.caCertDirectories = caCertDirectories;

          this.getRequestWithBinaryResponsePromised = restClient.getRequestWithBinaryResponsePromised;
      };
      this.restClient = restClient;
      this.logger = {
          info: sinon.stub(),
          warn: sinon.stub()
      };
      const nodeCache = {
            crls: {
                getStub: sinon.stub(),
                setStub: sinon.stub()
            },
            clients: {
                getStub: sinon.stub(),
                setStub: sinon.stub()
            }
      };
      this.NodeCacheMock = function construct(config) {
          assert.equal(typeof config.stdTTL, 'number');
          assert.equal(typeof config.checkperiod, 'number');
          assert.equal(typeof config.maxKeys, 'number');

          if (config.stdTTL === 0) {    // Any way to differentiate
            this.get = nodeCache.clients.getStub;
            this.set = nodeCache.clients.setStub;
          }
          else {
            this.get = nodeCache.crls.getStub;
            this.set = nodeCache.crls.setStub;
          }
         
      };
      this.nodeCache = nodeCache;
  }

  async getTarget() {
      return proxyquire('../../src/clients/crlAccessLayer/CRLClient', {
          '../../configLoader':      this.configLoader,
          '../../common/RestClient': this.RestClientMock,
          'node-cache':              this.NodeCacheMock
      });
  }
}

describe('PCSClient tests', () => {

  describe('getCrlFromDistributionPoint call', () => {

    it('response already cached', async() => {
        // GIVEN
        const testCtx = new TestContext();
        const reqId = 'requestId';
        const distributionPoint = 'https://localhost:1234/CRL.crl?encoding=pem';
        const mockedResponse = { status: 200, body: Buffer.from('CRL'), headers: ['header'] };
        testCtx.nodeCache.crls.getStub.returns(mockedResponse);
        const target = await testCtx.getTarget();
        // WHEN
        const response = await target.getCrlFromDistributionPoint(distributionPoint, reqId, testCtx.logger);
        // THEN
        assert.deepStrictEqual(response, mockedResponse);
        assert.strictEqual(testCtx.nodeCache.crls.getStub.args[0][0], distributionPoint);
        assert.strictEqual(testCtx.logger.info.callCount, 1);
        helpers.assertMockFirstCalledWithArgs(testCtx.logger.info, 'CRL taken from cache instead of ' + distributionPoint);
    });

    it('response saved to cache', async() => {
        // GIVEN
        const testCtx = new TestContext();
        const reqId = 'requestId';
        const distributionPoint = 'https://localhost:1234/CRL.crl?encoding=pem';
        const mockedResponse = { status: 200, body: Buffer.from('CRL'), headers: ['header'] };
        testCtx.restClient.getRequestWithBinaryResponsePromised.resolves(mockedResponse);
        const target = await testCtx.getTarget();
        // WHEN
        const response = await target.getCrlFromDistributionPoint(distributionPoint, reqId, testCtx.logger);
        // THEN
        assert.deepStrictEqual(response, mockedResponse);
        helpers.assertMockFirstCalledWithArgs(testCtx.restClient.getRequestWithBinaryResponsePromised,
            reqId, testCtx.logger, null, '/CRL.crl', {}, { encoding: 'pem' });
        helpers.assertMockFirstCalledWithArgs(testCtx.nodeCache.crls.setStub, distributionPoint, mockedResponse);
        assert.strictEqual(testCtx.logger.info.callCount, 3);
        helpers.assertMockCalledWithArgs(2, testCtx.logger.info, 'Cached CRL downloaded from: ' + distributionPoint);
    });

    it('error thrown', async() => {
        // GIVEN
        const testCtx = new TestContext();
        const reqId = 'requestId';
        const distributionPoint = 'https://localhost:1234/CRL.crl?encoding=pem';
        const error = new Error('Error');
        testCtx.restClient.getRequestWithBinaryResponsePromised.rejects(error);
        const target = await testCtx.getTarget();
        // WHEN
        const response = await target.getCrlFromDistributionPoint(distributionPoint, reqId, testCtx.logger);
        // THEN
        assert.deepStrictEqual(response, error);
        helpers.assertMockFirstCalledWithArgs(testCtx.restClient.getRequestWithBinaryResponsePromised,
            reqId, testCtx.logger, null, '/CRL.crl', {}, { encoding: 'pem' });        
        assert.strictEqual(testCtx.nodeCache.crls.setStub.callCount, 0);
        assert.strictEqual(testCtx.logger.warn.callCount, 0);
        assert.strictEqual(testCtx.logger.info.callCount, 2);
    });

    it('client already cached', async() => {
        // GIVEN
        const testCtx = new TestContext();
        const reqId = 'requestId';
        const distributionPoint = 'https://localhost:1234/CRL.crl?encoding=pem';
        const mockedResponse = { status: 200, body: Buffer.from('CRL'), headers: ['header'] };
        testCtx.restClient.getRequestWithBinaryResponsePromised.resolves(mockedResponse);
        testCtx.nodeCache.clients.getStub.returns(testCtx.restClient);
        const target = await testCtx.getTarget();
        // WHEN
        const response = await target.getCrlFromDistributionPoint(distributionPoint, reqId, testCtx.logger);
        // THEN
        assert.deepStrictEqual(response, mockedResponse);        
        assert.strictEqual(testCtx.nodeCache.crls.getStub.args[0][0], distributionPoint);
        assert.strictEqual(testCtx.nodeCache.clients.setStub.callCount, 0);
        assert.strictEqual(testCtx.logger.info.args[0][0].startsWith('Creating RestClient for host'), false);
    });

    it('no port provided - 443 by default', async() => {
        // GIVEN
        const testCtx = new TestContext();
        const reqId = 'requestId';
        const distributionPoint = 'https://localhost/CRL.crl?encoding=pem';
        const mockedResponse = { status: 200, body: Buffer.from('CRL'), headers: ['header'] };
        testCtx.restClient.getRequestWithBinaryResponsePromised.resolves(mockedResponse);
        const target = await testCtx.getTarget();
        // WHEN
        const response = await target.getCrlFromDistributionPoint(distributionPoint, reqId, testCtx.logger);
        // THEN
        assert.deepStrictEqual(response, mockedResponse);
        helpers.assertMockFirstCalledWithArgs(testCtx.restClient.getRequestWithBinaryResponsePromised,
            reqId, testCtx.logger, null, '/CRL.crl', {}, { encoding: 'pem' });
        helpers.assertMockFirstCalledWithArgs(testCtx.nodeCache.crls.setStub, distributionPoint, mockedResponse);
        assert.strictEqual(testCtx.logger.info.callCount, 3);
        helpers.assertMockCalledWithArgs(2, testCtx.logger.info, 'Cached CRL downloaded from: ' + distributionPoint);
        assert.strictEqual(testCtx.nodeCache.clients.setStub.args[0][1].port, 443);
    });

    it('CRL cache turned off', async() => {
        // GIVEN
        const testCtx = new TestContext();
        const reqId = 'requestId';
        const distributionPoint = 'https://localhost/CRL.crl?encoding=pem';
        const mockedResponse = { status: 200, body: Buffer.from('CRL'), headers: ['header'] };
        testCtx.restClient.getRequestWithBinaryResponsePromised.resolves(mockedResponse);
        testCtx.config.cache.maxKeys = 0;
        const target = await testCtx.getTarget();
        // WHEN
        const response = await target.getCrlFromDistributionPoint(distributionPoint, reqId, testCtx.logger);
        // THEN
        assert.deepStrictEqual(response, mockedResponse);
        helpers.assertMockFirstCalledWithArgs(testCtx.restClient.getRequestWithBinaryResponsePromised,
            reqId, testCtx.logger, null, '/CRL.crl', {}, { encoding: 'pem' });
        assert.strictEqual(testCtx.nodeCache.crls.setStub.callCount, 0);
        assert.strictEqual(testCtx.logger.info.callCount, 2);
    });

    it('saving rest client in cache fails - just a warning', async() => {
        // GIVEN
        const testCtx = new TestContext();
        const reqId = 'requestId';
        const distributionPoint = 'https://localhost:1234/CRL.crl?encoding=pem';
        const mockedResponse = { status: 200, body: Buffer.from('CRL'), headers: ['header'] };
        testCtx.restClient.getRequestWithBinaryResponsePromised.resolves(mockedResponse);
        const error = new Error('Problem with cache');
        testCtx.nodeCache.clients.setStub.throws(error);
        const target = await testCtx.getTarget();
        // WHEN
        const response = await target.getCrlFromDistributionPoint(distributionPoint, reqId, testCtx.logger);
        // THEN
        assert.deepStrictEqual(response, mockedResponse);
        helpers.assertMockFirstCalledWithArgs(testCtx.restClient.getRequestWithBinaryResponsePromised,
            reqId, testCtx.logger, null, '/CRL.crl', {}, { encoding: 'pem' });
        assert.strictEqual(testCtx.logger.warn.callCount, 1);
        helpers.assertMockFirstCalledWithArgs(testCtx.logger.warn, 'Problem with clients cache: Error: Problem with cache');
    });

    it('saving CRL in cache fails - just a warning', async() => {
        // GIVEN
        const testCtx = new TestContext();
        const reqId = 'requestId';
        const distributionPoint = 'https://localhost:1234/CRL.crl?encoding=pem';
        const mockedResponse = { status: 200, body: Buffer.from('CRL'), headers: ['header'] };
        testCtx.restClient.getRequestWithBinaryResponsePromised.resolves(mockedResponse);
        const error = new Error('Problem with cache');
        testCtx.nodeCache.crls.setStub.throws(error);
        const target = await testCtx.getTarget();
        // WHEN
        const response = await target.getCrlFromDistributionPoint(distributionPoint, reqId, testCtx.logger);
        // THEN
        assert.deepStrictEqual(response, mockedResponse);
        helpers.assertMockFirstCalledWithArgs(testCtx.restClient.getRequestWithBinaryResponsePromised,
            reqId, testCtx.logger, null, '/CRL.crl', {}, { encoding: 'pem' });
        assert.strictEqual(testCtx.logger.warn.callCount, 1);
        helpers.assertMockFirstCalledWithArgs(testCtx.logger.warn, 'Problem with CRLs cache: Error: Problem with cache');
    });

  });

});
