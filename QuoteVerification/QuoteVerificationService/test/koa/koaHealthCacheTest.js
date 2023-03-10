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

const HealthCache = require('../../src/koa/koaHealthCache');
const proxyquire = require('proxyquire').noCallThru().noPreserveCache();
const _ = require('lodash');
const assert = require('assert');
const sinon = require('sinon');
const { assertMockCalledWithArgs, assertMockCalledOnceWithArgs } = require('../mocks/helpers');


const {
    STATUS_OK,
    STATUS_NOT_FOUND,
    STATUS_SERVICE_UNAVAILABLE
} = require('../../src/koa/response').STATUSES;

class TestContext {
    constructor(input) {

        if (!input) {
            input = {
                stripResult: {}
            };
        }

        this.logger = {
            trace:  sinon.stub(),
            debug:  sinon.stub(),
            info:   sinon.stub(),
            warn:   sinon.stub(),
            error:  sinon.stub(),
            scoped: null
        };
        this.logger.scoped = sinon.stub().returns(this.logger);
        this.defaultOptions = {
            frequencyMS: 100,
            validityMS:  5000,
            version:     '999.9',
            logger:      this.logger
        };
        this.healthCondition = (status) => {
            return async(logger, reqId, callback) => {
                callback(null, { status });
            };
        };

        this.utilMock = {
            promisify: sinon.stub().returns(sinon.stub().resolves(input.stripResult))
        };

        this.statusFailed = 'FAILED';
        this.statusUnknown = 'UNKNOWN';
        this.NA = 'NA';
    }

    getCtx() {
        return {
            log:    this.logger,
            status: STATUS_NOT_FOUND,
            body:   {},
            set:    sinon.stub(),
            assert: () => {}
        };
    }

    getTarget(options) {
        const modifiedDefaultOptions = _.extend(this.defaultOptions, options);
        const HealthCache = proxyquire('../../src/koa/koaHealthCache', {
            util: this.utilMock,
        });

        return new HealthCache(modifiedDefaultOptions);
    }
}

describe('healthCacheTests', () => {
    describe('healthcheck all components', () => {
        it('should throw error when component with given name already exists', () => {
            // GIVEN
            const c = new TestContext();
            const healthCache = c.getTarget();
            healthCache.addComponentHealthCondition('component', c.healthCondition('OK'));

            const addComponentStep = () => {
                // WHEN
                healthCache.addComponentHealthCondition('component', c.healthCondition('OK'));
            };

            const errorContainsHealthCheckFormatError = (error) => {
                // THEN
                const expectedMessage = 'componentName should be unique';
                return error.message.indexOf(expectedMessage) >= 0;
            };

            assert.throws(addComponentStep, errorContainsHealthCheckFormatError);
        });
    });

    it('logger is mandatory', () => {
        // GIVEN
        const c = new TestContext();

        // WHEN
        const action = () => { c.getTarget({ logger: undefined }); };

        // THEN
        assert.throws(action);
    });

    it('constructor should throw error when no parameters passed', () => {
        const action = () => {
            //WHEN
            return new HealthCache();
        };

        //THEN
        assert.throws(action, Error);
    });

    it('addComponentHealthCondition should throw error when wrong component format given', () => {
        //GIVEN
        const c = new TestContext();
        const healthCache = c.getTarget();

        const addComponentStep = () => {
            //WHEN
            healthCache.addComponentHealthCondition();
        };

        const errorContainsComponentFormatError = (error) => {
            //THEN
            const expectedMessage = 'componentName should be a string';
            return error.message.indexOf(expectedMessage) >= 0;
        };

        assert.throws(addComponentStep, errorContainsComponentFormatError);
    });

    it('addComponentHealthCondition should throw error when wrong component health check format given', () => {
        //GIVEN
        const c = new TestContext();
        const healthCache = c.getTarget();

        const addComponentStep = () => {
            //WHEN
            healthCache.addComponentHealthCondition('componentName', 'notAFunction');
        };

        const errorContainsHealthCheckFormatError = (error) => {
            // THEN
            const expectedMessage = 'componentHealthCheck should be a function';
            return error.message.indexOf(expectedMessage) >= 0;
        };

        assert.throws(addComponentStep, errorContainsHealthCheckFormatError);
    });

    it('handleRequest, should return STATUS_OK when params is present', (done) => {
        // GIVEN
        const stripResult = {
            status:          STATUS_OK.name,
            version:         '1',
            componentStatus: STATUS_OK.httpCode,
            details:         'details'
        };
        const c = new TestContext({ stripResult });
        const ctx = c.getCtx();
        ctx.params = {
            component: 'this'
        };
        const healthCache = c.getTarget({ details: 'details' });

        // WHEN
        healthCache.addComponentHealthCondition('this', () => {});
        healthCache.run();


        setTimeout(() => {
            healthCache.handleRequest(ctx);
            healthCache.stop();

            // THEN
            assert.deepStrictEqual(ctx.status, STATUS_OK.httpCode);
            assert.deepStrictEqual(ctx.body.status, STATUS_OK.name);
            assert.deepStrictEqual(ctx.body.version, c.defaultOptions.version);
            assert.deepStrictEqual(ctx.body.this.status, STATUS_OK.name);
            assert.deepStrictEqual(ctx.body.this.version, stripResult.version);
            done();
        }, 1);

    });

    it('handleRequest, should return OUTDATED when params is present AS', (done) => {
        // GIVEN
        const stripResult = {
            'status':                                 STATUS_OK.name,
            'version':                                '1',
            'componentStatus':                        STATUS_OK.httpCode,
            'details':                                'details',
            'X-IASReport-Signing-Certificate':        'X-IASReport-Signing-Certificate',
            'X-IASReport-Signing-Certificate-Status': 'X-IASReport-Signing-Certificate-Status'
        };
        const c = new TestContext({ stripResult });
        const ctx = c.getCtx();
        ctx.params = {
            component: 'AttestationService'
        };
        const healthCache = c.getTarget({ details: 'details', validityMS: 1 });

        // WHEN
        healthCache.addComponentHealthCondition('this', () => {});
        healthCache.addComponentHealthCondition('AttestationService', () => {});
        healthCache.run();


        setTimeout(() => {
            healthCache.handleRequest(ctx);
            healthCache.stop();

            // THEN
            assert.deepStrictEqual(ctx.status, STATUS_OK.httpCode);
            assert.deepStrictEqual(ctx.body.AttestationService.status, 'OUTDATED');
            assert.deepStrictEqual(ctx.body.AttestationService['X-IASReport-Signing-Certificate-Status'], undefined);
            assert.deepStrictEqual(ctx.body.AttestationService['X-IASReport-Signing-Certificate'], undefined);
            assert.deepStrictEqual(ctx.set.called, false);
            done();
        }, 100);

    });

    it('handleRequest, should return STATUS_OK when params is present AS', (done) => {
        // GIVEN
        const stripResult = {
            'status':                                 STATUS_OK.name,
            'version':                                '1',
            'componentStatus':                        STATUS_OK.httpCode,
            'details':                                'details',
            'X-IASReport-Signing-Certificate':        'Certificate',
            'X-IASReport-Signing-Certificate-Status': 'cert_status'
        };
        const c = new TestContext({ stripResult });
        const ctx = c.getCtx();
        ctx.params = {
            component: 'AttestationService'
        };
        const healthCache = c.getTarget({ details: 'details' });

        // WHEN
        healthCache.addComponentHealthCondition('this', () => {});
        healthCache.addComponentHealthCondition('AttestationService', () => {});
        healthCache.run();


        setTimeout(() => {
            healthCache.handleRequest(ctx);
            healthCache.stop();

            // THEN
            assert.deepStrictEqual(ctx.status, STATUS_OK.httpCode);
            assert.deepStrictEqual(ctx.body.AttestationService.status, STATUS_OK.name);
            assert.deepStrictEqual(ctx.body.AttestationService['X-IASReport-Signing-Certificate-Status'], 'cert_status');
            assert.deepStrictEqual(ctx.body.AttestationService['X-IASReport-Signing-Certificate'], undefined);
            assertMockCalledOnceWithArgs(ctx.set, 'X-IASReport-Signing-Certificate', 'Certificate');
            done();
        }, 1);

    });


    it('handleRequest, should return STATUS_SERVICE_UNAVAILABLE when params is not present', (done) => {
        // GIVEN
        const c = new TestContext();
        const ctx = c.getCtx();

        const healthCache = c.getTarget({ details: 'details' });

        // WHEN
        healthCache.addComponentHealthCondition('this', () => {});
        healthCache.run();

        setTimeout(() => {
            healthCache.handleRequest(ctx);
            healthCache.stop();

            // THEN
            assert.deepStrictEqual(ctx.status, STATUS_SERVICE_UNAVAILABLE.httpCode);
            assert.deepStrictEqual(ctx.body.status, c.statusFailed);
            assert.deepStrictEqual(ctx.body.version, c.NA);
            assert.deepStrictEqual(ctx.body.this, undefined);
            done();
        }, 1);
    });

    it('handleRequest, should return STATUS_SERVICE_UNAVAILABLE when stripResult is undefined', (done) => {
        // GIVEN
        const c = new TestContext({ stripResult: undefined });
        const ctx = c.getCtx();
        const healthCache = c.getTarget();

        // WHEN
        healthCache.addComponentHealthCondition('component', () => {});
        healthCache.run();
        setTimeout(() => {
            healthCache.handleRequest(ctx);
            healthCache.stop();

            // THEN
            assert.deepStrictEqual(ctx.status, STATUS_SERVICE_UNAVAILABLE.httpCode);
            assert.deepStrictEqual(ctx.body.status, c.statusFailed);
            assert.deepStrictEqual(ctx.body.version, c.defaultOptions.version);
            assert.deepStrictEqual(ctx.body.componentStatus.component.status, c.statusUnknown);
            assert.deepStrictEqual(ctx.body.componentStatus.component.version, c.NA);
            done();
        }, 1);
    });

    it('run, positive', () => {
        // GIVEN
        const c = new TestContext();
        const expInfoMsg = ['healthCache starting...', 'healthCache started.'];
        const healthCache = c.getTarget();

        // WHEN
        healthCache.addComponentHealthCondition('component', () => {});
        healthCache.run();
        healthCache.stop();


        // THEN
        assertMockCalledWithArgs(4, c.logger.info, expInfoMsg[0]);
        assertMockCalledWithArgs(5, c.logger.info, expInfoMsg[1]);
    });

    it('stop, positive', () => {
        // GIVEN
        const c = new TestContext();
        const expInfoMsg = ['healthCache stopping...', 'healthCache stopped.'];
        const healthCache = c.getTarget();
        healthCache.addComponentHealthCondition('component', () => {});

        // WHEN
        healthCache.stop();

        // THEN
        assertMockCalledWithArgs(4, c.logger.info, expInfoMsg[0]);
        assertMockCalledWithArgs(5, c.logger.info, expInfoMsg[1]);
    });

    it('should return default value when frequencyMs is negative', () => {
        // GIVEN
        const c = new TestContext();
        const options = {
            frequencyMS: -100,
            logger:      c.logger
        };
        const frequnecyMsDefault = 5000;

        // WHEN
        HealthCache(options);

        // THEN
        assert.deepStrictEqual(options.frequencyMS, frequnecyMsDefault);
    });

});
