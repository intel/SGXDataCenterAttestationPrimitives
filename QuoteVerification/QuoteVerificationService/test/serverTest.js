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
            logger: {
                levelFile:    'trace',
                levelConsole: 'off',
                fileName:     'qvs.log',
                category:     'qvs'
            },
            service: {
                port:              8799,
                certFile:          '',
                keyFile:           '',
                caCertDirectories: [''],
                tlsServerType:     'TLS',
                bodySizeLimits:    {
                    json: '256kb'
                }
            },
            healthCheck: { extraHttpPort: 8798 }
        };

        this.configLoader = {
            getConfig: () => this.config
        };

        this.routes = sinon.stub();

        this.healthRoutes = {
            createRouter: () => {
                return { routes: () => { return () => {}; } };
            }
        };

        this.HealthCache = {
            run: sinon.stub()
        };

        this.process = {
            on:   sinon.stub(),
            exit: sinon.stub()
        };

        this.version = {
            version: 'UNDEFINED'
        };


        this.init = sinon.stub();
        this.init.prototype.startHTTPServer = sinon.stub();
        this.init.prototype.startHTTPSServer = sinon.stub();
    }

    async getTarget() {
        this.logger = proxyquire('../src/logger', {
            './config': this.config
        });
        return proxyquire('../src/server', {
            'process':               this.process,
            './configLoader':        this.configLoader,
            './logger':              this.logger,
            './healthChecker':       this.HealthCache,
            '../version':            this.version,
            './routes':              this.routes,
            './routes/health':       this.healthRoutes,
            './koa/init/serverInit': this.init
        });
    }
}

describe('serverTest', () => {

    describe('positive', () => {
        it('both https and http server started', async() => {
            // GIVEN
            const c = new TestContext();
            // WHEN
            await c.getTarget();
            // THEN
            assert(c.init.prototype.startHTTPServer.notCalled);
            assert(c.init.prototype.startHTTPSServer.calledOnce);
            assert(c.HealthCache.run.calledOnce);
        });

        it('without http healthcheck, only https', async() => {
            // GIVEN
            const c = new TestContext();
            // WHEN
            c.config.healthCheck = {};
            await c.getTarget();
            // THEN
            assert(c.init.prototype.startHTTPSServer.calledOnce);
            assert(c.init.prototype.startHTTPServer.notCalled);
            assert(c.HealthCache.run.calledOnce);
        });
    });

    describe('negative', () => {
        it('no key or cert available', async() => {
            // GIVEN
            const c = new TestContext();
            c.init.prototype.startHTTPSServer.throws('fatal error');
            // WHEN
            await c.getTarget();
            // THEN
            assert(c.init.prototype.startHTTPSServer.calledOnce);
            assert(c.init.prototype.startHTTPServer.notCalled);
            assert(c.HealthCache.run.notCalled);
        });
    });
});
