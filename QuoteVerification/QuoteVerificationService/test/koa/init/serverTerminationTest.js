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
const http = require('http');
const https = require('https');

const assertMockCalledWithArgs = require('../../mocks/helpers').assertMockCalledWithArgs;

const EventEmitter = require('events');

class ProcessMock extends EventEmitter {
    exit(code) {
        this.emit('exit', code);
    }
}

class KoaMock {
    constructor() {
        this.context = {};
    }

    use() {}

    callback() {}
}

class HttpServerStub {
    constructor() {
        // HTTP server
        this._server = undefined;
        this.listenStub = undefined;
        this.closeStub = undefined;
    }

    createServer() {
        this._server = http.createServer((req, res) => {
            res.writeHead(200);
            res.end('Server mock');
        });
        this.listenStub = sinon.stub(this._server, 'listen').callsFake(() => this._server.emit('listening'));
        this.closeStub = sinon.stub(this._server, 'close').callsFake(closeCallback => closeCallback(undefined)); // undefined = no error
        return this._server;
    }
}

class HttpsServerStub {
    constructor() {
        // HTTPS server
        this._server = undefined;
        this.listenStub = undefined;
        this.closeStub = undefined;
    }

    createServer() {
        this._server = https.createServer((req, res) => {
            res.writeHead(200);
            res.end('Server mock');
        });
        this.listenStub = sinon.stub(this._server, 'listen').callsFake(() => this._server.emit('listening'));
        this.closeStub = sinon.stub(this._server, 'close').callsFake(closeCallback => closeCallback(undefined)); // undefined = no error
        return this._server;
    }
}

class TestContext {
    constructor() {
        this.httpServerStub = new HttpServerStub();
        this.httpsServerStub = new HttpsServerStub();

        this.processMock = new ProcessMock();
        this.processExitSpy = sinon.spy(this.processMock, 'exit');
        this.processOnSpy = sinon.spy(this.processMock, 'on');

        this.logger = {
            info:  sinon.stub(),
            warn:  sinon.stub(),
            error: sinon.stub()
        };

        this._router = {
            routes:         sinon.stub(),
            allowedMethods: sinon.stub()
        };

        this._httpPort = '9999';
        this._httpsPort = '9998';
    }

    async _getTarget() {
        return proxyquire('../../../src/koa/init/serverInit', {
            'http': {
                createServer: () => this.httpServerStub.createServer()
            },
            'https': {
                createServer: () => this.httpsServerStub.createServer()
            },
            'process':                               this.processMock,
            'koa':                                   KoaMock,
            '../../utilities/getCACertificatesSync': sinon.stub().returns(['file1, file2']),
            '../../common/readFileSafely':           sinon.stub()
        });
    }

    _getOptions(isHttps) {
        return {
            serviceName:   'serviceName',
            logger:        this.logger,
            middlewares:   [sinon.stub(), sinon.stub()],
            serviceConfig: {
                tlsServerType:     isHttps ? 'TLS' : undefined,
                keyFile:           'file.key',
                certFile:          'file.crt',
                caCertDirectories: [],
            }
        };
    }

    async startServerHTTP() {
        const isHttps = false;
        const ServerInit = await this._getTarget();
        const ctx = new ServerInit(this._getOptions(isHttps));
        await ctx.startHTTPServer(this._httpPort, this._router);
        sinon.assert.calledOnce(this.httpServerStub.listenStub);
    }

    async startServerHTTPS() {
        const isHttps = true;
        const ServerInit = await this._getTarget();
        const ctx = new ServerInit(this._getOptions(isHttps));
        await ctx.startHTTPSServer(this._httpsPort, this._router);
        sinon.assert.calledOnce(this.httpsServerStub.listenStub);
    }
}

describe('serverTerminationTest', () => {

    let testContext;
    const itSleep = 10; // ms
    const signalsToTest = ['SIGINT', 'SIGTERM'];

    describe('http', () => {
        beforeEach(async() => {
            testContext = new TestContext();
            await testContext.startServerHTTP();
        });

        signalsToTest.forEach(signal => {
            it(signal, (done) => {
                // THEN
                testContext.processMock.once(signal, () => {
                    setTimeout(() => {
                        sinon.assert.calledOnce(testContext.httpServerStub.closeStub);
                        sinon.assert.calledOnce(testContext.processExitSpy);
                        sinon.assert.calledWithExactly(testContext.processExitSpy, 0);
                        done();
                    }, itSleep);
                });

                // WHEN
                testContext.processMock.emit(signal);
            });
        });
    });

    describe('https', () => {
        beforeEach(async() => {
            testContext = new TestContext();
            await testContext.startServerHTTPS();
        });

        signalsToTest.forEach(signal => {
            it(signal, (done) => {
                // THEN
                testContext.processMock.once(signal, () => {
                    setTimeout(() => {
                        sinon.assert.calledOnce(testContext.httpsServerStub.closeStub);
                        sinon.assert.calledOnce(testContext.processExitSpy);
                        sinon.assert.calledWithExactly(testContext.processExitSpy, 0);
                        done();
                    }, itSleep);
                });

                // WHEN
                testContext.processMock.emit(signal);
            });
        });
    });

    describe('both = http + https', () => {
        beforeEach(async() => {
            testContext = new TestContext();
            await testContext.startServerHTTP();
            await testContext.startServerHTTPS();
        });

        signalsToTest.forEach(signal => {
            it(signal, (done) => {
                // THEN
                testContext.processMock.once(signal, () => {
                    setTimeout(() => {
                        sinon.assert.calledOnce(testContext.httpServerStub.closeStub);
                        sinon.assert.calledOnce(testContext.httpsServerStub.closeStub);
                        sinon.assert.calledTwice(testContext.processExitSpy); // FIXME: no idea why it is not called once
                        const expectedExitCode = 0;
                        assertMockCalledWithArgs(0, testContext.processExitSpy, expectedExitCode);
                        assertMockCalledWithArgs(1, testContext.processExitSpy, expectedExitCode);
                        done();
                    }, itSleep);
                });

                // WHEN
                testContext.processMock.emit(signal);
            });
        });
    });

});
