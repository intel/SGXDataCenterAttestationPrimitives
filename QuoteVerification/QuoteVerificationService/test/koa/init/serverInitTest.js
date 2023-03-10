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

const assertMockFirstCalledWithArgs = require('../../mocks/helpers').assertMockFirstCalledWithArgs;

class KoaMock {
    constructor() {
        this.context = {};
    }

    use() {}

    callback() {}
}

class TestContext {
    constructor() {
        this.logger = {
            info:  sinon.stub(),
            warn:  sinon.stub(),
            error: sinon.stub()
        };
        this.httpsServer = {
            listen: sinon.stub(),
            on:     (event, callback) => callback(),
        };
        this.https = {
            createServer: sinon.stub().returns(this.httpsServer),
        };
        this.httpServer = {
            listen: sinon.stub(),
            on:     (event, callback) => callback(),
        };
        this.router = {
            routes:         sinon.stub(),
            allowedMethods: sinon.stub()
        };
        this.http = {
            createServer: sinon.stub().returns(this.httpServer)
        };
        this.session = sinon.stub();
        this.serviceName = 'serviceName';
        this.port = 999;
        this.readFileSafely = sinon.stub();

        this.getCACertificatesSyncMock = sinon.stub().returns(['file1, file2']);
    }

    getOptions(options) {
        return {
            serviceName:   this.serviceName,
            logger:        this.logger,
            middlewares:   [sinon.stub(), sinon.stub()],
            serviceConfig: {
                tlsServerType:     options.serverType,
                keyFile:           'file.key',
                certFile:          'file.crt',
                caCertDirectories: [],
            }
        };
    }

    async getTarget() {
        return proxyquire('../../../src/koa/init/serverInit', {
            'https':                                 this.https,
            'http':                                  this.http,
            'koa':                                   KoaMock,
            '../../utilities/getCACertificatesSync': this.getCACertificatesSyncMock,
            '../../common/readFileSafely':           this.readFileSafely
        });
    }
}

describe('serverTest', () => {
    describe('https server - positive', () => {
        it('started with MTLS', async() => {
            // GIVEN
            const c = new TestContext();
            const expLogInfo = `HTTPS server started on port ${c.port}!`;
            const initServer = await c.getTarget();

            // WHEN
            const ctx = new initServer(c.getOptions({ serverType: 'MTLS' }));
            await ctx.startHTTPSServer(c.port, c.router);

            // THEN
            assert(c.https.createServer.calledOnce);
            assert(c.logger.info.calledOnce);
            assertMockFirstCalledWithArgs(c.logger.info, expLogInfo);
        });

        it('started with TLS', async() => {
            // GIVEN
            const c = new TestContext();
            const expLogInfo = `HTTPS server started on port ${c.port}!`;
            const initServer = await c.getTarget();

            // WHEN
            const ctx = new initServer(c.getOptions({ serverType: 'TLS' }));
            await ctx.startHTTPSServer(c.port, c.router);

            // THEN
            assert(c.https.createServer.calledOnce);
            assert(c.logger.info.calledOnce);
            assertMockFirstCalledWithArgs(c.logger.info, expLogInfo);
        });

        it('started', async() => {
            // GIVEN
            const c = new TestContext();
            const expLogInfo = `HTTP server started on port ${c.port}!`;
            const initServer = await c.getTarget();

            // WHEN
            const ctx = new initServer(c.getOptions({}));
            await ctx.startHTTPServer(c.port, c.router);

            // THEN
            assert(c.http.createServer.calledOnce);
            assert(c.logger.info.calledOnce);
            assertMockFirstCalledWithArgs(c.logger.info, expLogInfo);
        });
    });
});
