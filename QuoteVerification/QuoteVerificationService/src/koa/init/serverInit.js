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


const process = require('process');
const Promise = require('bluebird');
const Koa = require('koa');
const https = require('https');
const http = require('http');
const tlsType = require('../../common/tlsType');

const getCACertificatesSync = require('../../common/getCACertificatesSync');
const configureCtxLoggerAndLogResponse = require('../middleware/configureCtxLoggerAndLogResponse');
const readFileSafely = require('../../common/readFileSafely');


/**
 * IntelliJ IDEA has long lasting bugs: 
 * https://youtrack.jetbrains.com/issue/WEB-31971
 * https://youtrack.jetbrains.com/issue/WEB-52385
 * JSDoc import works for example in Visual Studio Code.
 * 
 * @typedef {import('../../jsDoc/types').KoaApplication} KoaApplication
 * @typedef {import('../../jsDoc/types').Logger} Logger
 * @typedef {import('../../jsDoc/types').KoaRouter} KoaRouter
 */

/**
 * Initializes koa application middlewares used in each server
 * @returns {Promise<KoaApplication>} - preconfigured koa application
 */
/* eslint-disable no-invalid-this */
async function getPreconfiguredApp() {
    const app = new Koa();
    app.use(configureCtxLoggerAndLogResponse(this.logger));

    for (let i = 0; i < this.middlewares.length; i++) {
        app.use(this.middlewares[i]);
    }
    return app;
}

/**
 * @typedef {Object} ServerInitOptions
 * 
 * @property {string} serviceName - name of the service
 * @property {Array.<Function>} middleware - a list of middlewares
 * @property {Logger} logger - logger
 * @property {bool} validatorApp - if true use validator 
 */

module.exports = class ServerInit {
    /**
     * @param {ServerInitOptions} options - json with parameters:
     */
    constructor(options) {
        this.serviceName = options.serviceName;
        this.logger = options.logger;
        this.middlewares = options.middlewares;
        this.serviceConfig = options.serviceConfig;
        this.__servers = [];

        this.__setupProcessEvents();
    }

    __setupProcessEvents() {
        const closeGracefully = async(signal) => {
            this.logger.warn(`Received signal to terminate: ${signal}`);
            try {
                await this.closeAllServers();
                this.logger.info('Servers closed properly');
                process.exit(0);
            }
            catch (err) {
                this.logger.error('Error occurred while trying to close servers:', err);
                process.exit(1);
            }
        };

        process.on('SIGINT', closeGracefully);
        process.on('SIGTERM', closeGracefully);
        process.on('exit', (code) => {
            const exitMsg = `Exit process with code: ${code}`;
            (code === 0) ? this.logger.info(exitMsg) : this.logger.error(exitMsg);
        });
    }

    async __createHttpServer(app) {
        return http.createServer(app.callback());
    }

    async __createHttpsServer(app) {
        const isMtls = this.serviceConfig.tlsServerType === 'MTLS';
        const sslOptions = {
            key:                readFileSafely(this.serviceConfig.keyFile, 'utf8'),
            cert:               readFileSafely(this.serviceConfig.certFile, 'utf8'),
            ca:                 isMtls ? getCACertificatesSync(this.serviceConfig.caCertDirectories).map(file => readFileSafely(file, 'utf8')) : undefined,
            requestCert:        isMtls,
            rejectUnauthorized: isMtls,
            maxVersion:         tlsType.MAX_SECURE_PROTOCOL,
            minVersion:         tlsType.MIN_SECURE_PROTOCOL,
            ciphers:            tlsType.CIPHERS,
        };

        return https.createServer(sslOptions, app.callback());
    }

    /**
     * Starts HTTP/HTTPS server with service API
     * 
     * @param {number} port - port to listen on
     * @param {KoaRouter} router - koa-router instance
     * @param {string} serverType - HTTP or HTTPS
     *      
     */
    async __startServer(port, router, serverType) {
        const app = await getPreconfiguredApp.bind(this)();
        app.use(router.routes());
        app.use(router.allowedMethods());

        const createServerFn = async() => (serverType === 'HTTPS' ? this.__createHttpsServer(app) : this.__createHttpServer(app));
        const server = await createServerFn();

        // ELB timeout is 60s. General rule from internets to avoid 502/504: ELB timeout < keepAliveTimeout < headersTimeout
        server.keepAliveTimeout = 70000;
        server.headersTimeout = 80000;
        server.requestTimeout = 60000;
        return new Promise((resolve) => {
            server.on('listening', () => {
                this.__servers.push(server);
                this.logger.info(`${serverType} server started on port ${port}!`);
                resolve();
            });
            server.listen(port);
        });
    }

    /**
     * Starts HTTPS server with service API
     * 
     * @param {number} port - port to listen on
     * @param {KoaRouter} router - koa-router instance
     */
    async startHTTPSServer(port, router) {
        return this.__startServer(port, router, 'HTTPS');
    }

    /**
     * Starts plain HTTP server with only health endpoint available
     * 
     * @param {number} port - port to listen on
     * @param {KoaRouter} router - koa-router instance
     */
    async startHTTPServer(port, router) {
        return this.__startServer(port, router, 'HTTP');
    }

    async closeAllServers() {
        const closeAllPromises = this.__servers.map(server => new Promise((resolve, reject) => {
            server.close(err => {
                if (err) { reject(err); }
                resolve();
            });
        }));
        return Promise.all(closeAllPromises);
    }
};
