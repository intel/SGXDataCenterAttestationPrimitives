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

const http = require('http');
const https = require('https');

const config = require('../configLoader').getConfig();

const HttpsProxyAgent = require('https-proxy-agent');

const RequestHandler = require('./requestHandler');
const getCACertificatesSync = require('./getCACertificatesSync');
const tlsType = require('./tlsType');
const readFileSafely = require('../common/readFileSafely');

class RestClient {

    constructor(type, host, port, retryCount, retryDelay, factor, certFile, keyFile, caCertDirectories, proxy, servername) {
        this.cfg = {
            address:  'None', // Placeholder, will be populated with first request
            protocol: (type === tlsType.None) ? 'http' : 'https',
            host,
            port,
            retryCount,
            retryDelay,
            factor,
            proxy,
            servername
        };
        this.prepareOptions(type, certFile, keyFile, caCertDirectories);
        this.initializeRequestHandler();
    }

    prepareOptions(type, certFile, keyFile, caCertDirectories) {
        const ca = getCACertificatesSync(caCertDirectories).map(file => readFileSafely(file, 'utf8'));

        this.agentOptions = {
            keepAlive:  true,
            timeout:    config.service.restClientTimeout,
            scheduling: 'lifo',
        };

        const proxy = this.cfg.proxy;
        let agent;
        if (proxy) {
            agent = new HttpsProxyAgent(proxy);
        }
        else {
            agent = (type === tlsType.None) ? new http.Agent(this.agentOptions) : new https.Agent(this.agentOptions);
        }

        const options = {
            ca,
            maxVersion:         tlsType.MAX_SECURE_PROTOCOL,
            minVersion:         tlsType.MIN_SECURE_PROTOCOL,
            ciphers:            tlsType.CIPHERS,
            requestCert:        type === tlsType.MTLS,
            rejectUnauthorized: type === tlsType.MTLS,
            strictSSL:          true,
            agent
        };

        if (type === tlsType.MTLS) {
            options.cert = readFileSafely(certFile, 'utf8');
            options.key = readFileSafely(keyFile, 'utf8');
            options.servername = this.cfg.servername;
        }

        this.cfg.options = options;
    }

    initializeRequestHandler() {
        this.requestHandler = new RequestHandler(this.cfg);
    }

    async requestPromised(logger, method, path, body, requestId, headers, queryParams, isResponseBinary = false) {
        headers['Request-ID'] = requestId;
        headers['Content-Type'] = 'application/json';

        return this.requestHandler.sendRequestWithRetries(logger, method, path, body, headers, queryParams, isResponseBinary);
    }

    async requestPromisedOctetStream(logger, method, path, body, requestId, headers, queryParams) {
        headers['Request-ID'] = requestId;
        headers['Content-Type'] = 'application/octet-stream';

        return this.requestHandler.sendRequestWithRetries(logger, method, path, body, headers, queryParams);
    }

    async health(logger, headers) {
        return this.requestHandler.sendRequest(logger, 'GET', '/health', '', headers, undefined);
    }

    async healthWithRetry(logger, headers) {
        return this.requestHandler.sendRequestWithRetriesOnConnectionReset(logger, 'GET', '/health', '', headers, undefined);
    }

    async getRequestPromised(requestId, logger, body, path, headers = {}, queryParams = {}) {
        return this.requestPromised(logger, 'GET', path, body, requestId, headers, queryParams);
    }

    async getRequestWithBinaryResponsePromised(requestId, logger, body, path, headers = {}, queryParams = {}) {
        return this.requestPromised(logger, 'GET', path, body, requestId, headers, queryParams, true);
    }

    async postOctetStreamRequestPromised(requestId, logger, body, path, headers = {}, queryParams = {}) {
        return this.requestPromisedOctetStream(logger, 'POST', path, body, requestId, headers, queryParams);
    }

    async postRequestPromised(requestId, logger, body, path, headers = {}, queryParams = {}, isResponseBinary = false) {
        return this.requestPromised(logger, 'POST', path, body, requestId, headers, queryParams, isResponseBinary);
    }

    async putRequestPromised(requestId, logger, body, path, headers = {}, queryParams = {}) {
        return this.requestPromised(logger, 'PUT', path, body, requestId, headers, queryParams);
    }
}

module.exports = RestClient;
