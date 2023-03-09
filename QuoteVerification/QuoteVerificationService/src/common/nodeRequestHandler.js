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
const Buffer = require('safe-buffer').Buffer;

const jsonUtils = require('../util/jsonUtils');

/**
 * IntelliJ IDEA has long lasting bugs:
 * https://youtrack.jetbrains.com/issue/WEB-31971
 * https://youtrack.jetbrains.com/issue/WEB-52385
 * JSDoc import works for example in Visual Studio Code.
 *
 * @typedef {import('../jsDoc/types').KoaResponse} KoaResponse
 * @typedef {import('../jsDoc/types').Logger} Logger
 */

/**
 * Check if content is JSON
 *
 * @param {KoaResponse} res
 *
 * @returns {boolean}
 */
function isContentTypeJson(res) {
    if (res.headers && res.headers.hasOwnProperty('content-type')) {
        return res.headers['content-type'].startsWith('application/json');
    }
    return false;
}

/**
 * Create result
 *
 * @param {number} statusCode
 * @param {Object} headers
 * @param {Object} body
 *
 * @returns {{headers, body, statusCode}}
 */
function createResult(statusCode, headers, body) {
    return { statusCode, headers, body };
}

/**
 * @typedef {Object} NodeRequestOptions
 * @property {string[]} ca
 * @property {string} secureProtocol
 * @property {string} ciphers
 * @property {boolean} requestCert
 * @property {boolean} rejectUnauthorized
 * @property {boolean} strictSSL
 * @property {Object} agent
 * @property {string} protocol
 * @property {string} method
 * @property {string} host
 * @property {number} port
 * @property {string} path
 * @property {Object} headers
 */

const limit10MB = 1024 * 1024 * 10; // 10 MB

/**
 * Create node request
 * @param {NodeRequestOptions} options
 * @param {string} body
 * @param {boolean=} isResponseBinary - default false
 */
async function nodeRequest(options, body, isResponseBinary = false) {
    return new Promise((resolve, reject) => {
        const requestFunctionForSelectedProtocol = options.protocol === 'http:' ? http.request : https.request;
        const req = requestFunctionForSelectedProtocol(options, (res) => {
            let remainingLimit = limit10MB;
            if (res.headers && res.headers['content-length'] > remainingLimit) {
                // Calling this will cause remaining data in the response to be dropped and the socket to be destroyed.
                // Will emit error and close events.
                req.destroy(new Error(`Expected response size is too big. Rejected to download ${res.headers['content-length']} bytes`));
                return;
            }
            if (isResponseBinary) {
                let buffer = Buffer.from([]);
                res.on('data', (b) => {
                    remainingLimit -= b.length;
                    if (remainingLimit < 0) {
                        // Calling this will cause remaining data in the response to be dropped and the socket to be destroyed.
                        // Will emit error and close events.
                        req.destroy(new Error('Response size limit exceeded'));
                    }
                    buffer = Buffer.concat([buffer, b], buffer.length + b.length);
                });
                res.on('end', () => {
                    const result = createResult(res.statusCode, res.headers, buffer);
                    resolve(result);
                });
            }
            else {
                let data = '';
                res.on('data', (d) => {
                    remainingLimit -= d.length;
                    if (remainingLimit < 0) {
                        // Calling this will cause remaining data in the response to be dropped and the socket to be destroyed.
                        // Will emit error and close events.
                        req.destroy(new Error('Response size limit exceeded'));
                    }
                    data += d;
                });
                res.on('end', () => {
                    const result = isContentTypeJson(res) ?
                        createResult(res.statusCode, res.headers, jsonUtils.parse(data)) :
                        createResult(res.statusCode, res.headers, data);
                    resolve(result);
                });
            }
        });
        req.on('timeout', () => {
            req.destroy();
        });
        req.on('error', (err) => {
            reject(err);
        });
        if (body) {
            if (body instanceof Uint8Array) {
                req.write(body);
            }
            else {
                req.write(JSON.stringify(body));
            }
        }
        req.end();
    });
}

module.exports = nodeRequest;
