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

const axios = require('axios');

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
 * @property {?Object} httpAgent
 * @property {?Object} httpsAgent
 * @property {number} timeout
 * @property {string} method
 * @property {string} url
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
    const axiosOptions = {
        ...options,
        maxContentLength: limit10MB,
        maxBodyLength:    limit10MB,
        responseType:     isResponseBinary ? 'arraybuffer' : 'json',
    };
    if (body) {
        axiosOptions.data = body;
    }
    try {
        const response = await axios(axiosOptions);
        return createResult(response.status, response.headers, response.data);
    }
    catch (error) {
        const response = error.response;
        if (response) {
            return createResult(response.status, response.headers, response.data);
        }
        throw error;
    }
}

module.exports = nodeRequest;
