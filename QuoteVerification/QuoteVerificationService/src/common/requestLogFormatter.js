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

const util = require('util');
const _ = require('lodash');

const LENGTH_LIMIT = 15000;

/**
 * Formats a key-value pair with an optional prefix
 * 
 * @param {string} key
 * @param {Object} value
 * @param {string} prefix
 * 
 * @returns {string} returns (prefix)key=value
 */
function printableValue(key, value, prefix = '') {
    if (_.isNull(value) || _.isUndefined(value)) {
        return '';
    }
    else if (_.isObject(value) && !_.isEmpty(value)) {
        return util.format(`${prefix}${key}=%j`, value);
    }
    else if (_.isString(value)) {
        return `${prefix}${key}='${value}'`;
    }
    else {
        return '';
    }
}

/** Formats a string with request or response headers and/or body
 *
 * @param {Object} headers - headers as object
 * @param {Object} body - body as object or string
 */
function addHeadersAndBody(headers, body) {
    return util.format('[%s%s]',
        printableValue('headers', headers),
        printableValue('body', body, ' ')
    );
}

/** Formats a string with request or response header
 *
 * @param {string} reqMethod
 * @param {string} reqUrl
 * @param {Object} reqHeaders
 */
function formatRequestMessageWithoutBody(reqMethod, reqUrl, reqHeaders) {
    return util.format('  <-- request %s %s [%s]',
        reqMethod, reqUrl, printableValue('headers', reqHeaders));
}

/**
 * Formats a string with request body
 * 
 * @param {*} reqBody
 */
function formatRequestBodyMessage(reqBody) {
    const body = printableValue('body', reqBody);
    return body ? util.format('      [%s]', body) : '';
}

/** Formats a string with request or response headers and/or body
 *
 * @param {string} reqMethod
 * @param {string} reqUrl
 * @param {number} resStatus
 * @param {Object|string} resHeaders
 * @param {Object|string} resBody
 * @param {number} duration - duration in ms
 */
function formatResponseMessage(reqMethod, reqUrl, resStatus, resHeaders, resBody, duration) {
    const headersAndBody = addHeadersAndBody(resHeaders, resBody);

    if (headersAndBody.length < LENGTH_LIMIT) {
        return [util.format('  --> response %s %s %d took %sms %s',
            reqMethod, reqUrl, resStatus, duration, headersAndBody)];
    }

    const body = util.format('%j', resBody);
    const numChunks = Math.ceil(body.length / LENGTH_LIMIT) + 1;
    const messages = new Array(numChunks);
    messages[0] = util.format('  --> response %s %s %d took %sms [%s][find large body in next log]',
        reqMethod, reqUrl, resStatus, duration, printableValue('headers', resHeaders));
    for (let i = 1, o = 0; i < numChunks; ++i, o += LENGTH_LIMIT) {
        messages[i] = util.format('  --> response body part %s of %s [%s]', i, numChunks - 1,
            printableValue('body', body.substr(o, LENGTH_LIMIT)));
    }
    return messages;
}

module.exports = {
    addHeadersAndBody,
    formatRequestMessageWithoutBody,
    formatRequestBodyMessage,
    formatResponseMessage
};
