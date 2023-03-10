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

const getRawBody = require('raw-body');
const PassThrough = require('stream').PassThrough;

/**
 * Configures and returns bodyParser
 * @param {Object} config - service configuration
 * @returns {function} rawBodyParser middleware
 */
function getConfiguredRawBodyParser(config) {
    return async(ctx, next) => {
        try {
            /*
               Observed behaviour:
                0. keep-alive must be enabled
                1. client sends too long request
                2. server's middleware pareses the stream and throws error
                3. koa catches the error, returns response
                4. koa kills socket w/o informing the client
                5. client sends an another request and receives 'socket hung' error

                Wrap the stream in another stream to prevent koa noticing an error.
                If there is no error, connection remains alive.
             */
            const wrappedStream = ctx.request.req.on('error', ctx.onerror).pipe(new PassThrough());
            ctx.request.body = await getRawBody(wrappedStream, {
                length: ctx.request.headers['content-length'],
                limit:  config.service.bodySizeLimits.blob
            });
            await next();
        }
        catch (err) {
            ctx.log.error(err);
            ctx.throw(err.statusCode ? err.statusCode : 500);
        }
    };
}

module.exports = {
    getConfiguredRawBodyParser
};
