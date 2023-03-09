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

/**
 * Handles errors thrown during request processing
 *
 * Removes charset from <b>Content-Type</b> response header
 * Logs an error and can hide detailed error message from client 
 *
 * @param sendBodyOnErrors if body should be send with error responses
 */

function errorHandler(sendBodyOnErrors) {
    return async(ctx, next) => {
        try {
            await next();
            removeCharsetFromContentTypeHeader(ctx);
            if (((ctx.status === 400 || ctx.status === 403 || ctx.status === 404 || ctx.status === 500 || ctx.status === 503) && !ctx.body) ||
                (ctx.status > 400 && ctx.status !== 403 && ctx.status !== 404 && ctx.status !== 500 && ctx.status !== 503)) {
                ctx.throw(ctx.status);
            }
        }
        catch (err) {
            // HTTP errors won't be additionally logged
            const status = err.status || err.statusCode;
            if (!status) {
                ctx.log.error(err);
            }
            ctx.status = status || 500;
            // Bad Request HTTP error is the only one which gives more information to the user
            // Top level services should not return body on all errors
            if (status !== 400 || !sendBodyOnErrors) {
                ctx.body = '';
            }
            else {
                ctx.body = { status: err.message };
                removeCharsetFromContentTypeHeader(ctx);
            }
        }
        removeContentTypeWhenEmptyBody(ctx);
    };
}

function removeCharsetFromContentTypeHeader(ctx) {
    let contentType = ctx.response.get('Content-Type');
    if (contentType) {
        contentType = contentType.replace('; charset=utf-8', '');
        ctx.set('Content-Type', contentType);
    }
}

function removeContentTypeWhenEmptyBody(ctx) {
    if (!ctx.body) {
        ctx.type = undefined;
    }
}

module.exports = {
    withBodyOnError:   errorHandler(true),
    withNoBodyOnError: errorHandler(false)
};
