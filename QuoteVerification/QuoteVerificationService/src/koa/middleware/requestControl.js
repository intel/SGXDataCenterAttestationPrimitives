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
 * Request control
 * @param {Object} opts
 * @return {function} returns middleware
 */
function requestControl(opts) {
    const options = opts || {};
    const allowedMethods = options.allowedMethods || ['PUT', 'GET', 'POST', 'DELETE']; // this is just to filter out HEAD, CONNECT, TRACE, etc. methods
    const contentType = options.contentType || 'application/json'; // it should be configured per endpoint, I will leave this logic as it was until it bites us

    return async(ctx, next) => {
        const path = ctx.path;
        const method = ctx.req.method;
        const router = ctx.app.middleware.find(x => x.name === 'dispatch').router; // pull out router from the request context
        const matched = router.match(path, method);

        const allowed = {};
        for (let i = 0; i < matched.path.length; i++) {
            const route = matched.path[i];
            for (let j = 0; j < route.methods.length; j++) {
                const method = route.methods[j];
                if (allowedMethods.includes(method)) {
                    allowed[method] = method;
                }
            }
        }
        const allowedArr = Object.keys(allowed); // allowedArr is almost copy pasted from koa-router's allowedMethods method

        if (matched.path.length === 0 || allowedArr.length === 0) {
            ctx.log.warn(`Path: ${path} is not allowed.`);
            ctx.throw(404);
        }

        if (!allowedArr.includes(method) || !matched.route) {
            ctx.log.warn(`Method: ${method} is not allowed.`);
            ctx.set('Allow', allowedArr.join(', '));
            ctx.throw(405);
        }

        if (method === 'GET') {
            // If there is no request body, null is returned. If there is no content type,
            // or the match fails false is returned. Otherwise, it returns the matching content-type.
            if (ctx.is('*/*') !== null) {
                ctx.log.warn('Incoming request has not empty body for GET method. Return 415 Unsupported Media Type.');
                ctx.throw(415);
            }
            return next();
        }

        if (contentType !== 'None' && !ctx.is(contentType)) {
            ctx.log.warn(`Only ${contentType} content type is supported. Return 415 Unsupported Media Type.`);
            ctx.throw(415);
        }
        return next();
    };
}

module.exports = {
    requestControl
};
