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


const { ERROR, WARN, INFO } = require('log4js').levels;

const { formatResponseMessage } = require('../../common/requestLogFormatter');
const { STATUS_INTERNAL_ERROR, STATUS_BAD_REQUEST } = require('../response').STATUSES;

function getLevel(status) {
    if (status >= STATUS_INTERNAL_ERROR.httpCode) {
        return ERROR.levelStr.toLowerCase();
    }
    if (status >= STATUS_BAD_REQUEST.httpCode) {
        return WARN.levelStr.toLowerCase();
    }
    return INFO.levelStr.toLowerCase();
}

module.exports = (logger) => {
    return async(ctx, next) => {
        const t = Date.now();
        ctx.log = logger;
        ctx.res.on('finish', () => {
            const dt = Date.now() - t;
            const messages = formatResponseMessage(
                ctx.request.method, ctx.request.originalUrl, ctx.status, ctx.response.headers, ctx.response.body, dt
            );
            messages.forEach(msg => ctx.log[getLevel(ctx.status)](msg));
        });

        return next();
    };
};
