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

const { WARN, INFO, DEBUG } = require('log4js').levels;
const uuidGen = require('uuid-random');
const validators = require('../commonDataValidator');
const requestLogFormatter = require('../../common/requestLogFormatter');

async function generateReqId() {
    return uuidGen.bin().toString('hex');
}

module.exports = (serverLevel) => {
    return async function requestId(ctx, next) {
        let msg = '';
        let logLevel = INFO.levelStr.toLowerCase();
        const incomingReqIDHeader = ctx.req.headers['request-id'];
        // Set correct reqId
        if (incomingReqIDHeader) {
            if (serverLevel.isTopLevel) {
                ctx.reqId = ctx.request.reqId = await generateReqId();
                msg = `Received own Request-ID header: [${incomingReqIDHeader}]. New Request-ID is: [${ctx.reqId}]`;
            }
            else if (!validators.validateHexstring('Request-ID', incomingReqIDHeader, 32, ctx.log)) {
                ctx.reqId = ctx.request.reqId = await generateReqId();
                msg = `Received own Request-ID header: [${incomingReqIDHeader}] has incorrect format (must be 32-sign hexadecimal). New Request-ID is: [${ctx.reqId}]`;
                logLevel = WARN.levelStr.toLowerCase();
            }
            else {
                ctx.reqId = ctx.request.reqId = incomingReqIDHeader;
                msg = `Using received Request-ID: [${ctx.reqId}]`;
                logLevel = DEBUG.levelStr.toLowerCase();
            }
        }
        else {
            ctx.reqId = ctx.request.reqId = await generateReqId();
            msg = `No Request-ID header. New Request-ID is: [${ctx.reqId}]`;
            logLevel = DEBUG.levelStr.toLowerCase();
        }

        ctx.log = ctx.log.scoped(ctx.reqId);
        ctx.log[logLevel](msg);

        ctx.log.info(requestLogFormatter.formatRequestMessageWithoutBody(
            ctx.request.method, ctx.request.originalUrl, ctx.request.headers
        ));

        // Add response header with Request-ID
        ctx.set('Request-ID', ctx.reqId);
        return next();
    };
};
