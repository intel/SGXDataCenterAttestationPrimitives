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

const { InternalErrorResponse, BadRequestResponse } = require('../response');

class BaseResponseHandler {

    constructor(ctx) {
        this.ctx = ctx;
    }

    isResponseValid(response) {
        if (!response.httpCode || !response.jsonBody) {
            this.ctx.log.error("Invalid response object set, can't send response");
            throw new InternalErrorResponse(this.ctx.log);
        }
    }

    setBody(response) {
        this.ctx.status = response.httpCode;
        this.ctx.body = response.jsonBody;
    }

    setHeaders(response) {
        if (!response.headers) {
            return;
        }
        const headersNames = response.headers.keys();
        let headerName = headersNames.next().value;
        while (headerName) {
            this.ctx.set(headerName, response.headers.get(headerName));
            headerName = headersNames.next().value;
        }
    }

    setResponse(response) {
        this.isResponseValid(response);
        this.setBody(response);
        this.setHeaders(response);
    }
}

class NoBodyOnErrorResponseHandler extends BaseResponseHandler {
    isResponseValid(response) {
        if (!response.httpCode || response.httpCode === 200 && !response.jsonBody) {
            this.ctx.log.error("Invalid response object set, can't send response");
            throw new InternalErrorResponse(this.ctx.log);
        }
    }

    setBody(response) {
        this.ctx.status = response.httpCode;
        if (this.ctx.status !== 200) {
            this.ctx.body = '';
        }
        else {
            this.ctx.body = response.jsonBody;
        }
    }
}

function responseHandler(sendBodyOnErrors) {
    return async(ctx, next) => {
        const handler = sendBodyOnErrors ? new BaseResponseHandler(ctx) : new NoBodyOnErrorResponseHandler(ctx);

        ctx.setResponse = (response) => {
            handler.setResponse(response);
        };
        ctx.setBadRequest = () => {
            const response = new BadRequestResponse(ctx.log);
            handler.setResponse(response);
        };
        ctx.setInternalError = () => {
            const response = new InternalErrorResponse(ctx.log);
            handler.setResponse(response);
        };
        return next();
    };
}

module.exports = {
    withBodyOnError:   responseHandler(true),
    withNoBodyOnError: responseHandler(false)
};
