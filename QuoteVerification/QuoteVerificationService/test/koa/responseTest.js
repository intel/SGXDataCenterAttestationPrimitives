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

const sinon = require('sinon');
const assert = require('assert');
global.configPath = './configuration-default/';

const response = require('../../src/koa/response');
const { InternalError, InternalErrorResponse, BadRequestResponse, GenericResponse } = response;

const loggerStub = {
    error: sinon.stub()
};


describe('responseTest', () => {

    it('should execute properly', () => {
        // GIVEN
        const statusStub = { httpCode: 1024, name: 'test' };

        // WHEN
        const genResponse = new GenericResponse(statusStub, loggerStub);

        // THEN
        assert.equal(genResponse.httpCode, statusStub.httpCode);
        assert.equal(genResponse.jsonBody.status, statusStub.name);

    });

    it('should throw error when required status params missing', () => {
        // GIVEN / WHEN
        const statusStub = { httpCode: undefined, name: undefined };

        // THEN
        assert.throws(() => {
            return new GenericResponse(statusStub, loggerStub);
        }, InternalError);

    });

    it('should properly init BadRequestResponse', () => {
        // GIVEN / WHEN
        const badRequestResponse = new BadRequestResponse(loggerStub);
        // THEN
        assert.equal(badRequestResponse.httpCode, 400);
        assert.equal(badRequestResponse.jsonBody.status, 'STATUS_BAD_REQUEST');

    });

    it('should properly init InternalErrorResponse', () => {
        // GIVEN / WHEN
        const internalErrorResponse = new InternalErrorResponse(loggerStub);
        // THEN
        assert.equal(internalErrorResponse.httpCode, 500);
        assert.equal(internalErrorResponse.jsonBody.status, 'STATUS_INTERNAL_ERROR');

    });

    describe('setResponse', () => {

        it('should help setting BadRequestResponse in current context', () => {
            // GIVEN
            const ctx = {};
            const exampleResponse = new BadRequestResponse(loggerStub);
            // WHEN
            response.setResponse(exampleResponse, ctx);
            // THEN
            assert.strictEqual(ctx.body, exampleResponse.jsonBody);
            assert.strictEqual(ctx.status, exampleResponse.httpCode);
        });

        it('should help setting InternalErrorResponse in current context', () => {
            // GIVEN
            const ctx = {};
            const exampleResponse = new InternalErrorResponse(loggerStub);
            // WHEN
            response.setResponse(exampleResponse, ctx);
            // THEN
            assert.strictEqual(ctx.body, exampleResponse.jsonBody);
            assert.strictEqual(ctx.status, exampleResponse.httpCode);
        });

    });

});
