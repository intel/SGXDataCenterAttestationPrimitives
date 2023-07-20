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

const proxyquire = require('proxyquire');
const assert = require('assert');
const sinon = require('sinon');
const Buffer = require('safe-buffer').Buffer;

const request = sinon.stub();
const httpsHandler = proxyquire('../../src/common/nodeRequestHandler', {
    axios: request
});

describe('nodeRequestHandler unit tests', () => {
    it('should convert json result to object', async() => {
        const expected = { hello: 'world' };
        const response = {
            data:    expected,
            status:  200,
            headers: { 'content-type': 'application/json' }
        };

        request.resolves(response);

        const res = await httpsHandler({}, '');
        assert.deepEqual(res.body, { hello: 'world' });
        assert.deepEqual(res.statusCode, 200);
        assert.deepEqual(res.headers, { 'content-type': 'application/json' });
        assert(request.withArgs(sinon.match({
            maxContentLength: sinon.match.number,
            maxBodyLength:    sinon.match.number,
            responseType:     'json'
        })).calledOnce);
    });

    it('should return string object', async() => {
        const expected = 'expected response';
        const response = {
            data:    JSON.stringify(expected),
            status:  200,
            headers: { 'content-type': 'text/plain' }
        };

        request.resolves(response);

        const res = await httpsHandler({}, '');
        assert.deepEqual(res.body, '"expected response"');
        assert.deepEqual(res.statusCode, 200);
        assert.deepEqual(res.headers, { 'content-type': 'text/plain' });
    });

    it('should return byte Buffer, when isResponseBinary = true', async() => {
        const isResponseBinary = true;

        const expectedResponseBody = Buffer.from([1, 2, 3]);
        const expectedResponseHeaders = { 'content-type': 'application/pkix-crl' };

        const response = {
            data:    expectedResponseBody,
            status:  200,
            headers: expectedResponseHeaders
        };

        request.resolves(response);

        const res = await httpsHandler({}, '', isResponseBinary);
        assert.deepEqual(res.body, expectedResponseBody);
        assert.deepEqual(res.statusCode, 200);
        assert.deepEqual(res.headers, expectedResponseHeaders);
        assert(request.withArgs(sinon.match({ responseType: 'arraybuffer' })).calledOnce);
    });

    it('should return string object when no content type given', async() => {
        const expected = 'expected response';
        const response = {
            data:   expected,
            status: 200
        };

        request.resolves(response);

        const res = await httpsHandler({}, '');
        assert.deepEqual(res.body, 'expected response');
        assert.deepEqual(res.statusCode, 200);
        assert.deepEqual(res.headers, undefined);
    });

    it('should send body', async() => {
        const body = { somekey: 'somevalue' };

        request.resolves({});

        await httpsHandler({}, body);
        assert(request.withArgs(sinon.match({ data: body })).calledOnce);
    });

    it('should return body with unsuccessful status', async() => {
        const expectedError = new Error('expected error');
        expectedError.response = {
            status: 404
        };
        request.throws(expectedError);

        const res = await httpsHandler({}, '');
        assert.deepEqual(res.body, undefined);
        assert.deepEqual(res.statusCode, 404);
        assert.deepEqual(res.headers, undefined);
    });

    it('should reject request error', async() => {
        const expectedError = new Error('expected error');
        request.throws(expectedError);

        try {
            await httpsHandler({}, '');
            assert.fail('Expected test to throw');
        }
        catch (err) {
            assert.deepEqual(err, expectedError);
        }
    });

    it('should use provided options', async() => {
        const method = 'post';
        request.resolves({});

        await httpsHandler({ method }, '');
        assert(request.withArgs(sinon.match({ method })).calledOnce);
    });
});
