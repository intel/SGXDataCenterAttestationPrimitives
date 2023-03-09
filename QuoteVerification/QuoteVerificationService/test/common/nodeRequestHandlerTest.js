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

const assert = require('assert');
const sinon = require('sinon');
const PassThrough = require('stream').PassThrough;
const https = require('https');
const Buffer = require('safe-buffer').Buffer;

const httpsHandler = require('../../src/common/nodeRequestHandler');

let request;

describe('nodeRequestHandler unit tests', () => {
    beforeEach(() => {
        request = sinon.stub(https, 'request');
    });

    afterEach(() => {
        https.request.restore();
    });

    it('should convert json result to object', async() => {
        const expected = { hello: 'world' };
        const response = new PassThrough();
        response.write(JSON.stringify(expected));
        response.statusCode = 200;
        response.headers = { 'content-type': 'application/json' };
        response.end();

        const req = new PassThrough();

        request.callsArgWith(1, response)
            .returns(req);

        const res = await httpsHandler({}, '');
        assert.deepEqual(res.body, { hello: 'world' });
        assert.deepEqual(res.statusCode, 200);
        assert.deepEqual(res.headers, { 'content-type': 'application/json' });
    });

    it('should return string object', async() => {
        const expected = 'expected response';
        const response = new PassThrough();
        response.write(JSON.stringify(expected));
        response.statusCode = 200;
        response.headers = { 'content-type': 'text/plain' };
        response.end();

        const req = new PassThrough();

        request.callsArgWith(1, response)
            .returns(req);

        const res = await httpsHandler({}, '');
        assert.deepEqual(res.body, '"expected response"');
        assert.deepEqual(res.statusCode, 200);
        assert.deepEqual(res.headers, { 'content-type': 'text/plain' });
    });

    it('should return byte Buffer, when isResponseBinary = true', async() => {
        const isResponseBinary = true;

        const expectedResponseBody = Buffer.from([1, 2, 3]);
        const expectedResponseHeaders = { 'content-type': 'application/pkix-crl' };

        const response = new PassThrough();
        response.write(expectedResponseBody);
        response.statusCode = 200;
        response.headers = expectedResponseHeaders;
        response.end();

        const req = new PassThrough();

        request.callsArgWith(1, response)
            .returns(req);

        const res = await httpsHandler({}, '', isResponseBinary);
        assert.deepEqual(res.body, expectedResponseBody);
        assert.deepEqual(res.statusCode, 200);
        assert.deepEqual(res.headers, expectedResponseHeaders);
    });

    it('should return string object when no content type given', async() => {
        const expected = 'expected response';
        const response = new PassThrough();
        response.write(JSON.stringify(expected));
        response.statusCode = 200;
        response.end();

        const req = new PassThrough();

        request.callsArgWith(1, response)
            .returns(req);

        const res = await httpsHandler({}, '');
        assert.deepEqual(res.body, '"expected response"');
        assert.deepEqual(res.statusCode, 200);
        assert.deepEqual(res.headers, undefined);
    });

    it('should call write when json', () => {
        const body = { somekey: 'somevalue' };
        const expected = JSON.stringify(body);

        const req = new PassThrough();
        const write = sinon.spy(req, 'write');

        request.returns(req);

        httpsHandler({}, body);
        assert(write.withArgs(expected).calledOnce);
    });

    it('should call write when Uint8Array', () => {
        const body = new Uint8Array([21, 31]);

        const req = new PassThrough();
        const write = sinon.spy(req, 'write');

        request.returns(req);

        httpsHandler({}, body);
        assert(write.withArgs(new Uint8Array([21, 31])).calledOnce);
    });

    it('should reject request error', async() => {
        const expectedError = new Error('expected error');
        const req = new PassThrough();
        const response = new PassThrough();
        response.on('end', () => {
            req.emit('error', expectedError);
        });
        response.end();

        request.callsArgWith(1, response)
            .returns(req);

        try {
            await httpsHandler({}, '');
            assert.fail('Expected test to throw');
        }
        catch (err) {
            assert.deepEqual(err, expectedError);
        }
    });
});
