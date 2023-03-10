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
const proxyquire = require('proxyquire');

function getTarget(isFile, isDirectory) {
    return proxyquire('../../src/common/getCACertificatesSync', {
        fs: {
            readdirSync: sinon.stub().returns(['file', 'additionalFile']),
            statSync:    () => {
                return {
                    isFile,
                    isDirectory
                };
            }
        }
    });
}


describe('getCACertificatesSyncTests', () => {

    it('should return expected path combination for given directories and files', () => {
        // GIVEN / WHEN
        const isFileStub = sinon.stub().returns(true);
        const isDirStub = sinon.stub().returns(false);
        const result = getTarget(isFileStub, isDirStub)(['directory', 'additionalDirectory']);
        // THEN
        assert.equal(result.length, 4);
        assert.equal(result[0], 'directory/file');
        assert.equal(result[1], 'directory/additionalFile');
        assert.equal(result[2], 'additionalDirectory/file');
        assert.equal(result[3], 'additionalDirectory/additionalFile');
    });

    it('should check also subdirs', () => {
        // GIVEN / WHEN
        const isFileStub = sinon.stub().returns(true);
        const isDirStub = sinon.stub();
        isDirStub.onCall(3).returns(true);
        isDirStub.returns(false);
        const result = getTarget(isFileStub, isDirStub)(['directory', 'additionalDirectory']);
        // THEN
        assert.equal(result.length, 6);
        assert.equal(result[0], 'directory/file');
        assert.equal(result[1], 'directory/additionalFile');
        assert.equal(result[2], 'additionalDirectory/additionalFile/file');
        assert.equal(result[3], 'additionalDirectory/additionalFile/additionalFile');
        assert.equal(result[4], 'additionalDirectory/file');
        assert.equal(result[5], 'additionalDirectory/additionalFile');
    });

    it('should return empty array when empty array given', () => {
        // GIVEN / WHEN
        const isFileStub = sinon.stub().returns(true);
        const isDirStub = sinon.stub().returns(false);
        const result = getTarget(isFileStub, isDirStub)([]);
        // THEN
        assert.equal(result.length, 0);
    });

    it('should return empty array when no array given', () => {
        // WHEN
        const isFileStub = sinon.stub().returns(true);
        const isDirStub = sinon.stub().returns(false);
        const result = getTarget(isFileStub, isDirStub)();
        // THEN
        assert.equal(result.length, 0);
    });
});
