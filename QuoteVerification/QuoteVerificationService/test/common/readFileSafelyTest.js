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
const proxyquire = require('proxyquire').noCallThru().noPreserveCache();
const sinon = require('sinon');

const { assertMockFirstCalledWithArgs, assertMockCalledWithArgs } = require('../mocks/helpers');

class TestContext {

    constructor() {
        this.fd = 21;   // file descriptor is a number
        this.targetFile = '/home/user/targetFile';
        this.targetFileContent = 'Content';

        this.fs = {
            openSync:     sinon.stub().returns(this.fd),
            readlinkSync: sinon.stub().withArgs('/proc/self/fd/' + this.fd).returns(this.targetFile),
            fstatSync:    sinon.stub().withArgs(this.fd).returns({
                size:        this.targetFileContent.length,
                isDirectory: sinon.stub().returns(false)
            }),
            readSync:  (d, buffer/*, offset, length, position*/) => { buffer.write(this.targetFileContent); },
            closeSync: sinon.stub()
        };
        this.os = {
            homedir: sinon.stub().returns('/home/user')
        };
        this.logger = {
            trace: sinon.stub(),
            debug: sinon.stub(),
            info:  sinon.stub(),
            error: sinon.stub()
        };
    }

    getTarget() {
        return proxyquire('../../src/common/readFileSafely', {
            'fs':       this.fs,
            'os':       this.os,
            './logger': {
                genericLogger: this.logger
            }
        });
    }
}

describe('readFileSafelyTests', () => {

    it('normal file', async() => {
        // GIVEN
        const c = new TestContext();
        const target = c.getTarget();

        // WHEN
        const response = target(c.targetFile);

        //THEN
        assert.strictEqual(response, c.targetFileContent);
        assert(c.fs.closeSync.calledOnce);
    });

    it('symlink to mount point', async() => {
        // GIVEN
        const c = new TestContext();
        c.fs.readlinkSync = sinon.stub().returns('/home/user/targetFile2');
        const target = c.getTarget();

        // WHEN
        const response = target(c.targetFile);

        //THEN
        assertMockFirstCalledWithArgs(c.logger.debug, 'Loading file from symlink: /home/user/targetFile which directs to: /home/user/targetFile2');
        assert.strictEqual(response, c.targetFileContent);
        assert(c.fs.closeSync.calledOnce);
    });

    it('symlink outside approved location', async() => {
        // GIVEN
        const c = new TestContext();
        c.fs.readlinkSync = sinon.stub().returns('/tmp/otherFile');
        const target = c.getTarget();

        try {
            // WHEN
            target(c.targetFile);
        }
        catch (err) {
            //THEN
            assertMockFirstCalledWithArgs(c.logger.debug, 'Loading file from symlink: /home/user/targetFile which directs to: /tmp/otherFile');
            assertMockFirstCalledWithArgs(c.logger.error, 'Problem loading file: Error: Loading link which directs outside of provided locations: ["/home/user/"] is forbidden!');
            assert(c.fs.closeSync.calledOnce);
            return;
        }
        assert.fail('Should throw error');

    });

    it('not existing file', async() => {
        // GIVEN
        const c = new TestContext();
        c.fs.readlinkSync = sinon.stub().throws(new Error({ code: 'ENOENT' }));
        c.fs.closeSync = sinon.stub().throws(new Error('File does not exist'));
        const target = c.getTarget();
        try {
            // WHEN
            target(c.targetFile);
        }
        catch (err) {
            //THEN
            assert(c.fs.closeSync.calledOnce);
            assertMockCalledWithArgs(1, c.logger.error, 'Problem closing file 21: Error: File does not exist');
            return;
        }
        assert.fail('Should throw error');
    });

    it('unexpected directory', async() => {
        // GIVEN
        const c = new TestContext();
        c.fs.fstatSync = sinon.stub().returns({
            size:        c.targetFileContent.length,
            isDirectory: sinon.stub().returns(true)
        });
        const target = c.getTarget();
        try {
            // WHEN
            target(c.targetFile);
        }
        catch (err) {
            //THEN
            assert(c.fs.closeSync.calledOnce);
            assertMockFirstCalledWithArgs(c.logger.error, 'Problem loading file: Error: Expected path to a file, not a directory. Are you sure path "/home/user/targetFile" is correct?');
            return;
        }
        assert.fail('Should throw error');
    });

});
