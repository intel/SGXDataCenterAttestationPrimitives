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

const proxyquire = require('proxyquire').noCallThru().noPreserveCache();
const sinon = require('sinon');
const assert = require('assert');

class TestContext {
    constructor() {
        this.checkHealth = sinon.stub();
    }

    getTarget() {
        return proxyquire('../../src/routes/health', {
            '../handlers/health': {
                checkHealth: this.checkHealth
            }
        });
    }
}

describe('health router', () => {
    it('should return router with prefix', async() => {
        const c = new TestContext();
        const target = c.getTarget();
        const router = target.createRouter('/test');
        assert.equal(router.stack[1].path, '/test/:component', c.checkHealth);
        assert.equal(router.stack[1].stack[0], c.checkHealth);
        assert.equal(router.stack[0].path, '/test');
        assert.equal(router.stack[0].stack[0], c.checkHealth);
    });

    it('should return router', async() => {
        const c = new TestContext();
        const target = c.getTarget();
        const router = target.createRouter();
        assert.equal(router.stack[1].path, '/:component', c.checkHealth);
        assert.equal(router.stack[1].stack[0], c.checkHealth);
        assert.equal(router.stack[0].path, '/');
        assert.equal(router.stack[0].stack[0], c.checkHealth);
    });
});
