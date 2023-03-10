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
const assert = require('chai').assert;

const { assertMockCalledOnceWithArgs } = require('../mocks/helpers');

class RouterStub {
    constructor() {
        this.get = sinon.spy();
    }
}

class TestContext {
    constructor() {
        this.healthHandler = sinon.stub();
    }

    getTarget() {
        return proxyquire('../../src/koa/koaHealthRouter', {
            'koa-router': RouterStub
        });
    }
}

describe('koa health cache router', () => {
    it('should return router with prefix', async() => {
        const c = new TestContext();
        const target = c.getTarget();
        const router = target.createHealthRouter(c.healthHandler, '/test');
        assert.instanceOf(router, RouterStub);
        assertMockCalledOnceWithArgs(router.get, '/test/:component', c.healthHandler);
        assertMockCalledOnceWithArgs(router.get, '/test', c.healthHandler);
    });

    it('should return router with default prefix', async() => {
        const c = new TestContext();
        const target = c.getTarget();
        const router = target.createHealthRouter(c.healthHandler);
        assert.instanceOf(router, RouterStub);
        assertMockCalledOnceWithArgs(router.get, '/:component', c.healthHandler);
        assertMockCalledOnceWithArgs(router.get, '/', c.healthHandler);
    });
});
