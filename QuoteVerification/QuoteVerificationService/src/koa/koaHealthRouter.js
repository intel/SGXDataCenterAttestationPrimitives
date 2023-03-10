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

const Router = require('koa-router');

/**
 * IntelliJ IDEA has long lasting bugs: 
 * https://youtrack.jetbrains.com/issue/WEB-31971
 * https://youtrack.jetbrains.com/issue/WEB-52385
 * JSDoc import works for example in Visual Studio Code.
 * 
 * @typedef {import('../jsDoc/types').KoaRouter} KoaRouter
 */

/**
 * Creates new router as its instances are mutable and should be used only once
 * 
 * @param {function} healthHandler - handler for health router
 * @param {string} urlPrefix - optional url prefix, '/' as default
 * 
 * @returns {KoaRouter}
 */
function createHealthRouter(healthHandler, urlPrefix = '/') {
    const router = new Router();
    if (urlPrefix === '/') {
        router.get('/', healthHandler);
        router.get('/:component', healthHandler);
    }
    else {
        router.get(urlPrefix, healthHandler);
        router.get(`${urlPrefix}/:component`, healthHandler);
    }
    return router;
}

module.exports = {
    createHealthRouter
};
