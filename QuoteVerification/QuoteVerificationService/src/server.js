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

const process = require('process');

const config = require('./configLoader').getConfig();
const logger = require('./logger')(config);

const HealthCache = require('./healthChecker');
const router = require('./routes');

const ServerInit = require('./koa/init/serverInit');
const { getConfiguredBodyParser } = require('./koa/middleware/bodyParser');
const requestId = require('./koa/middleware/requestId');
const errorHandler = require('./koa/middleware/errorHandler').withNoBodyOnError;
const { requestControl } = require('./koa/middleware/requestControl');

const options = {
    serverName:  'QVS',
    logger,
    middlewares: [
        errorHandler,
        requestId({ isTopLevel: true }),
        requestControl(),
        getConfiguredBodyParser(config)
    ],
    serviceConfig: config.service
};

const init = new ServerInit(options);

process.on('unhandledRejection', (result, error) => {
    logger.error('Unhandled Rejection occured:', result, 'Error:', error);
});

module.exports = (async function initialize() {
    try {
        if (config.service.tlsServerType === 'None') {
            await init.startHTTPServer(config.service.port, router);
        }
        else {
            await init.startHTTPSServer(config.service.port, router);
        }
        HealthCache.run();
    }
    catch (e) {
        logger.error('Error occurred during server initialization:', e);
        /*eslint no-process-exit: 0 */
        process.exit(1);
    }
}());
