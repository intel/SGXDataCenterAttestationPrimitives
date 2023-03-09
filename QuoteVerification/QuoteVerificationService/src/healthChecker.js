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

const HealthCache = require('./koa/koaHealthCache');
const detailedErrorString = require('./common/detailedErrorString');
const config = require('./configLoader').getConfig();
const logger = require('./logger')(config);
const { version } = require('./package.json');
const vcsHealth = require('./clients/vcsAccessLayer/VCSClient').getHealth;
const errorHandler = require('./common/errorHandler');
const qvl = require('./qvl');

// initialize from configuration
const koaHealthCache = new HealthCache({
    frequencyMS: config.healthCheck.intervalMs,
    validityMS:  config.healthCheck.freshnessMs,
    version,
    logger
});

async function handleHealthConditionCallback(svcClientHealth, logger, reqId, callback) {
    try { // All exceptions have to be handled inside because function is executed without await in common code
        const response = await svcClientHealth(logger, { 'Request-ID': reqId });
        return callback(null, response.body);
    }
    catch (err) {
        logger.error(`Request health ended with an error: ${detailedErrorString(err)}`);
        return callback(null, err.body);
    }
}

koaHealthCache.addComponentHealthCondition('VerificationCryptoService', async(logger, reqId, callback) => {
    return handleHealthConditionCallback(vcsHealth, logger, reqId, callback);
});

koaHealthCache.addComponentHealthCondition('QuoteVerificationLibrary', async(logger, reqId, callback) => {
    try { // All exceptions have to be handled inside because function is executed without await in common code
        const response = await qvl.getVersion(reqId, logger);
        return callback(null, response.body);
    }
    catch (err) {
        logger.error(errorHandler.errorStackTraceHandler(err, logger.isMultiline), 'Request health ended with an error.');
        return callback(null, err.body);
    }
});

koaHealthCache.addComponentHealthCondition('this', async(logger, reqId, callback) => {
    callback(null, {
        status: koaHealthCache.status.OK,
        version
    });
});


module.exports = koaHealthCache;
