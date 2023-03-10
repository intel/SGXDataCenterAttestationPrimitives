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

const config = require('../../configLoader').getConfig();
const RestClient = require('../../common/RestClient');
const NodeCache = require('node-cache');

const cacheConfig = {
    stdTTL:      config.cache.ttl, // 0 is unlimited
    checkperiod: config.cache.checkPeriod,
    maxKeys:     config.cache.maxKeys, // -1 is unlimited, 0 turns off caching
};

const clientsCacheConfig = {
    stdTTL:      0,  // 0 is unlimited
    checkperiod: 0,  // no periodic check
    maxKeys:     -1, // -1 is unlimited, 0 turns off caching
};

const cache = {
    crls:    new NodeCache(cacheConfig),
    clients: new NodeCache(clientsCacheConfig)
};

/**
* @typedef {import('../../jsDoc/types').Logger} Logger
*/

/**
 * Creates and caches RestClient which will communicate with specific host
 * @param {string} host - url.host in format '<hostname>:<port>'
 * @returns {RestClient}
 */
function getRestClientForHost(host, logger) {
    const [hostname, port] = host.split(':');
    let client = cache.clients.get(host);
    if (!client) {
        logger.info(`Creating RestClient for host ${host}`);
        client = new RestClient(
            'TLS',
            hostname,
            parseInt(port || 443),
            config.crlClient.retries,
            config.crlClient.initialInterval,
            config.crlClient.factor,
            undefined,
            undefined,
            undefined,
            config.crlClient.proxy);
    
        try {
            cache.clients.set(host, client);
            logger.info('Created and indefinitely cached REST client ready to connect to host: ' + host);
        }
        catch (error) {
            logger.warn('Problem with clients cache: ' + error);
            // Not throwing error, if just saving to cache fails, it doesnt change the fact 
            // that client was created
        }
    }
    return client;
}

/**
* Retrieves SGX TcbInfo for provided fmspc from cache or directly from PCS
* @param {string} distributionPoint - address of file to download and cache
* @param {string} requestId
* @param {Logger} logger
* @returns {Promise<{
*  status: number, 
*  body: string, 
*  headers: Object.<string, string>
* }|Error>}
*/
async function getCrlFromDistributionPoint(distributionPoint, requestId, logger) {
    const url = new URL(distributionPoint);
    
    let response = cache.crls.get(url.href);
    if (!response) {
        try {
            const client = getRestClientForHost(url.host, logger);

            const path = url.pathname;
            const searchParams = Object.fromEntries(url.searchParams);
            const additionalHeaders = {};
            response = await client.getRequestWithBinaryResponsePromised(requestId, logger, null, path, additionalHeaders, searchParams);
            if (config.cache.maxKeys !== 0) {
                try {
                    cache.crls.set(url.href, response);
                    logger.info('Cached CRL downloaded from: ' + url.href);
                }
                catch (error) {
                    logger.warn('Problem with CRLs cache: ' + error);
                    // Not throwing error, if just saving to cache fails, it doesnt change the fact 
                    // that response was positive and can be returned
                }
            }
        }
        catch (error) {
            response = error;
        }
    }
    else {
        logger.info(`CRL taken from cache instead of ${distributionPoint}`);
    }
    
    return response;
}

module.exports = {
    getCrlFromDistributionPoint
};
