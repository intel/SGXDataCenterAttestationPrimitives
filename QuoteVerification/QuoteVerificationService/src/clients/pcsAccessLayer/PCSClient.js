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

const client = new RestClient(
    config.pcsClient.tlsClientType,
    config.pcsClient.host,
    config.pcsClient.port,
    config.pcsClient.retries,
    config.pcsClient.initialInterval,
    config.pcsClient.factor,
    config.pcsClient.certFile,
    config.pcsClient.keyFile,
    config.pcsClient.caCertDirectories,
    config.pcsClient.proxy,
    config.pcsClient.servername);

const cacheConfig = {
    stdTTL:      config.cache.ttl, // 0 is unlimited
    checkperiod: config.cache.checkPeriod,
    maxKeys:     config.cache.maxKeys, // -1 is unlimited, 0 turns off caching
};

const cache = {
    sgxTcbInfo:    new NodeCache(cacheConfig),
    tdxTcbInfo:    new NodeCache(cacheConfig),
    sgxQeIdentity: new NodeCache(cacheConfig),
    tdxQeIdentity: new NodeCache(cacheConfig)
};

/**
 * @typedef {import('../../jsDoc/types').Logger} Logger
 * @typedef {import('../../jsDoc/types').TcbInfo} TcbInfo
 * @typedef {import('../../jsDoc/types').EnclaveIdentity} EnclaveIdentity
 */

/**
 * Makes first character of string upper
 * @param {string} text 
 * @returns {string} with first character uppercase
 */
function capitalizeFirstLetter(text) {
    return text.length > 0 ? text.charAt(0).toUpperCase() + text.slice(1) : '';
}

/**
 * Saves response under specified key in specified cache
 * @param {string} cacheName - key of global cache object
 * @param {string} key
 * @param {string} value 
 * @param {Logger} logger 
 */
function saveInCache(cacheName, key, value, logger) {
    if (config.cache.maxKeys !== 0) {
        try {
            cache[cacheName].set(key, value);
            logger.info('Cached get' + capitalizeFirstLetter(cacheName) + ' response under key: ' + key);
        }
        catch (error) {
            logger.warn('Problem with ' + cacheName + ' cache: ' + error);
        }
    }
}

/**
 * Retrieves SGX TcbInfo for provided fmspc from cache or directly from PCS
 * @param {string} fmspc
 * @param {string} requestId
 * @param {Logger} logger
 * @returns {Promise<{
 *  status: number, 
 *  body: {tcbInfo: TcbInfo, signature: string }, 
 *  headers: Object.<string, string>
 * }|Error>}
 */
async function getSgxTcbInfo(fmspc, requestId, logger) {
    const path = '/sgx/certification/v4/tcb';

    let response = cache.sgxTcbInfo.get(fmspc);
    if (!response) {
        try {
            response = await client.getRequestPromised(requestId, logger, null, path, {}, {
                fmspc
            });
            saveInCache('sgxTcbInfo', fmspc, response, logger);
        }
        catch (error) {
            response = error;
        }
    }
    else {
        logger.info(`SGX TcbInfo for FMSPC=${fmspc} taken from cache`);
    }

    return response;
}

/**
 * Retrieves TDX TcbInfo for provided fmspc from cache or directly from PCS
 * @param {string} fmspc
 * @param {string} requestId
 * @param {Logger} logger
 * @returns {Promise<{
 *  status: number, 
 *  body: {tcbInfo: TcbInfo, signature: string}, 
 *  headers: Object.<string, string>
 * }|Error>}
 */
async function getTdxTcbInfo(fmspc, requestId, logger) {
    const path = '/tdx/certification/v4/tcb';

    let response = cache.tdxTcbInfo.get(fmspc);
    if (!response) {
        try {
            response = await client.getRequestPromised(requestId, logger, null, path, {}, {
                fmspc
            });
            saveInCache('tdxTcbInfo', fmspc, response, logger);            
        }
        catch (error) {
            response = error;
        }
    }
    else {
        logger.info(`TDX TcbInfo for FMSPC=${fmspc} taken from cache`);
    }

    return response;
}

/**
 * Retrieves SGX QE Identity from cache or directly from PCS
 * @param {string} requestId
 * @param {Logger} logger
 * @returns {Promise<{
 *  status: number, 
 *  body: {enclaveIdentity: EnclaveIdentity, signature: string}, 
 *  headers: Object.<string, string>
 * }|Error>}
 */
async function getSgxQeIdentity(requestId, logger) {
    const path = '/sgx/certification/v4/qe/identity';
    const cacheKey = 'sgxQeIdentity';

    let response = cache.sgxQeIdentity.get(cacheKey);
    if (!response) {
        try {
            response = await client.getRequestPromised(requestId, logger, null, path);
            saveInCache('sgxQeIdentity', cacheKey, response, logger);            
        }
        catch (error) {
            response = error;
        }
    }
    else {
        logger.info('SGX QeIdentity taken from cache');
    }

    return response;    
}

/**
 * Retrieves TDX QE Identity from cache or directly from PCS
 * @param {string} requestId
 * @param {Logger} logger
 * @returns {Promise<{
 *  status: number, 
 *  body: {enclaveIdentity: EnclaveIdentity, signature: string}, 
 *  headers: Object.<string, string>
 * }|Error>}
 */
async function getTdxQeIdentity(requestId, logger) {
    const path = '/tdx/certification/v4/qe/identity';
    const cacheKey = 'tdxQeIdentity';

    let response = cache.tdxQeIdentity.get(cacheKey);
    if (!response) {
        try {
            response = await client.getRequestPromised(requestId, logger, null, path);
            saveInCache('tdxQeIdentity', cacheKey, response, logger);
        }
        catch (error) {
            response = error;
        }
    }
    else {
        logger.info('TDX QeIdentity taken from cache');
    }

    return response;
}

module.exports = {
    getSgxTcbInfo,
    getTdxTcbInfo,
    getSgxQeIdentity,
    getTdxQeIdentity
};
