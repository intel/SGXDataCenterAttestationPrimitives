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

const client = new RestClient(
    config.vcsClient.tlsClientType,
    config.vcsClient.host,
    config.vcsClient.port,
    config.vcsClient.retries,
    config.vcsClient.initialInterval,
    config.vcsClient.factor,
    config.vcsClient.certFile,
    config.vcsClient.keyFile,
    config.vcsClient.caCertDirectories,
    config.vcsClient.proxy,
    config.vcsClient.servername);

/**
 * @typedef {import('../../jsDoc/types').Logger} Logger
 */

/**
 * Signs the attestation verification report 
 * @param {{}} body - attestation verification report to be signed
 * @param {string} requestId 
 * @param {Logger} logger 
 * @returns {Promise<{
 *  status: number, 
 *  body: {
 *   signature: string  
 *  }, 
 *  headers: Object.<string, string>
 * }|Error>}
 */
 async function signVerificationReport(body, requestId, logger) {
    const path = '/sign/attestation-verification-report';

    let response;
    try {
        response = await client.postRequestPromised(requestId, logger, body, path);
    }
    catch (error) {
        response = error;
    }

    return response;
}
    
/**
 * Retrieves health status of component and its dependencies
 * @param {Logger} logger
 * @param {Object.<string, string>} headers
 * @returns {status: number, body: JSON, headers: Object.<string, string>}
 */
function getHealth(logger, headers) {
    return client.health(logger, headers);
}

module.exports = {
    getHealth,
    signVerificationReport
};
