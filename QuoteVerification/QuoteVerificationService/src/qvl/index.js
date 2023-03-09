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

/*eslint no-process-env: 0 */
const env = process.env.NODE_ENV || 'development';
const wrapper = (env === 'production') ?
    require('../../native/QuoteVerificationLibraryWrapper.node') : // release binary
    require('../../native/QuoteVerificationLibraryWrapperd.node'); // QVL with debug symbols

//const wrapper = require('../qvl/cmake-build-debug/QuoteVerificationLibraryWrapperd');

async function getVersion(reqId, logger) {
    try {
        const result = await wrapper.version(reqId);
        return { body: { status: 'OK', version: result.result } };
    }
    catch (e) {
        logger.error('Failed to retrieve version from QVL', e);
        return { body: { status: 'FAILED', version: 'NA' } };
    }
}
/**
 * Retrieves Certification Data from ECDSA quote using QVL
 * @param {string} reqId
 * @param {buffer} quote
 * @returns {Promise<{type: number, data: string}>}
 */
async function getCertificationData(reqId, quote) {
    const certificationData = await wrapper.getCertificationData(reqId, quote);
    return { type: certificationData.type, data: certificationData.data.toString('ascii') };
}

/**
 * Retrieves FMSPC, SGX Type, dynamicPlatform (optional), cachedKeys (optional), smtEnabled (optional)
 * from PCK Certificate using Attestation Parsers
 * @param {string} reqId
 * @param {string} pemCertificate
 * @returns {Promise<{fmspc: string, sgxType: string, dynamicPlatform: boolean, cachedKeys: boolean, smtEnabled: boolean}>}
 */
async function getPckCertificateData(reqId, pemCertificate) {
    const certData = await wrapper.getPckCertificateData(reqId, pemCertificate);
    certData.fmspc = certData.fmspc.toString('hex').toUpperCase();
    return certData;
}

/**
 * Retrieves CRL Distribution Point from X509 certificate using Attestation Parsers
 * @param {string} reqId
 * @param pemCertificate
 * @returns {Promise<string>}
 */
async function getCrlDistributionPoint(reqId, pemCertificate) {
    return wrapper.getCrlDistributionPoint(reqId, pemCertificate);
}

/**
 * Verify quotes using QVL and all provided collaterals
 * @param {string} reqId
 * @param {Buffer} quote
 * @param {string} pckCertPem - PEM format
 * @param {string} tcbInfo - serialized JSON format
 * @param {string} qeIdentity - serialized JSON format
 * @param {string} pckCertIssuerCertChain - PEM format chain of 2 certificates
 * @param {string} tcbInfoIssuerChain - PEM format chain of 2 certificates
 * @param {string} pckCertCrl - hex encoded CRL
 * @param {string} rootCrl - hex encoded CRL
 * @param {string} trustedRootPem - PEM format
 * @param {string} tcbSigningChainTrustedRoot - PEM format
 * @returns {Promise<{status: number, error: (string|undefined), errorSource: (number|undefined)}>}
 */
async function verifyQuote(reqId, quote, pckCertPem, tcbInfo, qeIdentity, pckCertIssuerCertChain, tcbInfoIssuerChain,
                           pckCertCrl, rootCrl, trustedRootPem, tcbSigningChainTrustedRoot) {
    return wrapper.verifyQuote(reqId, quote, pckCertPem, tcbInfo, qeIdentity, pckCertIssuerCertChain,
        tcbInfoIssuerChain, pckCertCrl, rootCrl, trustedRootPem, tcbSigningChainTrustedRoot);
}

/**
 * Function setups logger in QVL
 * @param {string} name - name for logger that will be appended to every log (in node.js world known as category)
 * @param {string} consoleLogLevel - log level for console logger
 * @param {string} fileLogLevel - log level for file logger
 * @param {string} fileName - filename for file logger
 * @param {string} pattern - pattern that will be used to generate log lines.
 */
function loggerSetup(name, consoleLogLevel, fileLogLevel, fileName, pattern) {
    wrapper.loggerSetup(name, consoleLogLevel, fileLogLevel, fileName, pattern);
}
module.exports = {
    getVersion,
    getCertificationData,
    getPckCertificateData,
    getCrlDistributionPoint,
    verifyQuote,
    loggerSetup
};
