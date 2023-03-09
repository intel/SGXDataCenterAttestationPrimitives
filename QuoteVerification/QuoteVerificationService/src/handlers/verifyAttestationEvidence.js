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

const _ = require('lodash');
const moment = require('moment');

const certificateChainParser = require('./certificateChainParser');
const pcs = require('../clients/pcsAccessLayer/PCSClient');
const crl = require('../clients/crlAccessLayer/CRLClient');
const qvl = require('../qvl');
const qvlStatus = require('../qvl/status');
const errorSource = require('../qvl/verifyQuoteErrorSource');
const vcs = require('../clients/vcsAccessLayer/VCSClient');
const config = require('../configLoader').getConfig();
const STATUSES = require('../koa/response').STATUSES;
const random = require('../util/random');
const validator = require('validator');

const uriString = 'URI:';
const tdxsvnOffsetInQuote = 48; // 48 is the size of header
const tdxsvnSize = 16;

const attestationReportSigningChain = config.target.attestationReportSigningCertificate + config.target.attestationReportSigningCaCertificate;
const trustedRootPublicKey = decodeURIComponent(config.target.trustedRootPublicKey);

/**
 * @typedef {import('../jsDoc/types').Logger} Logger
 * @typedef {import('../jsDoc/types').TcbInfo} TcbInfo
 * @typedef {import('../jsDoc/types').EnclaveIdentity} EnclaveIdentity
 * @typedef {import('../jsDoc/types').TcbLevel} TcbLevel
 * @typedef {import('../jsDoc/types').EnclaveTcbLevel} EnclaveTcbLevel
 */

/**
 * Handler for verify attestation evidence endpoint
 * @param {Object} ctx - koa context
 * @returns
 */
async function verifyAttestationEvidence(ctx) {
    const nonce = ctx.request.body.nonce;   // optional

    if (_.isString(nonce) && nonce.length > 32) {
        ctx.log.error('Provided nonce is longer than 32 characters: ', nonce);
        ctx.status = 400;
        return;
    }

    const isvQuote = ctx.request.body.isvQuote;
    if (!_.isString(isvQuote) || !validator.isBase64(isvQuote)) {
        ctx.log.error('isvQuote is not provided or is not a base64 string: ', isvQuote);
        ctx.status = 400;
        return;
    }
    const quote = Buffer.from(isvQuote, 'base64');

    let certificationData;
    let pckCertData;
    let rootCaPem; let intermediateCaPem; let pckCertPem;
    let pckCertCrlDistributionPoint; let rootCaCrlDistributionPoint;
    try {
        certificationData = await getType5CertificationDataFromQuote(ctx.reqId, quote);
        ({ rootCaPem, intermediateCaPem, pckCertPem } = await certificateChainParser.parseCertificateChainWithSpecificRoot(trustedRootPublicKey, certificationData));
        pckCertData = await getPckCertificateData(ctx.reqId, pckCertPem);
        [pckCertCrlDistributionPoint, rootCaCrlDistributionPoint] = await Promise.all([pckCertPem, rootCaPem].map(cert => getCrlUrl(ctx.reqId, cert)));
    }
    catch (error)  {
        ctx.log.error(error);
        ctx.status = 400;
        return;
    }

    try {
        const { quoteType } = readQuoteVersion(quote);
        const isvsvn = readIsvsvn(quote);

        const getTcbInfo = (quoteType === 'SGX') ? pcs.getSgxTcbInfo : pcs.getTdxTcbInfo;
        const getQeIdentity = (quoteType === 'SGX') ? pcs.getSgxQeIdentity : pcs.getTdxQeIdentity;

        const requestPromises = {
            tcbInfoData: getTcbInfo(pckCertData.fmspc, ctx.reqId, ctx.log),
            qeIdentity:  getQeIdentity(ctx.reqId, ctx.log),
            pckCertCrl:  crl.getCrlFromDistributionPoint(pckCertCrlDistributionPoint, ctx.reqId, ctx.log),
            rootCrl:     crl.getCrlFromDistributionPoint(rootCaCrlDistributionPoint, ctx.reqId, ctx.log)
        };
        const requiredCollateral = _.zipObject(Object.keys(requestPromises), await Promise.all(Object.values(requestPromises)));

        const { tcbInfo, tcbInfoSigningChainData } = await readTcbInfoAndIssuerChainFromResponse(requiredCollateral.tcbInfoData);
        const qeIdentity = readQeIdentityFromResponse(requiredCollateral.qeIdentity);
        const pckCertCrl = parseCrlFromDistributionPoint(requiredCollateral.pckCertCrl);
        const rootCrl = parseCrlFromDistributionPoint(requiredCollateral.rootCrl);

        const caChain = `${rootCaPem}\n${intermediateCaPem}`;
        const tcbInfoSigningChain = `${tcbInfoSigningChainData.rootCaPem}\n${tcbInfoSigningChainData.tcbInfoSigningCertPem}`;
        const tcbInfoString = JSON.stringify(tcbInfo);
        const qeIdentityString = JSON.stringify(qeIdentity);

        const result = await qvl.verifyQuote(ctx.reqId, quote, pckCertPem, tcbInfoString, qeIdentityString, caChain, tcbInfoSigningChain, pckCertCrl, rootCrl, rootCaPem, tcbInfoSigningChainData.rootCaPem);

        const { status, isvQuoteStatus } = parseStatus(result.status, result.errorSource, ctx.log);
        if (status !== 200) {
            ctx.status = status;
            return;
        }
        /* Mandatory report fields */
        const report = {
            id:                      generateReportId(),
            timestamp:               prepareTimestampForReport(),
            version:                 5,
            attestationType:         'ECDSA',
            teeType:                 teeTypeForReport(quoteType, pckCertData.sgxType),
            isvQuoteStatus,
            isvQuoteBody:            base64quoteHeaderAndBodyOnly(quote, quoteType),
            tcbEvaluationDataNumber: qeIdentity.enclaveIdentity.tcbEvaluationDataNumber,
            tcbDate:                 tcbInfo.tcbInfo.issueDate,
        };

        /* Optional report fields */
        if (nonce) {
            report.nonce = nonce;
        }

        const pcesvn = pckCertData.pcesvn;
        const cpusvn = pckCertData.cpusvn;
        const tdxsvn = (quoteType === 'TDX') ? quote.slice(tdxsvnOffsetInQuote, tdxsvnOffsetInQuote + tdxsvnSize) : undefined;

        const matchedTcbInfoTcbLevel = matchTcbInfoTcbLevel(tcbInfo, cpusvn, pcesvn, tdxsvn);
        if (!matchedTcbInfoTcbLevel) {
            ctx.log.error(`Could not match TCB level (${JSON.stringify(cpusvn)}|${pcesvn}|{${JSON.stringify(tdxsvn)}) from certificate/quote to any TCB level from TCB Info`);
            ctx.status = 400;
            return;
        }
        ctx.log.info(`Matched to ${matchedTcbInfoTcbLevel.tcbStatus}. Matched TCB level is ${JSON.stringify(matchedTcbInfoTcbLevel)}`);

        const matchedEnclaveTcbTcbLevel = matchEnclaveTcbTcbLevel(qeIdentity, isvsvn);
        if (!matchedEnclaveTcbTcbLevel) {
            ctx.log.error(`Could not match ISVSVN (${isvsvn}) from quote to any TCB level from Enclave Identity`);
            ctx.status = 400;
            return;
        }
        ctx.log.info(`Matched Enclave TCB Level ${JSON.stringify(matchedEnclaveTcbTcbLevel)}`);

        if (['OK', 'TCB_OUT_OF_DATE', 'TCB_OUT_OF_DATE_AND_CONFIGURATION_NEEDED', 'CONFIGURATION_NEEDED', 'SW_HARDENING_NEEDED', 'CONFIGURATION_AND_SW_HARDENING_NEEDED'].includes(isvQuoteStatus)) {
            if (matchedTcbInfoTcbLevel.advisoryIDs || matchedEnclaveTcbTcbLevel.advisoryIDs) {
                report.advisoryURL = 'https://security-center.intel.com';
                const advisoryIds = collectAdvisoryIds(matchedTcbInfoTcbLevel, matchedEnclaveTcbTcbLevel);
                if (!_.isEmpty(advisoryIds)) {
                    report.advisoryIDs = _.sortedUniq(advisoryIds.sort());
                }
            }
        }

        if (['TCB_OUT_OF_DATE', 'TCB_OUT_OF_DATE_AND_CONFIGURATION_NEEDED'].includes(isvQuoteStatus)) {
            const tcbComponentsOutOfDate = collectTcbComponentsOutOfDate(quoteType, tcbInfo, matchedTcbInfoTcbLevel);
            if (!_.isEmpty(tcbComponentsOutOfDate)) {
                report.tcbComponentsOutOfDate = tcbComponentsOutOfDate;
            }
        }

        const configuration = configurationForReport(pckCertData);
        if (configuration.length > 0) {
            report.configuration = configuration;
        }

        await signReport(report, ctx);

        ctx.status = 200;
        ctx.body = report;
    }
    catch (error) {
        ctx.log.error(error);
        ctx.status = error.status || 500;
    }
}

/**
 * Concatenates and sorts advisoryIds from matched tcb levels
 * @param {TcbLevel} matchedTcbInfoTcbLevel - Tcb level from TcbInfo
 * @param {EnclaveTcbLevel} matchedEnclaveTcbTcbLevel - Tcb level from EnclaveTcb
 * @return {Array.<string>}
 */
function collectAdvisoryIds(matchedTcbInfoTcbLevel, matchedEnclaveTcbTcbLevel) {
    const advisoryIds = [];
    addAdvisoryIdsToArray(advisoryIds, matchedTcbInfoTcbLevel);
    addAdvisoryIdsToArray(advisoryIds, matchedEnclaveTcbTcbLevel);
    const sortedAdvisoryIds = _.sortedUniq(advisoryIds.sort());
    return sortedAdvisoryIds;
}

/**
 * Adds advisoryIds from tcbLevel to provided array
 * @param {Array.<string>} array
 * @param {TcbLevel|EnclaveTcbLevel} tcbLevel
 */
function addAdvisoryIdsToArray(array, tcbLevel) {
    const advisoryIDs = tcbLevel.advisoryIDs;
    if (_.isArray(advisoryIDs) && !_.isEmpty(advisoryIDs)) {
        array.push(...advisoryIDs);
    }
}

/**
 * Selects TcbComponents which are out of date
 * @param {string} quoteType
 * @param {TcbInfo} tcbInfo
 * @param {TcbLevel} matchedTcbInfoTcbLevel
 * @return {Array.<{category: string, type: string}>}
 */
function collectTcbComponentsOutOfDate(quoteType, tcbInfo, matchedTcbInfoTcbLevel) {
    const highestCpuSvn = getHighestCpuSvn(tcbInfo);

    let tcbComponentsOutOfDate = matchedTcbInfoTcbLevel.tcb.sgxtcbcomponents.reduce((filtered, svn, i) => {
        if ((svn.category || svn.type) && highestCpuSvn[i].svn > svn.svn) { filtered.push(_.omit(svn, 'svn')); } // copy only 'category' and 'type' fields if present
        return filtered;
    }, []);
    if (quoteType === 'TDX') {
        const highestTdxSvn = getHighestTdxSvn(tcbInfo);
        tcbComponentsOutOfDate = tcbComponentsOutOfDate.concat(matchedTcbInfoTcbLevel.tcb.tdxtcbcomponents.reduce((filtered, svn, i) => {
            if ((svn.category || svn.type) && highestTdxSvn[i].svn > svn.svn) { filtered.push(_.omit(svn, 'svn')); } // copy only 'category' and 'type' fields if present
            return filtered;
        }, []));
    }
    return tcbComponentsOutOfDate;
}

/**
 * Parse status from QVL to http status and isvQuoteStatus
 * @param {Number} status
 * @param {(Number|undefined)} source
 * @param {Logger} log
 * @returns {{status: Number, isvQuoteStatus: String?}} status
 */
function parseStatus(status, source, log) {
    const isvQuoteStatus = getIsvQuoteStatus(status);
    if (isvQuoteStatus !== null) {
        return { status: 200, isvQuoteStatus };
    }
    const msg = getErrorMessage(status, source);
    if (msg !== null) {
        log.error(msg);
        return { status: 400 };
    }

    if (status === qvlStatus.STATUS_TRUSTED_ROOT_CA_INVALID || status === qvlStatus.STATUS_TRUSTED_ROOT_CA_UNSUPPORTED_FORMAT) {
        log.error('Invalid trusted root CA cert. Check config.');
    }
    else {
        log.error('Unrecognized QVL status: ' + status);
    }

    return { status: 500 };
}

/**
 * Translates quote verification status (as defined in QuoteVerification.h in QVL) to isvQuoteStatus.
 * @param {Number} status
 * @returns {String?} isvQuoteStatus to corresponding qvlStatus or null if can't match qvlStatus
 */
function getIsvQuoteStatus(status) {
    switch (status) {
        case qvlStatus.STATUS_OK:
            return 'OK';
        case qvlStatus.STATUS_INVALID_QUOTE_SIGNATURE:
            return 'SIGNATURE_INVALID';
        case qvlStatus.STATUS_SGX_INTERMEDIATE_CA_REVOKED:
        case qvlStatus.STATUS_SGX_PCK_REVOKED:
        case qvlStatus.STATUS_PCK_REVOKED:
        case qvlStatus.STATUS_TCB_REVOKED:
            return 'REVOKED';
        case qvlStatus.STATUS_TCB_OUT_OF_DATE:
            return 'TCB_OUT_OF_DATE';
        case qvlStatus.STATUS_TCB_CONFIGURATION_NEEDED:
            return 'CONFIGURATION_NEEDED';
        case qvlStatus.STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED:
            return 'TCB_OUT_OF_DATE_AND_CONFIGURATION_NEEDED';
        case qvlStatus.STATUS_TCB_SW_HARDENING_NEEDED:
            return 'SW_HARDENING_NEEDED';
        case qvlStatus.STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED:
            return 'CONFIGURATION_AND_SW_HARDENING_NEEDED';
        default:
            return null;
    }
}

/**
 * Returns error message for quote verification status (as defined in QuoteVerification.h in QVL) and error source (as defined in verifyQuoteErrorSource in QVL wrapper)
 * @param {Number} status
 * @param {Number} source
 * @returns {String?} message or null if unrecognised status
 */
function getErrorMessage(status, source) {
    if (!Number.isInteger(source)) {
        return null;
    }
    const isStatusOneOf = (array, expectedErrorSource) => array.includes(status) && (expectedErrorSource === undefined || expectedErrorSource === source);
    const statusMessage = ` (qvlStatus: ${status}, errorSource: ${source})`;

    if (status === qvlStatus.STATUS_UNSUPPORTED_CERT_FORMAT && source === errorSource.VERIFY_PCK_CERTIFICATE) {
        return 'Some parameters may be null. ' +
            'Certs in PCK cert chain may not be properly encoded to PEM format (including trusted root). ' +
            'PCK cert chain may have wrong number of certs.';
    }
    if (isStatusOneOf([
        qvlStatus.STATUS_SGX_ROOT_CA_MISSING,
        qvlStatus.STATUS_SGX_ROOT_CA_INVALID_EXTENSIONS,
        qvlStatus.STATUS_SGX_ROOT_CA_INVALID_ISSUER,
    ], errorSource.VERIFY_PCK_CERTIFICATE) ||
        status === qvlStatus.STATUS_SGX_PCK_CERT_CHAIN_UNTRUSTED) {
        return 'Issue with parsing root CA cert' + statusMessage;
    }
    if (isStatusOneOf([
        qvlStatus.STATUS_SGX_INTERMEDIATE_CA_MISSING,
        qvlStatus.STATUS_SGX_INTERMEDIATE_CA_INVALID_EXTENSIONS,
        qvlStatus.STATUS_SGX_INTERMEDIATE_CA_INVALID_ISSUER
    ])) {
        return 'Issue with parsing intermediate CA cert' + statusMessage;
    }
    if (isStatusOneOf([
        qvlStatus.STATUS_SGX_PCK_MISSING,
        qvlStatus.STATUS_SGX_PCK_INVALID_EXTENSIONS,
        qvlStatus.STATUS_SGX_PCK_INVALID_ISSUER,
        qvlStatus.STATUS_UNSUPPORTED_PCK_CERT_FORMAT,
        qvlStatus.STATUS_INVALID_PCK_CERT
    ])) {
        return 'Issue with parsing PCK cert' + statusMessage;
    }
    if (isStatusOneOf([
        qvlStatus.STATUS_UNSUPPORTED_QUOTE_FORMAT,
        qvlStatus.STATUS_INVALID_QE_REPORT_SIGNATURE,
        qvlStatus.STATUS_INVALID_QE_REPORT_DATA,
        qvlStatus.STATUS_QE_IDENTITY_MISMATCH,
        qvlStatus.STATUS_TDX_MODULE_MISMATCH,
    ])) {
        return 'Issue with parsing quote' + statusMessage;
    }
    switch (status) {
        case qvlStatus.STATUS_TCB_NOT_SUPPORTED:
            return 'No matching TCB Level found';
        case qvlStatus.STATUS_SGX_PCK_CERT_CHAIN_EXPIRED:
            return 'Either of certs in PCK cert chain has expired.';
        default:
            return null;
    }
}

/**
 * Reads certificate chain from quote
 * @param {string} reqId - request id
 * @param {Buffer} quote
 * @throws {Error} if quote is invalid or has type different than 5
 * @returns {string} certification data
 */
async function getType5CertificationDataFromQuote(reqId, quote) {
    let certificationData;
    try {
        certificationData = await qvl.getCertificationData(reqId, quote);
    }
    catch (e) {
        throw new Error('Failed to retrieve certification data from quote', e);
    }

    if (certificationData.type !== 5) {
        throw new Error('Not supported certification data type: ' + certificationData.type);
    }
    return certificationData.data;
}

/**
 * Reads data from special extensions in PCK Certificate
 * @param {string} reqId
 * @param {string} pckCertPem
 * @returns {Promise<{fmspc: string, sgxType: string, dynamicPlatform: boolean, cachedKeys: boolean, smtEnabled: boolean}>}
 */
async function getPckCertificateData(reqId, pckCertPem) {
    try {
        return await qvl.getPckCertificateData(reqId, pckCertPem);
    }
    catch (error)  {
        throw new Error('PCK Cert does not contain required extensions', error);
    }
}

/**
 * Reads TcbInfo and TcbInfoIssuerChain from PCS response and parses TCB Info Signing Chain
 * @param {{ status: number, body: {}}} response
 * @throws {Error} if http status is different from 200 OK
 * @returns {{tcbInfo: TcbInfo, tcbInfoIssuerChain: string}} response body
 */
async function readTcbInfoAndIssuerChainFromResponse(response) {
    let err;
    switch (response.status) {
        case STATUSES.STATUS_OK.httpCode:
            break;
        case STATUSES.STATUS_TCB_NOT_FOUND.httpCode:
            err = new Error('Failed to retrieve required TcbInfo. PCS returned status: ' + response.status);
            err.status = 400;
            throw err;
        default:
            err = new Error('Failed to retrieve required TcbInfo. PCS returned status: ' + response.status);
            err.status = 500;
            throw err;
    }
    const tcbInfo = response.body;
    const tcbInfoIssuerChain = decodeURIComponent(response.headers['tcb-info-issuer-chain']);
    const tcbInfoSigningChainData = await certificateChainParser.parseTcbInfoSigningChainWithSpecificRoot(trustedRootPublicKey,
        tcbInfoIssuerChain);
    return {
        tcbInfo,
        tcbInfoIssuerChain,
        tcbInfoSigningChainData
    };
}

/**
 * Reads QeIdentity from PCS response
 * @param {{ status: number, body: {}}} response
 * @throws {Error} if http status is different from 200 OK
 * @returns {{}} response body
 */
function readQeIdentityFromResponse(response) {
    if (response.status !== STATUSES.STATUS_OK.httpCode) {
        throw new Error('Failed to retrieve required QeIdentity. PCS returned status: ' + response.status);
    }
    return response.body;
}

/**
 * Requests VCS to sign provided report structure.
 * Sets X-IASReport-Signing-Certificate and X-IASReport-Signature headers.
 * @param {*} report to sign
 * @param {*} ctx - koa context
 */
async function signReport(report, ctx) {
    ctx.set('X-IASReport-Signing-Certificate', attestationReportSigningChain);
    const signResponse = await vcs.signVerificationReport(report, ctx.reqId, ctx.log);
    if (signResponse.status !== STATUSES.STATUS_OK.httpCode) {
        throw new Error('Failed to sign the report. VCS returned status: ' + signResponse.status);
    }
    const signature = signResponse.body.signature;
    ctx.set('X-IASReport-Signature', signature);
}

/**
 * @typedef {Object} QuoteVersion
 * @property {number} quoteVersion - 3, 4 or 5
 * @property {string} quoteType - SGX or TDX
 * @property {number} quoteBodyVersion - 1.0 or 1.5
 */

/**
 * Determines quote version and type: SGX, TDX1.0, TDX1.5
 * @param {Buffer} quote
 * @returns {QuoteVersion} - SGX or TDX
 */
function readQuoteVersion(quote) {
    let quoteType = 'SGX';
    const quoteVersion = quote.readUInt16LE();
    if (quoteVersion >= 4) {
        const teeType = quote.readUint32LE(4);
        if (teeType === 0x00000081) {
            quoteType = 'TDX';
        }
    }
    let quoteBodyVersion = 1.0;
    if (quoteVersion === 5) {
        const quoteBodyType = quote.readUInt16LE(48);
        if (quoteBodyType === 3) {
            quoteBodyVersion = 1.5;
        }
    }
    return {
        quoteVersion,
        quoteType,
        quoteBodyVersion
    };
}

const V3_ISVSVN_QUOTE_OFFSET = 822;
const V4_SGX_ISVSVN_QUOTE_OFFSET = 828;
const V4_TDX10_ISVSVN_QUOTE_OFFSET = 1028;
const V5_SGX_ISVSVN_QUOTE_OFFSET = 834;
const V5_TDX10_ISVSVN_QUOTE_OFFSET = 1034;
const V5_TDX15_ISVSVN_QUOTE_OFFSET = 1098;

/**
 * Reads ISVSVN from different types of quote
 * @param {Buffer} quote
 * @return {number} ISVSVN
 */
function readIsvsvn(quote) {
    const { quoteVersion, quoteType, quoteBodyVersion } = readQuoteVersion(quote);

    let isvsvnOffset = 0;
    if (quoteVersion === 3) {
        isvsvnOffset = V3_ISVSVN_QUOTE_OFFSET;
    }
    else if (quoteVersion === 4) {
        isvsvnOffset = (quoteType === 'TDX') ? V4_TDX10_ISVSVN_QUOTE_OFFSET : V4_SGX_ISVSVN_QUOTE_OFFSET;
    }
    else if (quoteVersion === 5) {
        if (quoteType === 'SGX') {
            isvsvnOffset = V5_SGX_ISVSVN_QUOTE_OFFSET;
        }
        else if (quoteBodyVersion < 1.25) { // 1.0
            isvsvnOffset = V5_TDX10_ISVSVN_QUOTE_OFFSET;
        }
        else if (quoteBodyVersion < 1.75) {  // 1.5
            isvsvnOffset = V5_TDX15_ISVSVN_QUOTE_OFFSET;
        }
        else {
            throw new Error('Unsupported quote body version: ' + quoteBodyVersion);
        }
    }
    else {
        throw new Error('Unsupported quote version: ' + quoteType);
    }
    if (isvsvnOffset > quote.length - 2) {
        throw new Error('Version detection issue. Quote is too short to read ISVSVN.');
    }
    return quote.readUInt16LE(isvsvnOffset);
}

/**
 * Converts crl to string format expected by QVL
 * @param {{status: number, body: Buffer}} crl - response from getCrlFromDistributionPoint
 * @returns {string} utf8 string for PEM, hex string for DER
 */
function parseCrlFromDistributionPoint(crl) {
    if (crl.status !== STATUSES.STATUS_OK.httpCode) {
        throw new Error('Failed to retrieve one of CRLs. Distribution Point returned status: ' + crl.status);
    }
    // PEM format - QVL requires utf8 string
    if (crl.body.toString().startsWith('-----BEGIN')) {
        return crl.body.toString();
    }
    // DER format - QVL requires hex string
    else {
        return crl.body.toString('hex');
    }
}

/**
 * Generates long numeric id as string
 * @returns {string}
 */
function generateReportId() {
    return String(BigInt('0x' + random.uuid()));
}

/**
 * Returns current date and time in UTC in ISO 8601 standard
 * @returns {string} timestamp in ISO 8601 standard
 */
function prepareTimestampForReport() {
    const format = 'YYYY-MM-DDTHH:mm:ss';
    const utcTimestamp = moment.utc(new Date()).format(format);
    return utcTimestamp + 'Z';
}

/**
 * Converts enum values returned from QVL to enum values to be returned by QVS
 * @param {string} quoteType
 * @param {string} sgxType
 * @throws {Error} if sgxType has not accepted value
 * @returns {string} string representing enum to be returned in report
 */
function teeTypeForReport(quoteType, sgxType) {
    if (quoteType === 'TDX') {
        return 'TDX';
    }
    if (sgxType === 'Standard') {
        return 'SGX_STANDARD';
    }
    if (sgxType === 'Scalable') {
        return 'SGX_SCALABLE';
    }
    if (sgxType === 'ScalableWithIntegrity') {
        return 'SGX_SCALABLE_WITH_INTEGRITY';
    }
    throw new Error('Unsupported sgxType');
}

/**
 * Prepares a configuration for report based on PCK certification data
 * @param {*} pckCertData
 * @returns {Array.<string>}
 */
function configurationForReport(pckCertData) {
    const configuration = [];
    if (pckCertData.dynamicPlatform) {
        configuration.push('DYNAMIC_PLATFORM');
    }
    if (pckCertData.cachedKeys) {
        configuration.push('CACHED_KEYS');
    }
    if (pckCertData.smtEnabled) {
        configuration.push('SMT_ENABLED');
    }
    return configuration;
}

/**
 * Crops quote buffer to header and body fields and converts result to base64 string
 * @param {Buffer} quote
 * @param {string} quoteType - SGX or TDX
 * @returns {string} base64 representation of quote header and body
 */
function base64quoteHeaderAndBodyOnly(quote, quoteType) {
    const quoteHeaderSize = 48;
    let quoteBodySize = 384;
    if (quoteType === 'TDX') {
        quoteBodySize = 584;
    }
    const croppedBuffer = quote.subarray(0, quoteHeaderSize + quoteBodySize);
    return croppedBuffer.toString('base64');
}

/**
 * Get URL from CRL distribution point from certificate
 * @param {string} reqId
 * @param {string} certificate - PEM format
 * @returns {string}
 */
async function getCrlUrl(reqId, certificate) {
    const crlDistributionPoint = await qvl.getCrlDistributionPoint(reqId, certificate);
    const idx = crlDistributionPoint.indexOf(uriString);
    if (idx === -1) {
        throw Error('CRL Distribution point is in wrong format ' + crlDistributionPoint);
    }
    return crlDistributionPoint.substring(idx + uriString.length, crlDistributionPoint.length);
}

/**
 * Finds TcbLevel with provided cpusvn, pcesvn and optional tdxsvn in tcbInfo
 * @param {TcbInfo} tcbInfo 
 * @param {string} cpusvn 
 * @param {string} pcesvn 
 * @param {string} [tdxsvn] 
 * @returns {TcbLevel}
 */
function matchTcbInfoTcbLevel(tcbInfo, cpusvn, pcesvn, tdxsvn) {
    const matchedTcbLevel = tcbInfo.tcbInfo.tcbLevels.find(level => {
        const cpuSvnEqualOrGreater = cpusvn.every((svn, i) => svn >= level.tcb.sgxtcbcomponents[i].svn); // Readability trade off for performance. Invert condition and use 'some' instead of 'every' to gain some performance
        if (cpuSvnEqualOrGreater && pcesvn >= level.tcb.pcesvn) {
            if (tdxsvn) {
                const teeSvnEqualOrGreater = tdxsvn.every((svn, i) => svn >= level.tcb.tdxtcbcomponents[i].svn); // Readability trade off for performance. Invert condition and use 'some' instead of 'every' to gain some performance
                return (teeSvnEqualOrGreater && tdxsvn[1] === level.tcb.tdxtcbcomponents[1].svn);
            }
            else {
                return true;
            }
        }
        return false;
    });
    return matchedTcbLevel;
}

/**
 * 
 * @param {EnclaveIdentity} qeIdentity 
 * @param {string} isvsvn 
 * @returns {EnclaveTcbLevel}
 */
function matchEnclaveTcbTcbLevel(qeIdentity, isvsvn) {
    const matchedTcbLevel = qeIdentity.enclaveIdentity.tcbLevels.find(level => level.tcb.isvsvn === isvsvn);
    return matchedTcbLevel;
}

/**
 * 
 * @param {TcbInfo} tcbInfo 
 * @returns 
 */
function getHighestCpuSvn(tcbInfo) {
    return getHighestSvn(tcbInfo, x => x.sgxtcbcomponents);
}

/**
 * 
 * @param {TcbInfo} tcbInfo 
 * @returns 
 */
function getHighestTdxSvn(tcbInfo) {
    return getHighestSvn(tcbInfo, x => x.tdxtcbcomponents);
}

/**
 * 
 * @param {TcbInfo} tcbInfo 
 * @param {function} svnSelector 
 * @returns 
 */
function getHighestSvn(tcbInfo, svnSelector) {
    return tcbInfo.tcbInfo.tcbLevels
        .map(x => svnSelector(x.tcb))
        .reduce((highest, curr) => (curr.every((svn, i) => svn.svn >= highest[i].svn) ? curr : highest));

}

module.exports = {
    verifyAttestationEvidence
};
