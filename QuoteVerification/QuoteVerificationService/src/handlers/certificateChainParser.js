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

 const { X509Certificate } = require('crypto');
 
/**
 * Splits chain of certificates in PEM format
 * @param {string} certificateChain 
 * @returns {Array.<string>} array of certificates in PEM format
 */
 function splitCertificateChain(certificateChain) {
    return certificateChain
        .replaceAll('\n-----BEGIN CERTIFICATE-----', '-----BEGIN CERTIFICATE-----')
        .split('-----END CERTIFICATE-----')
        .slice(0, -1)
        .map(i => i + '-----END CERTIFICATE-----');
}

/**
 *
 * @param {string[]} chain
 * @returns {Promise<Awaited<X509Certificate>[]>}
 */
async function parseChain(chain) {
     return Promise.all(chain.map(async(pem) => new X509Certificate(pem)));
}

/**
 *
 * @param {X509Certificate[]} parsedChain
 * @param {string} rootPublicKey
 * @returns {number}
 */
function findRoot(parsedChain, rootPublicKey) {
    const rootCaIndex = parsedChain.findIndex(cert => {
        const pubKey = cert.publicKey.export({ type: 'spki', format: 'der' }).toString('hex');
        return pubKey === rootPublicKey;
    });
    if (rootCaIndex < 0) {
        throw new Error(`No trusted root CA in provided chain. Expected public key: ${rootPublicKey}`);
    }

    return rootCaIndex;
}

/**
 * @typedef {Object} TcbInfoSigningChainInformation
 *
 * @property {X509Certificate} rootCa
 * @property {X509Certificate} tcbSigningCert
 *
 * @property {string} rootCaPem
 * @property {string} tcbSigningCertPem
 *
 */

/**
 * Parses TCB Signing chain
 * @param {string} rootPublicKey
 * @param {string} tcbInfoSigningChain
 * @returns {TcbInfoSigningChainInformation}
 *
 */
async function parseTcbInfoSigningChainWithSpecificRoot(rootPublicKey, tcbInfoSigningChain) {
    const tcbChain = splitCertificateChain(tcbInfoSigningChain);
    if (tcbChain.length !== 2) {
        throw new Error('TCB Info Signing Chain is not a chain of 2 certificates in PEM format' + tcbInfoSigningChain);
    }

    if (tcbChain.length !== [...new Set(tcbChain)].length) {
        throw new Error('TCB Info Signing Chain contains duplicated certificates');
    }
    const parsedChain = await parseChain(tcbChain);
    const rootCaIndex = findRoot(parsedChain, rootPublicKey);

    const tcbInfoSigningCertIndex = parsedChain.findIndex((cert, index) => index !== rootCaIndex &&
        cert.issuer === parsedChain[rootCaIndex].subject);

    if (tcbInfoSigningCertIndex < 0) {
        throw new Error('No TCB Info Signing Cert issued by trusted root CA found in provided chain.');
    }
    return {
        // X509 Certificates
        rootCa:                parsedChain[rootCaIndex],
        tcbInfoSigningCert:    parsedChain[tcbInfoSigningCertIndex],
        // PEM Certificates
        rootCaPem:             tcbChain[rootCaIndex],
        tcbInfoSigningCertPem: tcbChain[tcbInfoSigningCertIndex]
    };
}

/**
 * @typedef {Object} PckChainInformation
 *
 * @property {X509Certificate} rootCa
 * @property {X509Certificate} intermediateCa
 * @property {X509Certificate} pckCert
 *
 * @property {string} rootCaPem
 * @property {string} intermediateCaPem
 * @property {string} pckCertPem
 *
 */

/**
 * Parses PCK certificate chain
 * @param {string} rootPublicKey
 * @param {string} certificationData 
 * @returns {PckChainInformation}
 */
async function parseCertificateChainWithSpecificRoot(rootPublicKey, certificationData) {
    const pckChain = splitCertificateChain(certificationData);

    if (pckChain.length !== 3) {
        throw new Error('Certification data is not a chain of 3 certificates in PEM format' + certificationData);        
    }

    if (pckChain.length !== [...new Set(pckChain)].length) {
        throw new Error('Certification data contains duplicated certificates');
    }

    const parsedChain = await parseChain(pckChain);
    const rootCaIndex = findRoot(parsedChain, rootPublicKey);

    const intermediateCaIndex = parsedChain.findIndex((cert, index) => index !== rootCaIndex &&
        cert.issuer === parsedChain[rootCaIndex].subject);
    if (intermediateCaIndex < 0) {
        throw new Error('No intermediate CA issued by trusted root CA found in provided chain.');
    }

    const pckCertIndex = parsedChain.findIndex((cert, index) => index !== rootCaIndex &&
        index !== intermediateCaIndex &&
        cert.issuer === parsedChain[intermediateCaIndex].subject);
    if (pckCertIndex < 0) {
        throw new Error('No PCK cert issued by intermediate CA found in provided chain.');
    }

    return {
        // X509 Certificates
        rootCa:            parsedChain[rootCaIndex],
        intermediateCa:    parsedChain[intermediateCaIndex],
        pckCert:           parsedChain[pckCertIndex],
        // PEM Certificates
        rootCaPem:         pckChain[rootCaIndex],
        intermediateCaPem: pckChain[intermediateCaIndex],
        pckCertPem:        pckChain[pckCertIndex]
    };
}

module.exports = {
    parseCertificateChainWithSpecificRoot,
    parseTcbInfoSigningChainWithSpecificRoot
};
