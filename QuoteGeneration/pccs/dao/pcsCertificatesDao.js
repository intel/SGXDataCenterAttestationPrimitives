/**
 *
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
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

const { pcs_certificates }= require('./models/');
const Constants = require('../constants/index.js');
const PccsError = require('../utils/PccsError.js');
const PCCS_STATUS = require('../constants/pccs_status_code.js');

// Update or insert a PCS certificate
exports.upsertPcsCertificates = async function(pcsCertJson){
    return await pcs_certificates.upsert(pcsCertJson);
}

// Split a certchain into two certificates (intermediate or singing ca, root ca)
split_chain = function(certchain){
    if (certchain == null)
        return null;

    let pos = certchain.lastIndexOf('-----BEGIN%20CERTIFICATE-----');
    if (pos == -1)
        return null;

    const cer1 = certchain.substring(0, pos);
    const cer2 = certchain.substring(pos, certchain.length);
    return new Array(cer1, cer2);
}

// Update or insert a PCS certificate
upsertPcsCertificates = async function(id, cert){
    return await pcs_certificates.upsert({
        id: id,
        cert: cert
    });
}

// Update or insert a certificate chain (intermediate or signing cert | root cert)
upsertPcsCertchain = async function(certchain, first_cert_id, second_cert_id){
    const certs = split_chain(certchain);
    if (certs == null)
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_INVALID_REQ);
    await upsertPcsCertificates(first_cert_id, certs[0]); 
    await upsertPcsCertificates(second_cert_id, certs[1]); 
    return certs[1];  // return the root cert
}

// Update or insert pck-certificate-issuer-chain
exports.upsertPckCertificateIssuerChain = async function(pck_certchain) {
    return await upsertPcsCertchain(pck_certchain, 
        Constants.PROCESSOR_INTERMEDIATE_CERT_ID, 
        Constants.PROCESSOR_ROOT_CERT_ID);
}

// Update or insert pck-crl-issuer-chain
exports.upsertPckCrlCertchain = async function(pck_crl_certchain) {
    return await upsertPcsCertchain(pck_crl_certchain, 
        Constants.PROCESSOR_INTERMEDIATE_CERT_ID, 
        Constants.PROCESSOR_ROOT_CERT_ID);
}

// Update or insert tcb-info-issuer-chain
exports.upsertTcbInfoIssuerChain = async function(tcbinfo_certchain) {
    return await upsertPcsCertchain(tcbinfo_certchain, 
        Constants.PROCESSOR_SIGNING_CERT_ID, 
        Constants.PROCESSOR_ROOT_CERT_ID);
}

// Update or insert enclave-identity-issuer-chain
exports.upsertEnclaveIdentityIssuerChain = async function(enclave_identity_certchain) {
    return await upsertPcsCertchain(enclave_identity_certchain, 
        Constants.PROCESSOR_SIGNING_CERT_ID, 
        Constants.PROCESSOR_ROOT_CERT_ID);
}

exports.getCertificateById = async function(ca_id) {
    return await pcs_certificates.findOne({
        where: {
            id: ca_id
        }
    });
}

exports.upsertRootCACrl = async function(rootcacrl) {
    return await pcs_certificates.upsert({
        id: Constants.PROCESSOR_ROOT_CERT_ID,
        crl: rootcacrl
    });
}

