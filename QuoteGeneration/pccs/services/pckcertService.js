/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
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
const logger = require('../utils/Logger.js');
const pckcertDao = require('../dao/pckcertDao.js');
const platformTcbsDao = require('../dao/platformTcbsDao.js');
const platformsDao = require('../dao/platformsDao.js')
const fmspcTcbDao = require('../dao/fmspcTcbDao.js');
const pcsCertificatesDao = require('../dao/pcsCertificatesDao.js');
const pckCertchainDao = require('../dao/pckCertchainDao.js');
const PccsError = require('../utils/PccsError.js');
const PCCS_STATUS = require('../constants/pccs_status_code.js');
const Config = require('config');
const Constants = require('../constants/index.js');
const PcsClient = require('../pcs_client/pcs_client.js');
const {sequelize, Sequelize} = require('../dao/models/');
const X509 = require('../x509/x509.js');
const PckLib = require('../lib_wrapper/pcklib_wrapper.js');

exports.getPcsVersion = function()
{
    let pcs_url = Config.get('uri');
    let verstr = pcs_url.match(/\/v([1-9][0-9]*)\//);
    if (verstr.length == 0)
        return 1;

    let ver = verstr[0].substr(2).slice(0,-1);
    return parseInt(ver);
}

// Try to get PCK certs from Intel PCS for the platform with {pce_id, platform_manifest}, 
// and if platform manifest is not provided, then use {pce_id, enc_ppid} instead. 
// Refresh the cache DB after a successful PCK certs retrieval. 
// If raw TCB is not null, call the PCK cert selection tool to select the "best" cert for this
// raw TCB and update cache DB
exports.getPckCertFromPCS = async function(qeid, cpusvn, pcesvn, pceid, enc_ppid, platform_manifest)
{
    let result = {};
    if (!enc_ppid && !platform_manifest) {
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_INVALID_REQ);
    }

    let pck_server_res;
    if (platform_manifest && this.getPcsVersion() >= 3) {
        // if platform manifest is provided, will call Intel PCS API with platform manifest
        pck_server_res = await PcsClient.getCertsWithManifest(platform_manifest, pceid);
    }
    else {
        // if enc_ppid is all zero, return NOT_FOUND
        if (enc_ppid.match(/^0+$/)) {
            throw new PccsError(PCCS_STATUS.PCCS_STATUS_NOT_FOUND);
        }

        // Call Intel PCS API with encrypted PPID
        pck_server_res = await PcsClient.getCerts(enc_ppid, pceid);
    }

    // check HTTP status
    if (pck_server_res.statusCode != Constants.HTTP_SUCCESS) {
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_NO_CACHE_DATA);
    }

    // Get PCK certificate issuer chain
    const pck_certchain = pck_server_res.headers[Constants.SGX_PCK_CERTIFICATE_ISSUER_CHAIN];

    // Parse the response body
    let pckcerts = null;
    if (typeof pck_server_res.body === 'object') {
        pckcerts = pck_server_res.body;
    }
    else if (typeof pck_server_res.body === 'string') {
        pckcerts = JSON.parse(pck_server_res.body);
    }
    else {
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_INTERNAL_ERROR);
    }
    // The latest PCS service may return 'Not available' in the certs array, need to filter them out
    pckcerts = pckcerts.filter((pckcert)=>{
        return(pckcert.cert != 'Not available');
    });
    if (pckcerts.length == 0) {
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_NO_CACHE_DATA);
    }

    // parse arbitary cert to get fmspc value
    const x509 = new X509();
    if (!x509.parseCert(unescape(pckcerts[0].cert))) {
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_INTERNAL_ERROR);
    }

    if (x509.fmspc == null || x509.ca == null) {
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_INTERNAL_ERROR);
    }
    const fmspc = x509.fmspc.toUpperCase();

    // get tcbinfo for this fmspc
    pck_server_res = await PcsClient.getTcb(fmspc);
    if (pck_server_res.statusCode != Constants.HTTP_SUCCESS) {
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_NO_CACHE_DATA);
    }
    const tcbinfo = JSON.parse(pck_server_res.body);
    const tcbinfo_str = JSON.stringify(tcbinfo);

    // Before we flush the caching database, get current raw TCBs that are already cached
    // We need to re-run PCK cert selection tool for existing raw TCB levels due to certs change
    let cached_platform_tcbs = await platformTcbsDao.getPlatformTcbsById(qeid, pceid);

    await sequelize.transaction(async (t)=>{
        // Update the platform entry in the cache
        await platformsDao.upsertPlatform(qeid, 
            pceid, 
            platform_manifest, 
            enc_ppid, 
            fmspc,
            x509.ca
        );

        // flush pck_cert 
        await pckcertDao.deleteCerts(qeid, pceid);
        for (const pckcert of pckcerts) {
            await pckcertDao.upsertPckCert(qeid, 
                pceid, 
                pckcert.tcbm, 
                unescape(pckcert.cert));
        } 

        // delete old TCB mappings
        await platformTcbsDao.deletePlatformTcbsById(qeid, pceid);

        // Update or insert fmspc_tcbs 
        await fmspcTcbDao.upsertFmspcTcb({
            fmspc: fmspc,
            tcbinfo: tcbinfo
        });
        // Update or insert PCK Certchain
        await pckCertchainDao.upsertPckCertchain(x509.ca);
        // Update or insert PCS certificates 
        await pcsCertificatesDao.upsertPckCertificateIssuerChain(x509.ca, pck_certchain);
    });

    // For all cached TCB levels, re-run PCK cert selection tool
    var pem_certs = pckcerts.map(o => unescape(o.cert));
    for (const platform_tcb of cached_platform_tcbs) {
        let cert_index = PckLib.pck_cert_select(platform_tcb.cpu_svn, 
            platform_tcb.pce_svn, platform_tcb.pce_id, tcbinfo_str, pem_certs, pem_certs.length);
        if (cert_index == -1) {
            throw new PccsError(PCCS_STATUS.PCCS_STATUS_NO_CACHE_DATA);
        }
        await platformTcbsDao.upsertPlatformTcbs(platform_tcb.qe_id, 
            platform_tcb.pce_id, 
            platform_tcb.cpu_svn, 
            platform_tcb.pce_svn, 
            pckcerts[cert_index].tcbm);
    }

    if (!cpusvn || !pcesvn)
        return {}; // end here if raw TCB not provided

    // get the best cert with PCKCertSelectionTool for this raw TCB
    let cert_index = PckLib.pck_cert_select(cpusvn, pcesvn, pceid, tcbinfo_str, pem_certs, pem_certs.length);
    if (cert_index == -1) {
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_NO_CACHE_DATA);
    }

    // create an entry for the new TCB level
    await platformTcbsDao.upsertPlatformTcbs(qeid, 
        pceid, 
        cpusvn, 
        pcesvn, 
        pckcerts[cert_index].tcbm 
    );

    result[Constants.SGX_TCBM] = pckcerts[cert_index].tcbm;
    result[Constants.SGX_PCK_CERTIFICATE_ISSUER_CHAIN] = pck_certchain;
    result["cert"] = pem_certs[cert_index];

    return result;
}

// If a new raw TCB was reported, needs to run PCK Cert Selection for this raw TCB 
exports.pckCertSelection = async function(qeid, cpusvn, pcesvn, pceid, enc_ppid, fmspc, ca)
{
    let result = {};
    let pck_certs = await pckcertDao.getCerts(qeid, pceid);
    if (pck_certs == null)
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_NO_CACHE_DATA);

    let pem_certs = [];
    for (i = 0; i < pck_certs.length; i++) {
        pem_certs.push(pck_certs[i].pck_cert);
    }

    let tcbinfo = await fmspcTcbDao.getTcbInfo(fmspc);
    if (tcbinfo == null || tcbinfo.tcbinfo == null)
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_NO_CACHE_DATA);
    
    let tcbinfo_str = tcbinfo.tcbinfo.toString('utf8');
    let cert_index = PckLib.pck_cert_select(cpusvn, pcesvn, pceid, tcbinfo_str, pem_certs, pem_certs.length);
    if (cert_index == -1) {
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_NO_CACHE_DATA);
    }

    let certchain = await pckCertchainDao.getPckCertChain(ca);
    if (certchain == null)
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_NO_CACHE_DATA);

    result[Constants.SGX_TCBM] = pck_certs[cert_index].tcbm;
    result[Constants.SGX_PCK_CERTIFICATE_ISSUER_CHAIN] = certchain.intmd_cert + certchain.root_cert;;
    result["cert"] = pem_certs[cert_index];

    // create an entry for the new TCB level in platform_tcbs table
    await platformTcbsDao.upsertPlatformTcbs(qeid, 
        pceid, 
        cpusvn, 
        pcesvn, 
        pck_certs[cert_index].tcbm 
    );

    return result;
}

exports.getPckCert=async function(qeid, cpusvn, pcesvn, pceid, enc_ppid) {
    let pckcert = null;

    const platform = await platformsDao.getPlatform(qeid, pceid);
    if (platform != null) {
        // query pck cert from cache DB
        pckcert = await pckcertDao.getCert(qeid, cpusvn, pcesvn, pceid);
    }

    let result = {};
    if (pckcert == null) {
        if (platform == null) {
            if (Config.get(Constants.CONFIG_OPTION_CACHE_FILL_MODE) == Constants.CACHE_FILL_MODE_LAZY) {
                // for LAZY mode, if no record found in local database, then request the cert from Intel PCS service
                result = await this.getPckCertFromPCS(qeid, cpusvn, pcesvn, pceid, enc_ppid, platform ? platform.platform_manifest : '');
            }
            else {
                    throw new PccsError(PCCS_STATUS.PCCS_STATUS_PLATFORM_UNKNOWN);    
            }
        }
        else {
            // Always treat presence of platform record as platform collateral is cached
            result = await this.pckCertSelection(qeid, cpusvn, pcesvn, pceid, enc_ppid, platform.fmspc, platform.ca);
        }
    }
    else {
        result[Constants.SGX_TCBM] = pckcert.tcbm;
        result[Constants.SGX_PCK_CERTIFICATE_ISSUER_CHAIN] = pckcert.intmd_cert + pckcert.root_cert;
        result["cert"] = pckcert.pck_cert;
    }

    return result;
}
