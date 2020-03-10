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

// Get PCK cert from PCS for platform {qeid, cpusvn, pcesvn, pce_id, enc_ppid} and update cache DB
exports.getPckCertFromPCS = async function(qeid, cpusvn, pcesvn, pceid, enc_ppid, platform_manifest)
{
    let result = {};
    if (enc_ppid == null) {
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_INVALID_REQ);
    }

    // if enc_ppid is all zero, return NOT_FOUND
    if (enc_ppid.match(/^0+$/)) {
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_NOT_FOUND);
    }

    // contact Intel PCS service to get PCK certs for this platform
    let pck_server_res = await PcsClient.getCerts(enc_ppid, pceid);

    // check HTTP status
    if (pck_server_res.statusCode != Constants.HTTP_SUCCESS) {
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_NOT_FOUND);
    }

    // Get PCK certificate issuer chain
    const pck_certchain = pck_server_res.headers[Constants.SGX_PCK_CERTIFICATE_ISSUER_CHAIN];

    // Parse the response body
    const pckcerts = JSON.parse(pck_server_res.body);
    if (pckcerts.length == 0) {
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_NOT_FOUND);
    }

    // parse arbitary cert to get fmspc value
    const x509 = new X509();
    if (!x509.parseCert(unescape(pckcerts[0].cert))) {
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_INTERNAL_ERROR);
    }

    if (x509.fmspc == null) {
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_INTERNAL_ERROR);
    }
    const fmspc = x509.fmspc.toUpperCase();

    // get tcbinfo for this fmspc
    pck_server_res = await PcsClient.getTcb(fmspc);
    if (pck_server_res.statusCode != Constants.HTTP_SUCCESS) {
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_NOT_FOUND);
    }

    const tcbinfo = JSON.parse(pck_server_res.body);
    const tcbinfo_str = JSON.stringify(tcbinfo);

    // get the best cert with PCKCertSelectionTool for this raw TCB
    var pem_certs = pckcerts.map(o => unescape(o.cert));
    let cert_index = PckLib.pck_cert_select(cpusvn, pcesvn, pceid, tcbinfo_str, pem_certs, pem_certs.length);
    if (cert_index == -1) {
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_NOT_FOUND);
    }

    result[Constants.SGX_TCBM] = pckcerts[cert_index].tcbm;
    result[Constants.SGX_PCK_CERTIFICATE_ISSUER_CHAIN] = pck_certchain;
    result["cert"] = pem_certs[cert_index];

    // update or insert collaterals including fmspc_tcbs, platforsm, pck_cert and platform_tcbs
    await sequelize.transaction(async (t)=>{
        // Update the platform entry in the cache
        await platformsDao.upsertPlatform(qeid, 
            pceid, 
            platform_manifest, 
            enc_ppid, 
            fmspc
        );

        // flush and add PCK certs
        await pckcertDao.deleteCerts(qeid, pceid);
        for (const pckcert of pckcerts) {
            await pckcertDao.upsertPckCert(qeid, 
                pceid, 
                pckcert.tcbm, 
                unescape(pckcert.cert));
        } 

        // Before we update or insert the new raw TCB, get current raw TCBs that are already cached
        // We need to re-run PCK cert selection tool for existing raw TCB levels due to certs change
        let cached_platform_tcbs = await platformTcbsDao.getPlatformTcbsById(qeid, pceid);

        // create an entry for the new TCB level
        await platformTcbsDao.upsertPlatformTcbs(qeid, 
            pceid, 
            cpusvn, 
            pcesvn, 
            pckcerts[cert_index].tcbm 
        );
        
        // For all cached TCB levels, re-run PCK cert selection tool
        for (const platform_tcb of cached_platform_tcbs) {
            cert_index = PckLib.pck_cert_select(platform_tcb.cpu_svn, 
                platform_tcb.pce_svn, platform_tcb.pce_id, tcbinfo_str, pem_certs, pem_certs.length);
            if (cert_index == -1) {
                throw new PccsError(PCCS_STATUS.PCCS_STATUS_NOT_FOUND);
            }
            await platformTcbsDao.upsertPlatformTcbs(platform_tcb.qe_id, 
                platform_tcb.pce_id, 
                platform_tcb.cpu_svn, 
                platform_tcb.pce_svn, 
                pckcerts[cert_index].tcbm);
        }

        // Update or insert fmspc_tcbs 
        await fmspcTcbDao.upsertFmspcTcb({
            fmspc: fmspc,
            tcbinfo: tcbinfo
        });
        // Update or insert PCK Certchain
        await pckCertchainDao.upsertPckCertchain();
        // Update or insert PCS certificates 
        await pcsCertificatesDao.upsertPckCertificateIssuerChain(pck_certchain);
    });

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
        if (Config.get(Constants.CONFIG_OPTION_CACHE_FILL_MODE) == Constants.CACHE_FILL_MODE_LAZY) {
            // for LAZY mode, if no record found in local database, then request the cert from Intel PCS service
            result = await this.getPckCertFromPCS(qeid, cpusvn, pcesvn, pceid, enc_ppid, platform ? platform.platform_manifest : '');
        }
        else {
            throw new PccsError(PCCS_STATUS.PCCS_STATUS_NOT_FOUND);
        }
    }
    else {
        result[Constants.SGX_TCBM] = pckcert.tcbm;
        result[Constants.SGX_PCK_CERTIFICATE_ISSUER_CHAIN] = pckcert.intmd_cert + pckcert.root_cert;
        result["cert"] = pckcert.pck_cert;
    }

    return result;
}
