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
const logger = require('../utils/Logger.js');
const pckcertDao = require('../dao/pckcertDao.js');
const qeidentityDao = require('../dao/qeidentityDao.js');
const qveidentityDao = require('../dao/qveidentityDao.js');
const pckcrlDao = require('../dao/pckcrlDao.js');
const platformTcbsDao = require('../dao/platformTcbsDao.js');
const platformsDao = require('../dao/platformsDao.js');
const fmspcTcbDao = require('../dao/fmspcTcbDao.js');
const pckCertchainDao = require('../dao/pckCertchainDao.js');
const pcsCertificatesDao = require('../dao/pcsCertificatesDao.js');
const PccsError = require('../utils/PccsError.js');
const PCCS_STATUS = require('../constants/pccs_status_code.js');
const Config = require('config');
const Constants = require('../constants/index.js');
const PcsClient = require('../pcs_client/pcs_client.js');
const pckcertService = require('./pckcertService.js')
const {sequelize, Sequelize} = require('../dao/models/');
const X509 = require('../x509/x509.js');
const PckLib = require('../lib_wrapper/pcklib_wrapper.js');

// Refresh the QE IDENTITY table
var refresh_qe_identity=async function(){
    const pck_server_res = await PcsClient.getQEIdentity();
    if (pck_server_res.statusCode == Constants.HTTP_SUCCESS) {
        // Then refresh cache DB
        await qeidentityDao.upsertQEIdentity(pck_server_res.body);
        await pcsCertificatesDao.upsertEnclaveIdentityIssuerChain(
            pck_server_res.headers[Constants.SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN]);
    }
    else {
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_SERVICE_UNAVAILABLE);
    }
}

// Refresh the QVE IDENTITY table
var refresh_qve_identity=async function(){
    const pck_server_res = await PcsClient.getQvEIdentity();
    if (pck_server_res.statusCode == Constants.HTTP_SUCCESS) {
        // Then refresh cache DB
        await qveidentityDao.upsertQvEIdentity(pck_server_res.body);
        await pcsCertificatesDao.upsertEnclaveIdentityIssuerChain(
            pck_server_res.headers[Constants.SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN]);
    }
    else {
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_SERVICE_UNAVAILABLE);
    }
}

function sorter(key1, key2) {
    return function(a, b) {  
        if (a[key1] > b[key1]) return -1;  
        else if (a[key1] < b[key1]) return 1;  
        else {
            if (a[key2] > b[key2]) return 1;  
            else if (a[key2] < b[key2]) return -1;  
            else return 0;
        } 
    }  
}

// Refresh all PCK certs in the database 
var refresh_all_pckcerts = async function(fmspc){
    const platformTcbs = await platformTcbsDao.getPlatformTcbs(fmspc);
    platformTcbs.sort(sorter("qe_id", "pce_id"));
    let last_qe_id = '';
    let last_pce_id = '';
    let tcbinfo_str;
    let pckcerts;
    let pem_certs;
    let pck_certchain = null;
    for (const platformTcb of platformTcbs) {
        if (platformTcb.qe_id != last_qe_id || platformTcb.pce_id != last_pce_id) {
            // new platform detected
            const platform = await platformsDao.getPlatform(platformTcb.qe_id, platformTcb.pce_id);

            // contact Intel PCS server to get PCK certs
            let pck_server_res = await PcsClient.getCerts(platform.enc_ppid, platformTcb.pce_id);

            // check HTTP status
            if (pck_server_res.statusCode != Constants.HTTP_SUCCESS) {
                throw new PccsError(PCCS_STATUS.PCCS_STATUS_NOT_FOUND);
            }

            pck_certchain = pck_server_res.headers[Constants.SGX_PCK_CERTIFICATE_ISSUER_CHAIN];

            // Parse the response body
            pckcerts = JSON.parse(pck_server_res.body);
            if (pckcerts.length == 0) {
                throw new PccsError(PCCS_STATUS.PCCS_STATUS_NOT_FOUND);
            }

            // parse arbitary cert to get fmspc value
            const x509 = new X509();
            if (!x509.parseCert(unescape(pckcerts[0].cert))) {
                throw new PccsError(PCCS_STATUS.PCCS_STATUS_INTERNAL_ERROR);
            }

            const fmspc = x509.fmspc;
            if (fmspc == null) {
                throw new PccsError(PCCS_STATUS.PCCS_STATUS_INTERNAL_ERROR);
            }

            // get tcbinfo for this fmspc
            pck_server_res = await PcsClient.getTcb(fmspc);
            if (pck_server_res.statusCode != Constants.HTTP_SUCCESS) {
                throw new PccsError(PCCS_STATUS.PCCS_STATUS_NOT_FOUND);
            }

            const tcbinfo = JSON.parse(pck_server_res.body);
            tcbinfo_str = JSON.stringify(tcbinfo);

            pem_certs = pckcerts.map(o => unescape(o.cert));

            // flush and add PCK certs
            await pckcertDao.deleteCerts(platformTcb.qe_id, platformTcb.pce_id);
            for (const pckcert of pckcerts) {
                await pckcertDao.upsertPckCert(platformTcb.qe_id, 
                    platformTcb.pce_id, 
                    pckcert.tcbm, 
                    unescape(pckcert.cert));
            } 
        }

        // get the best cert with PCKCertSelectionTool
        let cert_index = PckLib.pck_cert_select(platformTcb.cpu_svn, platformTcb.pce_svn, platformTcb.pce_id, 
            tcbinfo_str, pem_certs, pem_certs.length);
        if (cert_index == -1) {
            throw new PccsError(PCCS_STATUS.PCCS_STATUS_NOT_FOUND);
        }
        await platformTcbsDao.upsertPlatformTcbs(platformTcb.qe_id, 
            platformTcb.pce_id, 
            platformTcb.cpu_svn, 
            platformTcb.pce_svn, 
            pckcerts[cert_index].tcbm);
        
        last_qe_id = platformTcb.qe_id;
        last_pce_id = platformTcb.pce_id;
    }

    if (pck_certchain != null) {
        // Update pck_certchain
        await pckCertchainDao.upsertPckCertchain();
        // Update or insert SGX_PCK_CERTIFICATE_ISSUER_CHAIN
        await pcsCertificatesDao.upsertPckCertificateIssuerChain(pck_certchain);
    }
}

// Refresh the crl record for the specified ca
var refresh_one_crl=async function(ca){
    const pck_server_res = await PcsClient.getPckCrl(ca);
    if (pck_server_res.statusCode == Constants.HTTP_SUCCESS) {
        // Then refresh cache DB
        await pckcrlDao.upsertPckCrl(ca, pck_server_res.body);
        await pcsCertificatesDao.upsertPckCrlCertchain(pck_server_res.headers[Constants.SGX_PCK_CRL_ISSUER_CHAIN]);
    }
    else {
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_SERVICE_UNAVAILABLE);
    }
}

// Refresh all CRLs in the table
var refresh_all_crls = async function(){
    const pckcrls = await pckcrlDao.getAllPckCrls();
    for (var pckcrl of pckcrls){
        // refresh each crl
        await refresh_one_crl(pckcrl.ca);
    }
}

// Refresh the TCB info for the specified fmspc value
var refresh_one_tcb = async function(fmspc){
    const pck_server_res = await PcsClient.getTcb(fmspc);
    if (pck_server_res.statusCode == Constants.HTTP_SUCCESS) {
        // Then refresh cache DB
        await fmspcTcbDao.upsertFmspcTcb({
            "fmspc": fmspc,
            "tcbinfo": JSON.parse(pck_server_res.body)
        });
        // update or insert certificate chain
        await pcsCertificatesDao.upsertTcbInfoIssuerChain(pck_server_res.headers[Constants.SGX_TCB_INFO_ISSUER_CHAIN]);
    }
    else {
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_SERVICE_UNAVAILABLE);
    }
}

// Refresh all TCBs in the table
var refresh_all_tcbs=async function(){
    const tcbs = await fmspcTcbDao.getAllTcbs();
    for (var tcb of tcbs){
        // refresh each tcb
        await refresh_one_tcb(tcb.fmspc);
    }
}

exports.refreshCache=async function(type, fmspc) {
    if (Config.get(Constants.CONFIG_OPTION_CACHE_FILL_MODE) == Constants.CACHE_FILL_MODE_OFFLINE) {
        // Refresh is not supported in OFFLINE mode
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_SERVICE_UNAVAILABLE);
    }

    if (type == "certs") {
        await sequelize.transaction(async (t)=>{
            await refresh_all_pckcerts(fmspc);
        });
    }
    else {
        await sequelize.transaction(async (t)=>{
            await refresh_all_crls();
            await refresh_all_tcbs(); 
            await refresh_qe_identity();
            await refresh_qve_identity();
        });
    }
}

// Schedule the refresh job in cron-style
// # ┌───────────── minute (0 - 59)
// # │ ┌───────────── hour (0 - 23)
// # │ │ ┌───────────── day of the month (1 - 31)
// # │ │ │ ┌───────────── month (1 - 12)
// # │ │ │ │ ┌───────────── day of the week (0 - 6) (Sunday to Saturday;
// # │ │ │ │ │                                   7 is also Sunday on some systems)
// # │ │ │ │ │
// # │ │ │ │ │
// # * * * * * command to execute
//

exports.scheduledRefresh = async function() {
    try {
            if (Config.get(Constants.CONFIG_OPTION_CACHE_FILL_MODE) == Constants.CACHE_FILL_MODE_OFFLINE) {
                // Refresh is not supported in OFFLINE mode
                return;
            }
            await sequelize.transaction(async (t)=>{
            await refresh_all_crls();
            await refresh_all_tcbs(); 
            await refresh_qe_identity();
            await refresh_qve_identity();
        });

        logger.info('Scheduled cache refresh is completed successfully.')
    }
    catch(error) {
        logger.error('Scheduled cache refresh failed.')
    }
}
