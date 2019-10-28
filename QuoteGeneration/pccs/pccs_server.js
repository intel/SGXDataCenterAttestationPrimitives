#!/usr/bin/env node
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

const config = require('config');
const util = require('util');
const url = require('url');
const morgan = require('morgan');
const express = require('express');
const pckdb = require('./pckdb.js');
const pckclient = require('./pckclient.js');
const fs = require('fs');
const winston = require('./winston');
const http = require('http');
const https = require('https');
const schedule = require('node-schedule');
const X509 = require('./x509.js');
const crypto = require('crypto');

const QEID_SIZE = 32;
const CPUSVN_SIZE = 32;
const PCESVN_SIZE = 4;
const PCEID_SIZE = 4;
const ENC_PPID_SIZE = 768;
const FMSPC_SIZE = 12;
const SGX_TCBM = 'sgx-tcbm';
const SGX_PCK_CERTIFICATE_ISSUER_CHAIN = 'sgx-pck-certificate-issuer-chain';
const SGX_PCK_CRL_ISSUER_CHAIN = 'sgx-pck-crl-issuer-chain';
const SGX_TCB_INFO_ISSUER_CHAIN = 'sgx-tcb-info-issuer-chain';
const SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN = 'sgx-enclave-identity-issuer-chain';

const STATUS_SUCCESS = 200;
const STATUS_INVALID_PARAMETER = 400;
const STATUS_NOT_FOUND = 404;
const STATUS_REFRESH_FAIL = 499;


const app = express();
app.use(morgan('combined', {stream: winston.stream}));

// Create ./logs if it doesn't exist
fs.mkdir('./logs', (err)=> {/* do nothing*/});

// Start HTTPS server 
try {
var privateKey = fs.readFileSync('./private.pem', 'utf8');
var certificate = fs.readFileSync('./file.crt', 'utf8');
} catch (err){
    winston.error("The private key or certificate for HTTPS server is missing.");
}
const credentials = {key: privateKey, cert: certificate};
const httpsServer = https.createServer(credentials, app);
httpsServer.listen(config.get('HTTPS_PORT'), config.get('hosts'), function() {
    winston.info('HTTPS Server is running on: https://localhost:' + config.get('HTTPS_PORT'));
});

// callback function to parse url parameters
var parseUrlParams = function(req, res, next){
    req.urlP = url.parse(req.url, true);
    next();
}

app.get('/sgx/certification/v2/pckcert', parseUrlParams, async function(req, res) {
    const qeid = req.urlP.query.qeid;
    const cpusvn = req.urlP.query.cpusvn;
    const pcesvn = req.urlP.query.pcesvn;
    const pceid = req.urlP.query.pceid;
    let enc_ppid = req.urlP.query.encrypted_ppid;
    if (qeid == null || cpusvn == null || pcesvn == null || pceid == null) {
        winston.error('Invalid parameters');
        res.status(STATUS_INVALID_PARAMETER);
        res.send("Invalid parameters");
        return;
    }
    if (qeid.length != QEID_SIZE || cpusvn.length != CPUSVN_SIZE 
        || pcesvn.length != PCESVN_SIZE || pceid.length != PCEID_SIZE){
        winston.error('Invalid parameters');
        res.status(STATUS_INVALID_PARAMETER);
        res.send("Invalid parameters");
        return;
    }
    if (enc_ppid != null && enc_ppid.length != ENC_PPID_SIZE) {
        winston.error('Invalid parameters');
        res.status(STATUS_INVALID_PARAMETER);
        res.send("Invalid parameters");
        return;
    }

    try {
        // query pck cert from local database first
        const pckcert = await pckdb.getCert(qeid, cpusvn, pcesvn, pceid);
        if (pckcert == null) {
            // if no record found in local database, then request the cert from PCK service
            if (enc_ppid == null) {
                res.status(STATUS_INVALID_PARAMETER);
                res.send("Invalid parameters");
                return;
            }
            // if enc_ppid is all zero, return NOT_FOUND
            if (enc_ppid.match(/^0+$/)) {
                res.status(STATUS_NOT_FOUND);
                res.send("The PCK certificate for the platform was not found.");
                return;
            }

            // contact Intel PCS server
            const pck_server_res = await pckclient.getCert(enc_ppid, cpusvn, pcesvn, pceid);

            try {
                if (pck_server_res.statusCode == STATUS_SUCCESS) {
                    // Then update cache DB
                    const x509 = new X509();
                    if (x509.parseCert(pck_server_res.body) && x509.fmspc != null){
                        // Update or insert PCK cert
                        await pckdb.upsertCert(qeid, enc_ppid, cpusvn, pcesvn, pceid, 
                            pck_server_res.headers[SGX_TCBM], 
                            x509.fmspc,
                            pck_server_res.body);
                        // Update or insert SGX_PCK_CERTIFICATE_ISSUER_CHAIN
                        await pckdb.upsertPckCertchain(pck_server_res.headers[SGX_PCK_CERTIFICATE_ISSUER_CHAIN]);
                    }
                }
            }
            catch(err){
                winston.error('Failed to update/insert PCK cert and certchain!');
            }

            // Send response to client
            res.status(pck_server_res.statusCode);
            res.set(pck_server_res.headers);
            res.send(pck_server_res.body);

        }
        else {
            res.status(STATUS_SUCCESS);
            res.setHeader(SGX_TCBM, pckcert.tcbm);
            res.setHeader(SGX_PCK_CERTIFICATE_ISSUER_CHAIN, pckcert.intmd_cert.toString('utf8') + pckcert.root_cert.toString('utf8'));
            res.send(pckcert.pck_cert.toString('utf8'));
        }
    }
    catch(err){
        res.status(STATUS_NOT_FOUND);
        res.send(err);
    }
});

app.get('/sgx/certification/v2/pckcrl', parseUrlParams, async function(req, res) {
    const ca = req.urlP.query.ca;
    if (ca != 'processor' && ca != 'platform') {
        winston.error('Invalid parameters');
        res.status(STATUS_INVALID_PARAMETER);
        res.send("Invalid parameters");
        return;
    }
    try {
        // query pck crl from local database first
        const pckcrl = await pckdb.getPckCrl(ca);

        if (pckcrl == null) {
            const pck_server_res = await pckclient.getPckCrl(ca);
            // Send response to client first
            res.status(pck_server_res.statusCode);
            res.set(pck_server_res.headers);
            res.send(pck_server_res.body);

            // Since response was already sent to client, even if the db operation failed, we shouldn't 
            // send the response again. Can just ignore the error
            try {
                if (pck_server_res.statusCode == STATUS_SUCCESS) {
                    // Then update cache DB
                    await pckdb.upsertPckCrl(ca, pck_server_res.body);
                    await pckdb.upsertPckCrlCertchain(pck_server_res.headers[SGX_PCK_CRL_ISSUER_CHAIN]);
                }
            }
            catch(err){
                winston.error('Failed to update/insert PCK CRL!');
            }

        }
        else {
            res.status(STATUS_SUCCESS);
            res.setHeader(SGX_PCK_CRL_ISSUER_CHAIN,  pckcrl.intmd_cert.toString('utf8') + pckcrl.root_cert.toString('utf8'));
            res.send(pckcrl.pck_crl.toString('utf8'));
        }
    }
    catch(err){
        res.status(STATUS_NOT_FOUND);
        res.send(err);
    }
});

app.get('/sgx/certification/v2/tcb', parseUrlParams, async function(req, res) {
    const fmspc = req.urlP.query.fmspc;
    if (fmspc == null || fmspc.length != FMSPC_SIZE) {
        winston.error('Invalid parameters');
        res.status(STATUS_INVALID_PARAMETER);
        res.send("Invalid parameters");
        return;
    }

    try {
        // query pck crl from local database first
        const tcb = await pckdb.getTcb(fmspc);
        if (tcb == null) {
            const pck_server_res = await pckclient.getTcb(fmspc);
            // Send response to client first
            res.status(pck_server_res.statusCode);
            res.set(pck_server_res.headers);
            res.send(pck_server_res.body);

            // Since response was already sent to client, even if the db operation failed, we shouldn't 
            // send the response again. Can just ignore the error
            try {
                if (pck_server_res.statusCode == STATUS_SUCCESS) {
                    // Then update cache DB
                    await pckdb.upsertTcb(fmspc, pck_server_res.body);
                    await pckdb.upsertTcbInfoCertchain(pck_server_res.headers[SGX_TCB_INFO_ISSUER_CHAIN]);
                }
            }
            catch(err){
                winston.error('Failed to update/insert TCB info!');
            }
        }
        else {
            res.status(STATUS_SUCCESS);
            res.setHeader(SGX_TCB_INFO_ISSUER_CHAIN, tcb.signing_cert.toString('utf8') + tcb.root_cert.toString('utf8'));
            res.send(tcb.tcb_info.toString('utf8'));
        }
    }
    catch (err){
        res.status(STATUS_NOT_FOUND);
        res.send(err);
    }
});

app.get('/sgx/certification/v2/qe/identity', parseUrlParams, async function(req, res) {
    try {
        // query qe_identity from local database first
        const qe_identity = await pckdb.getQEIdentity();
        if (qe_identity == null) {
            const pck_server_res = await pckclient.getQEIdentity();
            // Send response to client first
            res.status(pck_server_res.statusCode);
            res.set(pck_server_res.headers);
            res.send(pck_server_res.body);

            // Since response was already sent to client, even if the db operation failed, we shouldn't 
            // send the response again. Can just ignore the error
            try {
                if (pck_server_res.statusCode == STATUS_SUCCESS) {
                    // Then update cache DB
                    await pckdb.upsertQEIdentity(pck_server_res.body);
                    await pckdb.upsertEnclaveIdentityCertchain(pck_server_res.headers[SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN]);
                }
            }
            catch(err){
                winston.error('Failed to update/insert QE identity!');
            }
        }
        else {
            res.status(STATUS_SUCCESS);
            res.setHeader(SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN, qe_identity.signing_cert.toString('utf8') + qe_identity.root_cert.toString('utf8'));
            res.send(qe_identity.qe_identity.toString('utf8'));
        }
    }
    catch (err) {
        res.status(STATUS_NOT_FOUND);
        res.send(err);

    }
});

app.get('/sgx/certification/v2/qve/identity', parseUrlParams, async function(req, res) {
    try {
        // query qve_identity from local database first
        const qve_identity = await pckdb.getQvEIdentity();
        if (qve_identity == null) {
            const pck_server_res = await pckclient.getQvEIdentity();
            // Send response to client first
            res.status(pck_server_res.statusCode);
            res.set(pck_server_res.headers);
            res.send(pck_server_res.body);

            // Since response was already sent to client, even if the db operation failed, we shouldn't 
            // send the response again. Can just ignore the error
            try {
                if (pck_server_res.statusCode == STATUS_SUCCESS) {
                    // Then update cache DB
                    await pckdb.upsertQvEIdentity(pck_server_res.body);
                    await pckdb.upsertEnclaveIdentityCertchain(pck_server_res.headers[SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN]);
                }
            }
            catch(err){
                winston.error('Failed to update/insert QvE identity!');
            }
        }
        else {
            res.status(STATUS_SUCCESS);
            res.setHeader(SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN, qve_identity.signing_cert.toString('utf8') + qve_identity.root_cert.toString('utf8'));
            res.send(qve_identity.qve_identity.toString('utf8'));
        }
    }
    catch (err) {
        res.status(STATUS_NOT_FOUND);
        res.send(err);

    }
});

app.get('/sgx/certification/v2/rootcacrl', parseUrlParams, async function(req, res) {
    try {
        // query ROOT CA CRL from local database first 
        let root_cert_crl = await pckdb.getRootCertCrl();
        if (root_cert_crl != null) {
            res.status(STATUS_SUCCESS);
            res.send(root_cert_crl.toString('utf8'));
        }
        else {
            res.status(STATUS_NOT_FOUND);
            res.send('Get Root CA CRL failed!');
        }
    }
    catch (err) {
        res.status(STATUS_NOT_FOUND);
        res.send(err);

    }
});

// Refresh the QE_IDENTITY table
var refresh_qe_identity=function(){
    return new Promise(async (resolve,reject)=>{
        try{
            const pck_server_res = await pckclient.getQEIdentity();
            if (pck_server_res.statusCode == STATUS_SUCCESS) {
                // Then refresh cache DB
                await pckdb.upsertQEIdentity(pck_server_res.body);
                await pckdb.upsertEnclaveIdentityCertchain(pck_server_res.headers[SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN]);
                resolve();
            }
            else {
                reject("Failed to get QEIdentity from Intel PCS.");
            }
        }
        catch (err){
            reject(err);
        }
    });
}

// Refresh the QVE_IDENTITY table
var refresh_qve_identity=function(){
    return new Promise(async (resolve,reject)=>{
        try{
            const pck_server_res = await pckclient.getQvEIdentity();
            if (pck_server_res.statusCode == STATUS_SUCCESS) {
                // Then refresh cache DB
                await pckdb.upsertQvEIdentity(pck_server_res.body);
                await pckdb.upsertEnclaveIdentityCertchain(pck_server_res.headers[SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN]);
                resolve();
            }
            else {
                reject("Failed to get QvEIdentity from Intel PCS.");
            }
        }
        catch (err){
            reject(err);
        }
    });
}

// Refresh PCK cert for one platform TCB
var refresh_one_pckcert=function(platformTcb){
    return new Promise(async (resolve,reject)=>{
        try {
            const pck_server_res = await pckclient.getCert(platformTcb.enc_ppid, platformTcb.cpu_svn, platformTcb.pce_svn, platformTcb.pce_id);
            if (pck_server_res.statusCode == STATUS_SUCCESS) {
                // Then refresh cache DB
                const x509 = new X509();
                if (x509.parseCert(pck_server_res.body) && x509.fmspc != null){
                    await pckdb.upsertCert(platformTcb.qe_id, platformTcb.enc_ppid, platformTcb.cpu_svn, platformTcb.pce_svn, platformTcb.pce_id, 
                                            pck_server_res.headers[SGX_TCBM], 
                                            x509.fmspc,
                                            pck_server_res.body);
                    await pckdb.upsertPckCertchain(pck_server_res.headers[SGX_PCK_CERTIFICATE_ISSUER_CHAIN]);
                }
                resolve();
            }
            else {
                reject("Failed to get PCK Cert from Intel PCS.");
            }
        }
        catch(err) {
            reject(err);
        }
    });
}

// Refresh all PCK certs in the database 
var refresh_all_pckcerts=function(fmspc){
    return new Promise(async (resolve,reject)=>{
        try {
            const platformTcbs = await pckdb.allPlatformTcbs(fmspc);
            for (var platformTcb of platformTcbs){
                await refresh_one_pckcert(platformTcb);
            }
            resolve();
        }
        catch(err){
            reject(err);
        }
    });
}

// Refresh the crl record for the specified ca
var refresh_one_crl=function(ca){
    return new Promise(async (resolve,reject)=>{
        try {
            const pck_server_res = await pckclient.getPckCrl(ca);
            if (pck_server_res.statusCode == STATUS_SUCCESS) {
                // Then refresh cache DB
                await pckdb.upsertPckCrl(ca, pck_server_res.body);
                await pckdb.upsertPckCrlCertchain(pck_server_res.headers[SGX_PCK_CRL_ISSUER_CHAIN]);
                resolve();
            }
            else {
                reject("Failed to get PCK CRL from Intel PCS.");
            }
        }
        catch(err) {
            reject(err);
        }
    });
}

// Refresh all CRLs in the table
var refresh_all_crls=function(){
    return new Promise(async (resolve,reject)=>{
        try {
            const pckcrls = await pckdb.getAllPckCrls();
            for (var pckcrl of pckcrls){
                // refresh each crl
                await refresh_one_crl(pckcrl.ca);
            }
            resolve();
        }
        catch(err) {
            reject(err);
        }
    });
}

// Refresh the TCB info for the specified fmspc value
var refresh_one_tcb=function(fmspc){
    return new Promise(async (resolve,reject)=>{
        try {
            const pck_server_res = await pckclient.getTcb(fmspc);
            if (pck_server_res.statusCode == STATUS_SUCCESS) {
                // Then refresh cache DB
                await pckdb.upsertTcb(fmspc, pck_server_res.body);
                await pckdb.upsertTcbInfoCertchain(pck_server_res.headers[SGX_TCB_INFO_ISSUER_CHAIN]);
                resolve(); 
            }
            else {
                reject("Failed to get TCBInfo from Intel PCS.");
            }
        }
        catch(err){
            reject(err);
        }
    });
}

// Refresh all TCBs in the table
var refresh_all_tcbs=function(){
    return new Promise(async (resolve,reject)=>{
        try {
            const tcbs = await pckdb.getAllTcbs();
            for (var tcb of tcbs){
                // refresh each tcb
                await refresh_one_tcb(tcb.fmspc);
            }
            resolve();
        }
        catch(err){
            reject(err);
        }
    });
}

app.get('/sgx/certification/v2/refresh', parseUrlParams, async function(req, res) {
    const token = req.urlP.query.token;
    const type = req.urlP.query.type;
    const fmspc = req.urlP.query.fmspc;

    if (token == null || token == '') {
        winston.error("Invalid token!");
        return;
    }

    var hash = crypto.createHash('sha512');
    hash.update(token);
    var AdminToken = hash.digest('hex');
    
    if (AdminToken != config.get('AdminToken')) {
        res.status(503);
        res.send('Authentication failed.')
        return;
    }

    if (type == "certs") {
        try {
            await refresh_all_pckcerts(fmspc);
            res.status(STATUS_SUCCESS);
            res.send('SUCCESS');
        }
        catch(err){
            res.status(STATUS_REFRESH_FAIL);
            res.send(err);
        }
    }
    else {
        try {
            await refresh_all_crls();
            await refresh_all_tcbs(); 
            await refresh_qe_identity();
            await refresh_qve_identity();

            res.status(STATUS_SUCCESS);
            res.send('SUCCESS');
        }
        catch(err){
            res.status(STATUS_REFRESH_FAIL);
            res.send(err);
        }
    }
});

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
schedule.scheduleJob(config.get('RefreshSchedule'), function(){
    refresh_all_crls().then(
        function(){
            winston.info('Refreshed CRLs successfully.')
        },
        function(){
            winston.error('Failed to refresh CRLs.')
        }
    );
    refresh_all_tcbs().then(
        function() {
            winston.info('Refreshed TCBs successfully.')
        },
        function() {
            winston.error('Failed to refresh TCBs.')
        }
    );
    refresh_qe_identity().then(
        function() {
            winston.info('Refreshed QEIdentity successfully.')
        },
        function() {
            winston.error('Failed to refresh QEIdentity.')
        }
    );
    refresh_qve_identity().then(
        function() {
            winston.info('Refreshed QvEIdentity successfully.')
        },
        function() {
            winston.error('Failed to refresh QvEIdentity.')
        }
    );
});

module.exports = app;       // for testing

