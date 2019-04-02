#!/usr/bin/env node
const config = require('./config.json');
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
const SGX_QE_IDENTITY_ISSUER_CHAIN = 'sgx-qe-identity-issuer-chain';

const STATUS_SUCCESS = 200;
const STATUS_INVALID_PARAMETER = 400;
const STATUS_NOT_FOUND = 404;
const STATUS_REFRESH_FAIL = 499;


var app = express();
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
var credentials = {key: privateKey, cert: certificate};
var httpsServer = https.createServer(credentials, app);
httpsServer.listen(config.HTTPS_PORT, function() {
    console.log('HTTPS Server is running on: https://localhost:%s', config.HTTPS_PORT);
});

// callback function to parse url parameters
var parseUrlParams = function(req, res, next){
    req.urlP = url.parse(req.url, true);
    next();
}

app.get('/sgx/certification/v1/pckcert', parseUrlParams, function(req, res) {
    let qeid = req.urlP.query.qeid;
    let cpusvn = req.urlP.query.cpusvn;
    let pcesvn = req.urlP.query.pcesvn;
    let pceid = req.urlP.query.pceid;
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

    // query pck cert from local database first
    pckdb.getCert(qeid, cpusvn, pcesvn, pceid).then(
        pckcert=>{
            if (pckcert == null){
                // if no record found in local database, then request the cert from PCK service
                if (enc_ppid == null) {
                    res.status(STATUS_INVALID_PARAMETER);
                    res.send("Invalid parameters");
                    return;
                }
                pckclient.getCert(enc_ppid, cpusvn, pcesvn, pceid).then(
                    pck_server_res=>{
                        // Send response to client first
                        res.status(pck_server_res.statusCode);
                        res.set(pck_server_res.headers);
                        res.send(pck_server_res.body);

                        if (pck_server_res.statusCode == STATUS_SUCCESS) {
                            // Then update cache DB
                            var x509 = new X509();
                            if (x509.parseCert(pck_server_res.body)){
                                pckdb.upsertCert(qeid, enc_ppid, cpusvn, pcesvn, pceid, 
                                    pck_server_res.headers[SGX_TCBM], 
                                    x509.fmspc,
                                    pck_server_res.headers[SGX_PCK_CERTIFICATE_ISSUER_CHAIN], 
                                    pck_server_res.body);
                            }
                        }
                    },
                    err=>{
                        res.status(STATUS_NOT_FOUND);
                        res.send(err);
                    }
                );
            }
            else {
                res.status(STATUS_SUCCESS);
                res.setHeader(SGX_TCBM, pckcert.tcbm);
                res.setHeader(SGX_PCK_CERTIFICATE_ISSUER_CHAIN, pckcert.pck_certchain.pck_certchain);
                res.send(pckcert.pck_cert.toString('utf8'));
            }
        },
        err=>{
            res.status(STATUS_NOT_FOUND);
            res.send(err);
        }
    );
});

app.get('/sgx/certification/v1/pckcrl', parseUrlParams, function(req, res) {
    let ca = req.urlP.query.ca;
    if (ca != 'processor' && ca != 'platform') {
        winston.error('Invalid parameters');
        res.status(STATUS_INVALID_PARAMETER);
        res.send("Invalid parameters");
        return;
    }
    // query pck crl from local database first
    pckdb.getPckCrl(ca).then(
        pckcrl=>{
            if (pckcrl == null){
                // if no record found in local database, then request the crl from PCK service
                pckclient.getPckCrl(ca).then(
                    pck_server_res=>{
                        // Send response to client first
                        res.status(pck_server_res.statusCode);
                        res.set(pck_server_res.headers);
                        res.send(pck_server_res.body);

                        if (pck_server_res.statusCode == STATUS_SUCCESS) {
                            // Then update cache DB
                            pckdb.upsertCrl( 
                                ca,
                                pck_server_res.headers[SGX_PCK_CRL_ISSUER_CHAIN], 
                                pck_server_res.body);
                        }
                    },
                    err=>{
                        res.status(STATUS_NOT_FOUND);
                        res.send(err);
                    }
                );
            }
            else {
                res.status(STATUS_SUCCESS);
                res.setHeader(SGX_PCK_CRL_ISSUER_CHAIN, pckcrl.crl_certchain);
                res.send(pckcrl.pck_crl.toString('utf8'));
            }
        },
        err=>{
            res.status(STATUS_NOT_FOUND);
            res.send(err);
        }
    );
});

app.get('/sgx/certification/v1/tcb', parseUrlParams, function(req, res) {
    let fmspc = req.urlP.query.fmspc;
    if (fmspc == null || fmspc.length != FMSPC_SIZE) {
        winston.error('Invalid parameters');
        res.status(STATUS_INVALID_PARAMETER);
        res.send("Invalid parameters");
        return;
    }
    // query pck crl from local database first
    pckdb.getTcb(fmspc).then(
        tcb=>{
            if (tcb == null){
                // if no record found in local database, then request the tcb from PCK service
                pckclient.getTcb(fmspc).then(
                    pck_server_res=>{
                        // Send response to client first
                        res.status(pck_server_res.statusCode);
                        res.set(pck_server_res.headers);
                        res.send(pck_server_res.body);

                        if (pck_server_res.statusCode == STATUS_SUCCESS) {
                            // Then update cache DB
                            pckdb.upsertTcb( 
                                fmspc,
                                pck_server_res.body,
                                pck_server_res.headers[SGX_TCB_INFO_ISSUER_CHAIN]);
                        }
                    },
                    err=>{
                        res.status(STATUS_NOT_FOUND);
                        res.send(err);
                    }
                );
            }
            else {
                res.status(STATUS_SUCCESS);
                res.setHeader(SGX_TCB_INFO_ISSUER_CHAIN, tcb.tcb_info_issuer_chain);
                res.send(tcb.tcb_info.toString('utf8'));
            }
        },
        err=>{
            res.status(STATUS_NOT_FOUND);
            res.send(err);
        }
    );
});

app.get('/sgx/certification/v1/qe/identity', parseUrlParams, function(req, res) {
    // query qe_identity from local database first
    pckdb.getQEIdentity().then(
        qe_identity=>{
            if (qe_identity == null){
                // if no record found in local database, then request the tcb from PCK service
                pckclient.getQEIdentity().then(
                    pck_server_res=>{
                        // Send response to client first
                        res.status(pck_server_res.statusCode);
                        res.set(pck_server_res.headers);
                        res.send(pck_server_res.body);

                        if (pck_server_res.statusCode == STATUS_SUCCESS) {
                            // Then update cache DB
                            pckdb.upsertQEIdentity( 
                                pck_server_res.body,
                                pck_server_res.headers[SGX_QE_IDENTITY_ISSUER_CHAIN]);
                        }
                    },
                    err=>{
                        res.status(STATUS_NOT_FOUND);
                        res.send(err);
                    }
                );
            }
            else {
                res.status(STATUS_SUCCESS);
                res.setHeader(SGX_QE_IDENTITY_ISSUER_CHAIN, qe_identity.qe_identity_issuer_chain);
                res.send(qe_identity.qe_identity.toString('utf8'));
            }
        },
        err=>{
            res.status(STATUS_NOT_FOUND);
            res.send(err);
        }
    );
});

// Refresh the QE_IDENTITY table
var refresh_qe_identity=function(){
    return new Promise((resolve,reject)=>{
        pckclient.getQEIdentity().then(
            pck_server_res=>{
                if (pck_server_res.statusCode == STATUS_SUCCESS) {
                    // Then refresh cache DB
                    pckdb.delQEIdentity().then(
                        result=>{
                            pckdb.upsertQEIdentity( 
                                pck_server_res.body,
                                pck_server_res.headers[SGX_QE_IDENTITY_ISSUER_CHAIN]).then(
                                    result=>{
                                        resolve(0);
                                    },
                                    err=>{
                                        reject(-1);
                                    }
                                );
                        },
                        err=>{
                            reject(-1);
                        }
                    )
                }
                else {
                    reject(-1);
                }
            },
            err=>{
                reject(-1);
            }
        );
    })
}

// Refresh PCK cert for one platform TCB
var refresh_one_pckcert=function(platformTcb){
    return new Promise((resolve,reject)=>{
        pckclient.getCert(platformTcb.enc_ppid, platformTcb.cpu_svn, platformTcb.pce_svn, platformTcb.pce_id).then(
            pck_server_res=>{
                if (pck_server_res.statusCode == STATUS_SUCCESS) {
                    // Then refresh cache DB
                    var x509 = new X509();
                    if (x509.parseCert(pck_server_res.body)){
                        pckdb.upsertCert(platformTcb.qe_id, platformTcb.enc_ppid, platformTcb.cpu_svn, platformTcb.pce_svn, platformTcb.pce_id, 
                            pck_server_res.headers[SGX_TCBM], 
                            x509.fmspc,
                            pck_server_res.headers[SGX_PCK_CERTIFICATE_ISSUER_CHAIN], 
                            pck_server_res.body).then(
                                result=>{
                                    resolve(0);
                                },
                                err=>{
                                    reject(-1);
                                }
                            );
                    }
                }
                else {
                    reject(-1);
                }
            },
            err=>{
                reject(-1);
            }
        );
    })
}

// Refresh all PCK certs in the database 
var refresh_all_pckcerts=function(fmspc){
    return new Promise((resolve,reject)=>{
        pckdb.allPlatformTcbs(fmspc).then(
            platformTcbs=>{
                console.log(platformTcbs);
                var ps = [];
                for (var platformTcb of platformTcbs){
                    // refresh each cert 
                    ps.push(refresh_one_pckcert(platformTcb).then(
                        result=>{
                        }
                    ).catch(function(){
                        reject(-1);
                    }));
                }
                Promise.all(ps).then(function(){
                    resolve(0);
                });
            });
    });
}

// Refresh the crl record for the specified ca
var refresh_one_crl=function(ca){
    return new Promise((resolve,reject)=>{
        pckclient.getPckCrl(ca).then(
            pck_server_res=>{
                if (pck_server_res.statusCode == STATUS_SUCCESS) {
                    // Then refresh cache DB
                    pckdb.upsertCrl( 
                        ca,
                        pck_server_res.headers[SGX_PCK_CRL_ISSUER_CHAIN], 
                        pck_server_res.body).then(
                            result=>{
                                resolve(0);
                            },
                            err=>{
                                reject(-1);
                            }
                        )
                }
                else {
                    reject(-1);
                }
            },
            err=>{
                reject(-1);
            }
        );
    })
}

// Refresh all CRLs in the table
var refresh_all_crls=function(){
    return new Promise((resolve,reject)=>{
        pckdb.allCrls().then(
            pckcrls=>{
                var ps = [];
                for (var pckcrl of pckcrls){
                    // refresh each crl
                    ps.push(refresh_one_crl(pckcrl.ca).then(
                        result=>{
                        }
                    ).catch(function(){
                        reject(-1);
                    }));
                }
                Promise.all(ps).then(function(){
                    resolve(0);
                });
            });
    });
}

// Refresh the TCB info for the specified fmspc value
var refresh_one_tcb=function(fmspc){
    return new Promise((resolve,reject)=>{
        pckclient.getTcb(fmspc).then(
            pck_server_res=>{
                if (pck_server_res.statusCode == STATUS_SUCCESS) {
                    // Then refresh cache DB
                    pckdb.upsertTcb( 
                        fmspc,
                        pck_server_res.body,
                        pck_server_res.headers[SGX_TCB_INFO_ISSUER_CHAIN]
                    ).then(
                        result=>{
                            resolve(0);
                        },
                        err=>{
                            reject(-1);
                        }
                    );
                }
                else {
                    reject(-1);
                }
            },
            err=>{
                reject(-1);
            }
        );

    })
}

// Refresh all TCBs in the table
var refresh_all_tcbs=function(){
    return new Promise((resolve,reject)=>{
        pckdb.allTcbs().then(
            tcbs=>{
                var ps = [];
                for (var tcb of tcbs){
                    // refresh each tcb
                    ps.push(refresh_one_tcb(tcb.fmspc).then(
                        result=>{
                        }
                    ).catch(function(){
                        reject(-1);
                    }));
                }
                Promise.all(ps).then(function(){
                    resolve(0);
                }).catch(function(){
                    reject(-1);
                });
            });
    });
}

app.get('/sgx/certification/v1/refresh', parseUrlParams, function(req, res) {
    let token = req.urlP.query.token;
    let type = req.urlP.query.type;
    let fmspc = req.urlP.query.fmspc;

    if (token == null || token == '') {
        winston.error("Invalid token!");
        return;
    }

    var hash = crypto.createHash('sha512');
    hash.update(token);
    var AdminToken = hash.digest('hex');
    
    if (AdminToken != config.AdminToken) {
        res.status(503);
        res.send('Authentication failed.')
        return;
    }

    if (type == "certs") {
        refresh_all_pckcerts(fmspc).then(
            result=>{
                res.status(STATUS_SUCCESS);
                res.send('SUCCESS');
            }).catch(err=>{
                res.status(STATUS_REFRESH_FAIL);
                res.send('Failed to refresh PCK certificates');
            });
    }
    else {
        refresh_all_crls().then(
            function(){
                refresh_all_tcbs().then(
                    function() {
                        refresh_qe_identity().then(
                            function() {
                                res.status(STATUS_SUCCESS);
                                res.send('SUCCESS');
                            },
                            function() {
                                res.status(STATUS_REFRESH_FAIL);
                                res.send('Failed to refresh table qe_identity');
                            }
                        );
                    },
                    function() {
                        res.status(STATUS_REFRESH_FAIL);
                        res.send('Failed to refresh table fmspc_tcbs');
                        res.send('FAILED');
                    }
                )
            },
            function(){
                res.status(STATUS_REFRESH_FAIL);
                res.send('Failed to refresh table pck_crls');
            }
        );
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
schedule.scheduleJob(config.RefreshSchedule, function(){
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
});
