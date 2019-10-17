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

const Sequelize = require('sequelize');
const config = require('config');
const winston = require('./winston');
const X509 = require('./x509.js');
const pckclient = require('./pckclient.js'); 

var db = config.get(config.get('DB_CONFIG'));
var db_opt = JSON.parse(JSON.stringify(db.options));
if (db_opt.logging == true) {
    // Enable sequelize logging through winston.info
    db_opt.logging = (msg)=>winston.info(msg);
}
const sequelize = new Sequelize(db.database, db.username, db.password, db_opt);

//------------------------Model definitions----------------------------------//
const PckCert = sequelize.define('pck_cert', {
  qe_id: { type: Sequelize.STRING, primaryKey: true},
  pce_id: { type: Sequelize.STRING, primaryKey: true },
  tcbm: { type: Sequelize.STRING, primaryKey: true },
  fmspc: { type: Sequelize.STRING },
  pck_cert: { type: Sequelize.BLOB },
  root_cert_id: { type: Sequelize.INTEGER },
  intmd_cert_id: { type: Sequelize.INTEGER }
},{
    timestamps: true,
    createdAt: 'created_time',
    updatedAt: 'updated_time'
});

const PlatformTcb = sequelize.define('platform_tcbs', {
  qe_id: { type: Sequelize.STRING, primaryKey: true},
  pce_id: { type: Sequelize.STRING, primaryKey: true },
  cpu_svn: { type: Sequelize.STRING, primaryKey: true },
  pce_svn: { type: Sequelize.STRING, primaryKey: true },
  enc_ppid: { type: Sequelize.BLOB },
  tcbm: { type: Sequelize.STRING }
},{
    timestamps: true,
    createdAt: 'created_time',
    updatedAt: 'updated_time'
});

const PcsCertificates = sequelize.define('pcs_certificates', {
  cert: { type: Sequelize.BLOB },
  crl: { type: Sequelize.BLOB }
},{
    timestamps: true,
    createdAt: 'created_time',
    updatedAt: 'updated_time'
});

const PckCrl = sequelize.define('pck_crl', {
  ca: { type: Sequelize.STRING, primaryKey: true},
  pck_crl: { type: Sequelize.BLOB },
  root_cert_id: { type: Sequelize.INTEGER },
  intmd_cert_id: { type: Sequelize.INTEGER }
},{
    timestamps: true,
    createdAt: 'created_time',
    updatedAt: 'updated_time'
});

const FmspcTcb = sequelize.define('fmspc_tcbs', {
  fmspc: { type: Sequelize.STRING, primaryKey: true},
  tcb_info: { type: Sequelize.BLOB },
  root_cert_id: { type: Sequelize.INTEGER },
  signing_cert_id: { type: Sequelize.INTEGER }
},{
    timestamps: true,
    createdAt: 'created_time',
    updatedAt: 'updated_time'
});

const QEIdentity = sequelize.define('qe_identity', {
  id: { type: Sequelize.INTEGER, primaryKey: true},
  qe_identity: { type: Sequelize.BLOB },
  root_cert_id: { type: Sequelize.INTEGER },
  signing_cert_id: { type: Sequelize.INTEGER }
},{
    timestamps: true,
    createdAt: 'created_time',
    updatedAt: 'updated_time'
});

const QvEIdentity = sequelize.define('qve_identity', {
  id: { type: Sequelize.INTEGER, primaryKey: true},
  qve_identity: { type: Sequelize.BLOB },
  root_cert_id: { type: Sequelize.INTEGER },
  signing_cert_id: { type: Sequelize.INTEGER }
},{
    timestamps: true,
    createdAt: 'created_time',
    updatedAt: 'updated_time'
});

const initialize_db = false;
PckCert.sync({force:initialize_db});
PlatformTcb.sync({force:initialize_db});
PckCrl.sync({force:initialize_db});
FmspcTcb.sync({force:initialize_db});
PcsCertificates.sync({force:initialize_db});
QEIdentity.sync({force:initialize_db});
QvEIdentity.sync({force:initialize_db});
//---------------------------------------------------------------------------//
const PROCESSOR_ROOT_CERT_ID = 1;
const PROCESSOR_INTERMEDIATE_CERT_ID = 2;
const PROCESSOR_SIGNING_CERT_ID = 3;

// Update or Insert a PCK Certificate
exports.upsertCert = function(qe_id, enc_ppid, cpu_svn, pce_svn, pce_id, sgx_tcbm, fmspc, pck_cert){
    return new Promise(async (resolve,reject)=>{
        try {
            return await sequelize.transaction(async function(t) {
                await PlatformTcb.upsert({
                    qe_id: qe_id,
                    pce_id: pce_id,
                    cpu_svn: cpu_svn,
                    pce_svn: pce_svn,
                    enc_ppid: enc_ppid,
                    tcbm: sgx_tcbm
                }, {transaction: t});
                await PckCert.upsert({
                    qe_id: qe_id,
                    pce_id: pce_id,
                    tcbm: sgx_tcbm,
                    fmspc: fmspc,
                    pck_cert: pck_cert,
                    root_cert_id: PROCESSOR_ROOT_CERT_ID,
                    intmd_cert_id: PROCESSOR_INTERMEDIATE_CERT_ID
                }, {transaction: t});
                resolve();
            });
        }
        catch(err){
            reject(err);
        }
    });
}

// Query a PCK Certificate
exports.getCert = function(qe_id, cpu_svn, pce_svn, pce_id){
    return new Promise(async (resolve,reject)=>{
        try {
            const sql = 'select b.*,' +
                      ' (select cert from pcs_certificates where id=b.root_cert_id) as root_cert,' +
                      ' (select cert from pcs_certificates where id=b.intmd_cert_id) as intmd_cert' +
                      ' from platform_tcbs a, pck_cert b ' +
                      ' where a.qe_id=$qe_id and a.pce_id=$pce_id and a.cpu_svn=$cpu_svn and a.pce_svn=$pce_svn' +
                      ' and a.qe_id=b.qe_id and a.pce_id=b.pce_id and a.tcbm=b.tcbm';
            const pckcert = await sequelize.query(sql,
                {
                    type:  sequelize.QueryTypes.SELECT,
                    bind: {
                            qe_id : qe_id,
                            pce_id : pce_id,
                            cpu_svn : cpu_svn,
                            pce_svn : pce_svn
                          }
                });
            if (pckcert.length == 0)
                resolve(null);
            else if (pckcert.length == 1 ){
                if (pckcert[0].root_cert != null && pckcert[0].intmd_cert != null)
                    resolve(pckcert[0]);
                else resolve(null);
            }
            else 
                throw new Error('Unexpected error!');
        }
        catch(err){
            reject(err);
        }
    });
}

// Split a certchain into two certificates (root ca , intermediate or singing ca)
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

// Update or Insert a PCS certificate
upsertPcsCertificates = function(id, cert){
    return new Promise(async (resolve,reject)=>{
        try {
            resolve(await PcsCertificates.upsert({
                id: id,
                cert: cert
            }));
        }
        catch(err){
            reject(err);
        }
    });
}

// Update or Insert a certificate chain (root cert | intermediate or signing cert)
upsertPcsCertchain = function(certchain, first_cert_id, second_cert_id){
    return new Promise(async (resolve,reject)=>{
        try{
            const certs = split_chain(certchain);
            if (certs == null)
                throw new Error('Invalid certificate chain.');
            await upsertPcsCertificates(first_cert_id, certs[0]); 
            await upsertPcsCertificates(second_cert_id, certs[1]); 
            resolve();
        }
        catch(err){
            reject(err);
        }
    });
}

// Update or Insert SGX-PCK-Certificate-Issuer-Chain
exports.upsertPckCertchain = function(pck_certchain){
    return upsertPcsCertchain(pck_certchain, PROCESSOR_INTERMEDIATE_CERT_ID, PROCESSOR_ROOT_CERT_ID);
}

// Update or Insert SGX-PCK-CRL-Issuer-Chain
exports.upsertPckCrlCertchain = function(pck_crl_certchain){
    return upsertPcsCertchain(pck_crl_certchain, PROCESSOR_INTERMEDIATE_CERT_ID, PROCESSOR_ROOT_CERT_ID);
}

// Update or Insert SGX-TCB-Info-Issuer-Chain
exports.upsertTcbInfoCertchain = function(tcbinfo_certchain){
    return upsertPcsCertchain(tcbinfo_certchain, PROCESSOR_SIGNING_CERT_ID, PROCESSOR_ROOT_CERT_ID);
}

// Update or Insert SGX-ENCLAVE-Identity-Issuer-Chain
exports.upsertEnclaveIdentityCertchain = function(enclave_identity_certchain){
    return upsertPcsCertchain(enclave_identity_certchain, PROCESSOR_SIGNING_CERT_ID, PROCESSOR_ROOT_CERT_ID);
}

// Query root certificate and CRL
exports.getRootCertCrl = function(){
    return new Promise(async (resolve,reject)=>{
        try {
            let PcsCertificate = await PcsCertificates.findOne({
                where: {
                    id: PROCESSOR_ROOT_CERT_ID
                }
            });

            if (PcsCertificate != null && PcsCertificate.crl != null) {
                resolve(PcsCertificate.crl);
                return;
            }
                
            if (PcsCertificate == null) {
                // Root Cert not cached
                const pck_server_res = await pckclient.getQEIdentity();
                if (pck_server_res.statusCode == 200) {
                    // update certificates
                    await this.upsertEnclaveIdentityCertchain(pck_server_res.headers['sgx-enclave-identity-issuer-chain']);
                    // Root cert should be cached now, query DB again
                    PcsCertificate = await PcsCertificates.findOne({
                        where: {
                            id: PROCESSOR_ROOT_CERT_ID
                        }
                    });
                    if (PcsCertificate == null){
                        reject(null);
                        return;
                    }
                }
                else {
                    reject(null);
                    return;
                }
            }

            const x509 = new X509();
            if (!x509.parseCert(unescape(PcsCertificate.cert)) || !x509.cdp_uri) {
                // Certificate is invalid
                throw new Error('Invalid PCS certificate!');
            }

            try {
                crl = await pckclient.getFileFromUrl(x509.cdp_uri);
            }
            catch(err){
                reject(null);
                return;
            }

            PcsCertificate.crl = crl;

            await PcsCertificates.upsert({
		    id: PcsCertificate.id,
		    cert: PcsCertificate.cert,
		    crl: PcsCertificate.crl
	    });
            resolve(crl);

        }
        catch(err){
            throw(err);
        }
    });
}

// Query all platform TCBs that has the same fmspc
exports.allPlatformTcbs = function(fmspc){
    if (fmspc == null) {
        return new Promise(async (resolve,reject)=>{
            try {
                resolve(await PlatformTcb.findAll());
            }
            catch(err){
                reject(err);
            }
        })
    }
    else {
        return new Promise(async (resolve,reject)=>{
            const sql = 'select * from platform_tcbs where (qe_id,pce_id,tcbm) in (select qe_id,pce_id,tcbm from pck_cert where fmspc=$fmspc)';
            try {
                resolve(await sequelize.query(sql,
                    {
                        type:  sequelize.QueryTypes.SELECT,
                        bind: {fmspc : fmspc}
                    }));
            }
            catch(err){
                reject(err);
            }
        });
    }
}

//Update or Insert a PCK CRL
exports.upsertPckCrl = function(ca, pck_crl){
    return new Promise(async (resolve,reject)=>{
        try {
            resolve(await PckCrl.upsert({
                    ca: ca,
                    pck_crl: pck_crl,
                    root_cert_id: PROCESSOR_ROOT_CERT_ID,
                    intmd_cert_id: PROCESSOR_INTERMEDIATE_CERT_ID
            }));
        }
        catch(err){
            reject(err);
        }
    });
}

//Query a PCK CRL by ca
exports.getPckCrl = function(ca){
    return new Promise(async (resolve,reject)=>{
        try {
            const sql = 'select a.*,' +
                      ' (select cert from pcs_certificates where id=a.root_cert_id) as root_cert,' +
                      ' (select cert from pcs_certificates where id=a.intmd_cert_id) as intmd_cert' +
                      ' from pck_crl a ' +
                      ' where a.ca=$ca';
            const pckcrl = await sequelize.query(sql,
                {
                    type:  sequelize.QueryTypes.SELECT,
                    bind: { ca : ca }
                });
            if (pckcrl.length == 0)
                resolve(null);
            else if (pckcrl.length == 1 ){
                if (pckcrl[0].root_cert != null && pckcrl[0].intmd_cert != null)
                    resolve(pckcrl[0]);
                else resolve(null);
            }
            else 
                throw new Error('Unexpected error!');
        }
        catch(err){
            reject(err);
        }
    });
}

//Query all PCK CRLs from table
exports.getAllPckCrls = function(){
    return new Promise(async (resolve,reject)=>{
        try {
            const sql = 'select a.*,' +
                      ' (select cert from pcs_certificates where id=a.root_cert_id) as root_cert,' +
                      ' (select cert from pcs_certificates where id=a.intmd_cert_id) as intmd_cert' +
                      ' from pck_crl a ';
            const pckcrls = await sequelize.query(sql,
                {
                    type:  sequelize.QueryTypes.SELECT
                });
            resolve(pckcrls);
        }
        catch(err){
            reject(err);
        }
    });
}

//Update or Insert a TCBInfo record
exports.upsertTcb = function(fmspc, tcb_info){
    return new Promise(async (resolve,reject)=>{
        try{
            resolve(await FmspcTcb.upsert({
                    fmspc: fmspc,
                    tcb_info: tcb_info,
                    root_cert_id: PROCESSOR_ROOT_CERT_ID,
                    signing_cert_id: PROCESSOR_SIGNING_CERT_ID
            }));
        }
        catch(err){
            reject(err);
        }
    });
}

//Query TCBInfo by fmspc
exports.getTcb = function(fmspc){
    return new Promise(async (resolve,reject)=>{
        try{
            const sql = 'select a.*,' +
                      ' (select cert from pcs_certificates where id=a.root_cert_id) as root_cert,' +
                      ' (select cert from pcs_certificates where id=a.signing_cert_id) as signing_cert' +
                      ' from fmspc_tcbs a ' +
                      ' where a.fmspc=$fmspc';
            const tcbinfo = await sequelize.query(sql,
                {
                    type:  sequelize.QueryTypes.SELECT,
                    bind: { fmspc : fmspc }
                });
            if (tcbinfo.length == 0)
                resolve(null);
            else if (tcbinfo.length == 1 ){
                if (tcbinfo[0].root_cert != null && tcbinfo[0].signing_cert != null)
                    resolve(tcbinfo[0]);
                else resolve(null);
            }
            else 
                throw new Error('Unexpected error!');
        }
        catch(err){
            reject(err);
        }
    })
}

//Query all TCBInfos
exports.getAllTcbs = function(){
    return new Promise(async (resolve,reject)=>{
        try{
            resolve(await FmspcTcb.findAll());
        }
        catch(err){
            reject(err);
        }
    })
}

//Update or Insert QEIdentity
exports.upsertQEIdentity = function(qe_identity){
    return new Promise(async (resolve,reject)=>{
        try{
            resolve(await QEIdentity.upsert({
                    id: 1,
                    qe_identity: qe_identity,
                    root_cert_id: PROCESSOR_ROOT_CERT_ID,
                    signing_cert_id: PROCESSOR_SIGNING_CERT_ID
            }));
        }
        catch(err){
            reject(err);
        }
    });
}

//Query QEIdentity
exports.getQEIdentity = function(){
    return new Promise(async (resolve,reject)=>{
        try {
            const sql = 'select a.*,' +
                      ' (select cert from pcs_certificates where id=a.root_cert_id) as root_cert,' +
                      ' (select cert from pcs_certificates where id=a.signing_cert_id) as signing_cert' +
                      ' from qe_identity a ' +
                      ' where a.id=1';
            const qe_identity = await sequelize.query(sql,
                {
                    type:  sequelize.QueryTypes.SELECT
                });
            if (qe_identity.length == 0)
                resolve(null);
            else if (qe_identity.length == 1 ){
                if (qe_identity[0].root_cert != null && qe_identity[0].signing_cert != null)
                    resolve(qe_identity[0]);
                else resolve(null);
            }
            else 
                throw new Error('Unexpected error!');
        }
        catch(err){
            reject(err);
        }
    })
}

//Update or Insert QvEIdentity
exports.upsertQvEIdentity = function(qve_identity){
    return new Promise(async (resolve,reject)=>{
        try{
            resolve(await QvEIdentity.upsert({
                    id: 1,
                    qve_identity: qve_identity,
                    root_cert_id: PROCESSOR_ROOT_CERT_ID,
                    signing_cert_id: PROCESSOR_SIGNING_CERT_ID
            }));
        }
        catch(err){
            reject(err);
        }
    });
}

//Query QvEIdentity
exports.getQvEIdentity = function(){
    return new Promise(async (resolve,reject)=>{
        try {
            const sql = 'select a.*,' +
                      ' (select cert from pcs_certificates where id=a.root_cert_id) as root_cert,' +
                      ' (select cert from pcs_certificates where id=a.signing_cert_id) as signing_cert' +
                      ' from qve_identity a ' +
                      ' where a.id=1';
            const qve_identity = await sequelize.query(sql,
                {
                    type:  sequelize.QueryTypes.SELECT
                });
            if (qve_identity.length == 0)
                resolve(null);
            else if (qve_identity.length == 1 ){
                if (qve_identity[0].root_cert != null && qve_identity[0].signing_cert != null)
                    resolve(qve_identity[0]);
                else resolve(null);
            }
            else 
                throw new Error('Unexpected error!');
        }
        catch(err){
            reject(err);
        }
    })
}

exports.sequelize = sequelize;
