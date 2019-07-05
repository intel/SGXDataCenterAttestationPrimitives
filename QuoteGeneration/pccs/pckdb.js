const Sequelize = require('sequelize');
const config = require('./config.json');
const winston = require('./winston');
const sequelize = new Sequelize('database', 'username', 'password', {
  host: 'localhost',
  dialect: 'sqlite',
  operatorsAliases: false,

  pool: {
    max: 5,
    min: 0,
    acquire: 30000,
    idle: 10000
  },

  // SQLite only
  storage: config.CacheDB,
  logging: (msg) => winston.info(msg),
});

//------------------------Model definitions----------------------------------//
const PckCerts = sequelize.define('pck_certs', {
  qe_id: { type: Sequelize.STRING, primaryKey: true},
  pce_id: { type: Sequelize.STRING, primaryKey: true },
  tcbm: { type: Sequelize.STRING, primaryKey: true },
  fmspc: { type: Sequelize.STRING },
  pck_cert: { type: Sequelize.BLOB },
  certchain_id: { type: Sequelize.INTEGER }
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
  enc_ppid: { type: Sequelize.STRING },
  tcbm: { type: Sequelize.STRING }
},{
    timestamps: true,
    createdAt: 'created_time',
    updatedAt: 'updated_time'
});

const PckCertchain = sequelize.define('pck_certchain', {
  id: { type: Sequelize.INTEGER,  autoIncrement: true, primaryKey: true},
  pck_certchain: { type: Sequelize.BLOB }
},{
    timestamps: true,
    createdAt: 'created_time',
    updatedAt: 'updated_time'
});

const PckCrl = sequelize.define('pck_crl', {
  ca: { type: Sequelize.STRING, primaryKey: true},
  crl_certchain: { type: Sequelize.BLOB },
  pck_crl: { type: Sequelize.BLOB }
},{
    timestamps: true,
    createdAt: 'created_time',
    updatedAt: 'updated_time'
});

const FmspcTcb = sequelize.define('fmspc_tcb', {
  fmspc: { type: Sequelize.STRING, primaryKey: true},
  tcb_info: { type: Sequelize.BLOB },
  tcb_info_issuer_chain: { type: Sequelize.BLOB }
},{
    timestamps: true,
    createdAt: 'created_time',
    updatedAt: 'updated_time'
});

const QEIdentity = sequelize.define('qe_identity', {
  qe_identity: { type: Sequelize.BLOB },
  qe_identity_issuer_chain: { type: Sequelize.BLOB }
},{
    timestamps: true,
    createdAt: 'created_time',
    updatedAt: 'updated_time'
});

PckCerts.belongsTo(PckCertchain, {foreignKey: 'certchain_id'});

const initialize_db = false;
PckCerts.sync({force:initialize_db});
PlatformTcb.sync({force:initialize_db});
PckCrl.sync({force:initialize_db});
FmspcTcb.sync({force:initialize_db});
PckCertchain.sync({force:initialize_db});
QEIdentity.sync({force:initialize_db});
//---------------------------------------------------------------------------//

exports.getCert = function(qe_id, cpu_svn, pce_svn, pce_id){
    return new Promise((resolve,reject)=>{
        PlatformTcb.findOne({
            where: {
                qe_id: qe_id,
                pce_id: pce_id,
                cpu_svn: cpu_svn,
                pce_svn: pce_svn
            }
        }).then(platformTcb=>{
            if (platformTcb != null) {
                PckCerts.findOne({
                    where: {
                        qe_id: qe_id,
                        pce_id: pce_id,
                        tcbm: platformTcb.tcbm
                    },
                    include: [PckCertchain]
                }).then(pckcert=>{
                    resolve(pckcert);
                }).catch(err=>{
                    reject(err);
                });
            }
            else {
                resolve(null);
            }
        }).catch(err=>{
            reject(err);
        });
    })
}

exports.upsertCert = function(qe_id, enc_ppid, cpu_svn, pce_svn, pce_id, sgx_tcbm, fmspc, pck_certchain, pck_cert){
    return new Promise((resolve,reject)=>{
        return sequelize.transaction(function(t) {
            return PckCertchain.findOrCreate(
                {
                    where: { pck_certchain: pck_certchain },
                    transaction: t
                }
            ).spread(function(certchain, created){
                if (certchain != null) {
                    return PlatformTcb.upsert({
                        qe_id: qe_id,
                        pce_id: pce_id,
                        cpu_svn: cpu_svn,
                        pce_svn: pce_svn,
                        enc_ppid: enc_ppid,
                        tcbm: sgx_tcbm
                    }, {transaction: t}).then(function(platform_tcb) {
                        return PckCerts.upsert({
                            qe_id: qe_id,
                            pce_id: pce_id,
                            tcbm: sgx_tcbm,
                            fmspc: fmspc,
                            pck_cert: pck_cert,
                            certchain_id: certchain.id
                        }, {transaction: t});
                    });
                }
                else {
                    throw new Error('Cannot find or create pck_certchain');
                }
            });
        }).then(function (result) {
            // Transaction has been committed
            // result is whatever the result of the promise chain returned to the transaction callback
            resolve(result);
        }).catch(function (err) {
            // Transaction has been rolled back
            // err is whatever rejected the promise chain returned to the transaction callback
            reject(err);
        });
    });
}

exports.allPlatformTcbs = function(fmspc){
    if (fmspc == null) {
        return new Promise((resolve,reject)=>{
            PlatformTcb.findAll().then(platformTcbs=>{
                resolve(platformTcbs);
            }).catch(err=>{
                reject(err);
            });
        })
    }
    else {
        return new Promise((resolve,reject)=>{
            var sql = 'select * from platform_tcbs where (qe_id,pce_id,tcbm) in (select qe_id,pce_id,tcbm from pck_certs where fmspc=$fmspc)';
            sequelize.query(sql,
                {
                    type:  sequelize.QueryTypes.SELECT,
                    bind: {fmspc : fmspc}
                }
            ).then(platformTcbs=>{
                resolve(platformTcbs);
            }).catch(err=>{
                reject(err);
            });
        });
    }
}

exports.getPckCrl = function(ca){
    return new Promise((resolve,reject)=>{
        PckCrl.findOne({
            where: {
                ca: ca
            }
        }).then(pckcrl=>{
            resolve(pckcrl);
        }).catch(err=>{
            reject(err);
        });
    })
}

exports.allCrls = function(){
    return new Promise((resolve,reject)=>{
        PckCrl.findAll().then(pckcrls=>{
            resolve(pckcrls);
        }).catch(err=>{
            reject(err);
        });
    })
}

exports.upsertCrl = function(ca, crl_certchain, pck_crl){
    return new Promise((resolve,reject)=>{
        return sequelize.transaction(function(t) {
            return PckCrl.upsert({
                ca: ca,
                crl_certchain: crl_certchain,
                pck_crl: pck_crl
            }, {transaction: t});
        }).then(function (result) {
            // Transaction has been committed
            // result is whatever the result of the promise chain returned to the transaction callback
            resolve(result);
        }).catch(function (err) {
            // Transaction has been rolled back
            // err is whatever rejected the promise chain returned to the transaction callback
            reject(err);
        });
    });
}

exports.getTcb = function(fmspc){
    return new Promise((resolve,reject)=>{
        FmspcTcb.findOne({
            where: {
                fmspc:fmspc 
            }
        }).then(tcb=>{
            resolve(tcb);
        }).catch(err=>{
            reject(err);
        });
    })
}

exports.allTcbs = function(){
    return new Promise((resolve,reject)=>{
        FmspcTcb.findAll().then(tcbs=>{
            resolve(tcbs);
        }).catch(err=>{
            reject(err);
        });
    })
}

exports.upsertTcb = function(fmspc, tcb_info, issuer_chain){
    return new Promise((resolve,reject)=>{
        return sequelize.transaction(function(t) {
            return FmspcTcb.upsert({
                fmspc: fmspc,
                tcb_info: tcb_info,
                tcb_info_issuer_chain: issuer_chain
            }, {transaction: t});
        }).then(function (result) {
            // Transaction has been committed
            // result is whatever the result of the promise chain returned to the transaction callback
            resolve(result);
        }).catch(function (err) {
            // Transaction has been rolled back
            // err is whatever rejected the promise chain returned to the transaction callback
            reject(err);
        });
    });
}

exports.getQEIdentity = function(){
    return new Promise((resolve,reject)=>{
        QEIdentity.findOne({
        }).then(qe_identity=>{
            resolve(qe_identity);
        }).catch(err=>{
            reject(err);
        });
    })
}

exports.delQEIdentity = function(){
    return new Promise((resolve,reject)=>{
        QEIdentity.destroy({
            where: {},
            truncate: true
        }).then(rowDeleted=>{
            resolve(rowDeleted);
        }).catch(err=>{
            reject(err);
        });
    })
}

exports.upsertQEIdentity = function(qe_identity, issuer_chain){
    return new Promise((resolve,reject)=>{
        return sequelize.transaction(function(t) {
            return QEIdentity.upsert({
                qe_identity: qe_identity,
                qe_identity_issuer_chain: issuer_chain
            }, {transaction: t});
        }).then(function (result) {
            // Transaction has been committed
            // result is whatever the result of the promise chain returned to the transaction callback
            resolve(result);
        }).catch(function (err) {
            // Transaction has been rolled back
            // err is whatever rejected the promise chain returned to the transaction callback
            reject(err);
        });
    });
}
