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

const { pck_cert }= require('./models/');
const Constants = require('../constants/index.js');
const PccsError = require('../utils/PccsError.js');
const PCCS_STATUS = require('../constants/pccs_status_code.js');
const {Sequelize, sequelize} = require('./models/');

// Query a PCK Certificate
exports.getCert = async function(qe_id, cpu_svn, pce_svn, pce_id){
    const sql = 'select b.*,' +
              ' (select cert from pcs_certificates c, pck_certchain d where c.id=d.root_cert_id and d.id=1) as root_cert,' +
              ' (select cert from pcs_certificates c, pck_certchain d where c.id=d.intmd_cert_id and d.id=1) as intmd_cert' +
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
        return null;
    else if (pckcert.length == 1 ){
        if (pckcert[0].root_cert != null && pckcert[0].intmd_cert != null)
            return pckcert[0];
        else return null;
    }
    else 
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_INTERNAL_ERROR);
}

// Update or insert a record
exports.upsertPckCert = async function(qe_id, pce_id, tcbm, cert) {
    return await pck_cert.upsert({
        qe_id: qe_id,
        pce_id: pce_id,
        tcbm: tcbm,
        pck_cert: cert
    });
}

// delete certs for a platform
exports.deleteCerts = async function(qe_id, pce_id) {
    return await pck_cert.destroy(
        {where:{
            qe_id: qe_id,
            pce_id: pce_id
        }}
    );
}
