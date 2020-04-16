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

const { platforms}= require('./models/');
const {Sequelize, sequelize} = require('./models/');

exports.upsertPlatform = async function(qe_id, pce_id, platform_manifest, enc_ppid, fmspc, ca) {
    return await platforms.upsert({
        qe_id: qe_id,
        pce_id: pce_id,
        platform_manifest: platform_manifest,
        enc_ppid: enc_ppid,
        fmspc: fmspc,
        ca: ca
    });
}

exports.getPlatform = async function(qe_id, pce_id) {
    return await platforms.findOne({where:
        {qe_id: qe_id,
         pce_id: pce_id
        }   
    });
}

exports.updatePlatform = async function(qe_id, pce_id, platform_manifest, enc_ppid) {
    return await platforms.update(
        {platform_manifest: platform_manifest,
         enc_ppid: enc_ppid   
        },
        {where:{
            qe_id: qe_id,
            pce_id: pce_id
        }}
    );
}

exports.getCachedPlatformsByFmspc = async function(fmspc_arr) {
    let sql = 'select a.qe_id, a.pce_id, b.cpu_svn, b.pce_svn, a.enc_ppid, a.platform_manifest ' +
              ' from platforms a, platform_tcbs b ' +
              ' where a.qe_id=b.qe_id and a.pce_id = b.pce_id ';
    if (fmspc_arr.length > 0) {
        sql += ' and a.fmspc in (:FMSPC)';
    }

    return await sequelize.query(sql,
        {
            replacements: {
                FMSPC: fmspc_arr
            },
            type:  sequelize.QueryTypes.SELECT
        });
}