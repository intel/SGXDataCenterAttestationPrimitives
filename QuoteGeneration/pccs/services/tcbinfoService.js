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
const fmspcTcbDao = require('../dao/fmspcTcbDao.js');
const pcsCertificatesDao = require('../dao/pcsCertificatesDao.js');
const PccsError = require('../utils/PccsError.js');
const PCCS_STATUS = require('../constants/pccs_status_code.js');
const Config = require('config');
const Constants = require('../constants/index.js');
const PcsClient = require('../pcs_client/pcs_client.js');
const {sequelize, Sequelize} = require('../dao/models/');

exports.getTcbInfoFromPCS=async function(fmspc) {
    const pck_server_res = await PcsClient.getTcb(fmspc);

    if (pck_server_res.statusCode != Constants.HTTP_SUCCESS) {
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_NOT_FOUND);
    }

    let result = {};
    result[Constants.SGX_TCB_INFO_ISSUER_CHAIN] = pck_server_res.headers[Constants.SGX_TCB_INFO_ISSUER_CHAIN];
    result["tcbinfo"] = JSON.parse(pck_server_res.body);

    await sequelize.transaction(async (t)=>{
        // update or insert TCB Info 
        await fmspcTcbDao.upsertFmspcTcb({
            "fmspc": fmspc,
            "tcbinfo": result["tcbinfo"]
        });
        // update or insert certificate chain
        await pcsCertificatesDao.upsertTcbInfoIssuerChain(pck_server_res.headers[Constants.SGX_TCB_INFO_ISSUER_CHAIN]);
    });

    return result;
}

exports.getTcbInfo=async function(fmspc) {
    // query tcbinfo from local database first
    const tcbinfo = await fmspcTcbDao.getTcbInfo(fmspc);
    let result = {};
    if (tcbinfo == null) {
        if (Config.get(Constants.CONFIG_OPTION_CACHE_FILL_MODE) == Constants.CACHE_FILL_MODE_LAZY) {
            result = await this.getTcbInfoFromPCS(fmspc);    
        }
        else {
            throw new PccsError(PCCS_STATUS.PCCS_STATUS_NOT_FOUND);
        }
    }
    else {
        result[Constants.SGX_TCB_INFO_ISSUER_CHAIN] = tcbinfo.signing_cert + tcbinfo.root_cert;
        result["tcbinfo"] = JSON.parse(tcbinfo.tcbinfo);
    }

    return result;
}
