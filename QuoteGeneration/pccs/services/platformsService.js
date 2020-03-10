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
const platformsDao = require('../dao/platformsDao.js');
const pckcertDao = require('../dao/pckcertDao.js');
const pckcrlDao = require('../dao/pckcrlDao.js');
const qeidentityDao = require('../dao/qeidentityDao.js');
const qveidentityDao = require('../dao/qveidentityDao.js');
const pcsCertificatesDao = require('../dao/pcsCertificatesDao.js');
const pckcertService = require('./pckcertService.js');
const pckcrlService = require('./pckcrlService.js');
const identityService = require('./identityService.js');
const rootcacrlService = require('./rootcacrlService.js');
const PccsError = require('../utils/PccsError.js');
const PCCS_STATUS = require('../constants/pccs_status_code.js');
const Constants = require('../constants/index.js');
const Ajv = require('ajv');
const Schema = require('./pccs_schemas.js');
const Config = require('config');

const ajv = new Ajv();

exports.getCachedPlatforms=async function(fmspc_arr) {
    let platfs = await platformsDao.getCachedPlatformsByFmspc(fmspc_arr);

    for (const platf of platfs) {
        // Convert buffer to string
        if (platf.enc_ppid)
            platf.enc_ppid = platf.enc_ppid.toString('utf8');
        if (platf.platform_manifest)
            platf.platform_manifest = platf.platform_manifest.toString('utf8');
    }

    return platfs;
}
