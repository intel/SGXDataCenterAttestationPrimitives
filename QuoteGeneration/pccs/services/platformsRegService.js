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
const platformsRegDao = require('../dao/platformsRegDao.js');
const platformsDao = require('../dao/platformsDao.js');
const platformTcbsDao = require('../dao/platformTcbsDao.js');
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
const {sequelize, Sequelize} = require('../dao/models/');

const ajv = new Ajv();

checkPCKCertCacheStatus=async function(platformInfoJson)
{
    let isCached = false;
    do {
        const platform = await platformsDao.getPlatform(platformInfoJson.qe_id, platformInfoJson.pce_id);
        if (platform == null) {
            break;
        }
        if (!Boolean(platformInfoJson.platform_manifest)) {
            // * treat the absence of the PLATFORMMANIFEST in the API while 
            // there is a PLATFORM_MANIFEST in the cache as a 'match' *
            platformInfoJson.platform_manifest = platform.platform_manifest;
            let pckcert = await pckcertDao.getCert(platformInfoJson.qe_id, 
                platformInfoJson.cpu_svn, platformInfoJson.pce_svn, platformInfoJson.pce_id);
            if (pckcert == null) {
                break;
            }
        }
        else if (platform.platform_manifest != platformInfoJson.platform_manifest) {
            // cached status is false
            break;
        }
        isCached = true;
    } while (false);

    return isCached;
}

checkQuoteVerificationCollateral=async function()
{
    // pck crl
    let pckcrl = await pckcrlDao.getPckCrl(Constants.CA_PROCESSOR);
    if (pckcrl == null) {
        await pckcrlService.getPckCrlFromPCS(Constants.CA_PROCESSOR);
    }
    if (pckcertService.getPcsVersion() >= 3) {
        pckcrl = await pckcrlDao.getPckCrl(Constants.CA_PLATFORM);
        if (pckcrl == null) {
            await pckcrlService.getPckCrlFromPCS(Constants.CA_PLATFORM);
        }
    }
    // QE identity
    const qeid = await qeidentityDao.getQEIdentity();
    if (qeid == null) {
        await identityService.getQEIdentityFromPCS();
    }
    // QVE identity
    const qveid = await qveidentityDao.getQvEIdentity();
    if (qveid == null) {
        await identityService.getQvEIdentityFromPCS();
    }
    // Root CA crl
    let rootca = await pcsCertificatesDao.getCertificateById(Constants.PROCESSOR_ROOT_CERT_ID);
    if (rootca == null || rootca.crl == null) {
        await rootcacrlService.getRootCACrlFromPCS(rootca);
    }
}

exports.registerPlatforms=async function(regDataJson) {
    //check parameters
    let valid = ajv.validate(Schema.PLATFORM_REG_SCHEMA, regDataJson);
    if (!valid) {
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_INVALID_REQ);
    }

    // normalize the registration data
    regDataJson.qe_id = regDataJson.qe_id.toUpperCase();
    regDataJson.pce_id = regDataJson.pce_id.toUpperCase();
    if (regDataJson.platform_manifest) {
        regDataJson.platform_manifest = regDataJson.platform_manifest.toUpperCase();
        // other parameters are useless
        regDataJson.cpu_svn = "";
        regDataJson.pce_svn = "";
        regDataJson.enc_ppid = "";
    }
    else {
        regDataJson.platform_manifest = '';
        if (!regDataJson.cpu_svn || !regDataJson.pce_svn || !regDataJson.enc_ppid)
            throw new PccsError(PCCS_STATUS.PCCS_STATUS_INVALID_REQ);
        regDataJson.cpu_svn = regDataJson.cpu_svn.toUpperCase();
        regDataJson.pce_svn = regDataJson.pce_svn.toUpperCase();
        regDataJson.enc_ppid = regDataJson.enc_ppid.toUpperCase();
    }

    // Get cache status
    let isCached = await checkPCKCertCacheStatus(regDataJson);

    if (Config.get(Constants.CONFIG_OPTION_CACHE_FILL_MODE) == Constants.CACHE_FILL_MODE_OFFLINE) {
        if (!isCached) {
            // add to registration table
            await platformsRegDao.registerPlatform(regDataJson, Constants.PLATF_REG_NEW);
        }
    }
    else {
        if (!isCached) {
            // For REQ mode, add registration entry first, and delete it after the collaterals are retrieved
            if (Config.get(Constants.CONFIG_OPTION_CACHE_FILL_MODE) == Constants.CACHE_FILL_MODE_REQ) {
                // add to registration table
                await platformsRegDao.registerPlatform(regDataJson, Constants.PLATF_REG_NEW);
            }

            // Get PCK certs from Intel PCS if not cached
            await pckcertService.getPckCertFromPCS(regDataJson.qe_id, 
                regDataJson.cpu_svn, regDataJson.pce_svn, regDataJson.pce_id, regDataJson.enc_ppid, regDataJson.platform_manifest);
            
            // For REQ mode, add registration entry first, and delete it after the collaterals are retrieved
            if (Config.get(Constants.CONFIG_OPTION_CACHE_FILL_MODE) == Constants.CACHE_FILL_MODE_REQ) {
                // delete registration entry
                await platformsRegDao.registerPlatform(regDataJson, Constants.PLATF_REG_DELETED);
            }
        }
        // Get other collaterals if not cached
        await checkQuoteVerificationCollateral();
    }
}

exports.getRegisteredPlatforms=async function() {
    let platfs = await platformsRegDao.findRegisteredPlatforms();

    return platfs;
}

exports.deleteRegisteredPlatforms=async function() {
    await platformsRegDao.deleteRegisteredPlatforms();
}
