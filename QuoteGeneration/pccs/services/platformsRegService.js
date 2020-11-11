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
import PccsError from '../utils/PccsError.js';
import PccsStatus from '../constants/pccs_status_code.js';
import Constants from '../constants/index.js';
import Config from 'config';
import Ajv from 'ajv';
import * as platformsRegDao from '../dao/platformsRegDao.js';
import * as platformsDao from '../dao/platformsDao.js';
import * as pckcertDao from '../dao/pckcertDao.js';
import * as pckcrlDao from '../dao/pckcrlDao.js';
import * as qeidentityDao from '../dao/qeidentityDao.js';
import * as qveidentityDao from '../dao/qveidentityDao.js';
import * as pcsCertificatesDao from '../dao/pcsCertificatesDao.js';
import * as pckcertService from './pckcertService.js';
import * as pckcrlService from './pckcrlService.js';
import * as identityService from './identityService.js';
import * as rootcacrlService from './rootcacrlService.js';
import { PLATFORM_REG_SCHEMA } from './pccs_schemas.js';

const ajv = new Ajv();

async function checkPCKCertCacheStatus(platformInfoJson) {
  let isCached = false;
  do {
    const platform = await platformsDao.getPlatform(
      platformInfoJson.qe_id,
      platformInfoJson.pce_id
    );
    if (platform == null) {
      break;
    }
    if (!Boolean(platformInfoJson.platform_manifest)) {
      // * treat the absence of the PLATFORMMANIFEST in the API while
      // there is a PLATFORM_MANIFEST in the cache as a 'match' *
      platformInfoJson.platform_manifest = platform.platform_manifest;
      let pckcert = await pckcertDao.getCert(
        platformInfoJson.qe_id,
        platformInfoJson.cpu_svn,
        platformInfoJson.pce_svn,
        platformInfoJson.pce_id
      );
      if (pckcert == null) {
        break;
      }
    } else if (
      platform.platform_manifest != platformInfoJson.platform_manifest
    ) {
      // cached status is false
      break;
    }
    isCached = true;
  } while (false);

  return isCached;
}

async function checkQuoteVerificationCollateral() {
  // pck crl
  let pckcrl = await pckcrlDao.getPckCrl(Constants.CA_PROCESSOR);
  if (pckcrl == null) {
    await pckcrlService.getPckCrlFromPCS(Constants.CA_PROCESSOR);
  }
  pckcrl = await pckcrlDao.getPckCrl(Constants.CA_PLATFORM);
  if (pckcrl == null) {
    await pckcrlService.getPckCrlFromPCS(Constants.CA_PLATFORM);
  }

  // QE identity
  const qeid = await qeidentityDao.getQeIdentity();
  if (qeid == null) {
    await identityService.getQeIdentityFromPCS();
  }
  // QVE identity
  const qveid = await qveidentityDao.getQveIdentity();
  if (qveid == null) {
    await identityService.getQveIdentityFromPCS();
  }
  // Root CA crl
  let rootca = await pcsCertificatesDao.getCertificateById(
    Constants.PROCESSOR_ROOT_CERT_ID
  );
  if (rootca == null || rootca.crl == null) {
    await rootcacrlService.getRootCACrlFromPCS(rootca);
  }
}

export async function registerPlatforms(regDataJson) {
  //check parameters
  let valid = ajv.validate(PLATFORM_REG_SCHEMA, regDataJson);
  if (!valid) {
    throw new PccsError(PccsStatus.PCCS_STATUS_INVALID_REQ);
  }

  // normalize the registration data
  regDataJson.qe_id = regDataJson.qe_id.toUpperCase();
  regDataJson.pce_id = regDataJson.pce_id.toUpperCase();
  if (regDataJson.platform_manifest) {
    regDataJson.platform_manifest = regDataJson.platform_manifest.toUpperCase();
    // other parameters are useless
    regDataJson.cpu_svn = '';
    regDataJson.pce_svn = '';
    regDataJson.enc_ppid = '';
  } else {
    regDataJson.platform_manifest = '';
    if (!regDataJson.cpu_svn || !regDataJson.pce_svn || !regDataJson.enc_ppid)
      throw new PccsError(PccsStatus.PCCS_STATUS_INVALID_REQ);
    regDataJson.cpu_svn = regDataJson.cpu_svn.toUpperCase();
    regDataJson.pce_svn = regDataJson.pce_svn.toUpperCase();
    regDataJson.enc_ppid = regDataJson.enc_ppid.toUpperCase();
  }

  // Get cache status
  let isCached = await checkPCKCertCacheStatus(regDataJson);

  if (
    Config.get(Constants.CONFIG_OPTION_CACHE_FILL_MODE) ==
    Constants.CACHE_FILL_MODE_OFFLINE
  ) {
    if (!isCached) {
      // add to registration table
      await platformsRegDao.registerPlatform(
        regDataJson,
        Constants.PLATF_REG_NEW
      );
    }
  } else {
    if (!isCached) {
      // For REQ mode, add registration entry first, and delete it after the collaterals are retrieved
      if (
        Config.get(Constants.CONFIG_OPTION_CACHE_FILL_MODE) ==
        Constants.CACHE_FILL_MODE_REQ
      ) {
        // add to registration table
        await platformsRegDao.registerPlatform(
          regDataJson,
          Constants.PLATF_REG_NEW
        );
      }

      // Get PCK certs from Intel PCS if not cached
      await pckcertService.getPckCertFromPCS(
        regDataJson.qe_id,
        regDataJson.cpu_svn,
        regDataJson.pce_svn,
        regDataJson.pce_id,
        regDataJson.enc_ppid,
        regDataJson.platform_manifest
      );

      // For REQ mode, add registration entry first, and delete it after the collaterals are retrieved
      if (
        Config.get(Constants.CONFIG_OPTION_CACHE_FILL_MODE) ==
        Constants.CACHE_FILL_MODE_REQ
      ) {
        // delete registration entry
        await platformsRegDao.registerPlatform(
          regDataJson,
          Constants.PLATF_REG_DELETED
        );
      }
    }
    // Get other collaterals if not cached
    await checkQuoteVerificationCollateral();
  }
}

export async function getRegisteredPlatforms() {
  let platfs = await platformsRegDao.findRegisteredPlatforms();

  return platfs;
}

export async function deleteRegisteredPlatforms() {
  await platformsRegDao.deleteRegisteredPlatforms();
}
