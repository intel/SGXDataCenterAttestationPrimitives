/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
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
import logger from '../utils/Logger.js';
import PccsError from '../utils/PccsError.js';
import PccsStatus from '../constants/pccs_status_code.js';
import Constants from '../constants/index.js';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import X509 from '../x509/x509.js';
import * as platformsDao from '../dao/platformsDao.js';
import * as pckcertDao from '../dao/pckcertDao.js';
import * as platformTcbsDao from '../dao/platformTcbsDao.js';
import * as fmspcTcbDao from '../dao/fmspcTcbDao.js';
import * as pckcrlDao from '../dao/pckcrlDao.js';
import * as enclaveIdentityDao from '../dao/enclaveIdentityDao.js';
import * as pckCertchainDao from '../dao/pckCertchainDao.js';
import * as pcsCertificatesDao from '../dao/pcsCertificatesDao.js';
import * as crlCacheDao from '../dao/crlCacheDao.js';
import * as pckLibWrapper from '../lib_wrapper/pcklib_wrapper.js';
import * as appUtil from '../utils/apputil.js';
import {
  PLATFORM_COLLATERAL_SCHEMA_V3,
  PLATFORM_COLLATERAL_SCHEMA_V4,
} from './pccs_schemas.js';
import { sequelize } from '../dao/models/index.js';

const ajv = new Ajv();
addFormats(ajv);

function toUpper(str) {
  if (str) return str.toUpperCase();
  else return str;
}

function verify_cert(root1, root2) {
  if (Boolean(root1) && Boolean(root2) && root1 != root2) return false;
  return true;
}

async function upsertIdentity(identityType, identity, version, updateType) {
  if (identity) {
    await enclaveIdentityDao.upsertEnclaveIdentity(
      identityType,
      identity,
      version,
      updateType
    );
  }
}

async function validateCollateral(collateralJson, version) {
  const schema = version < 4 ? PLATFORM_COLLATERAL_SCHEMA_V3 : PLATFORM_COLLATERAL_SCHEMA_V4;
  const validate = ajv.compile(schema);
  const valid = validate(collateralJson);

  if (!valid) {
    validate.errors.forEach(err => {
      logger.error(err.schemaPath);
      logger.error(err.message);
    });
    throw new PccsError(PccsStatus.PCCS_STATUS_INVALID_REQ);
  }
}

async function processPckCerts(collateralJson, version) {
  const { platforms, collaterals } = collateralJson;

  for (const platformCerts of collaterals.pck_certs) {
    const { qe_id: rawQeId, pce_id: rawPceId, certs } = platformCerts;
    const qeId = toUpper(rawQeId);
    const pceId = toUpper(rawPceId);

    if (!certs || certs.length === 0) {
      throw new PccsError(PccsStatus.PCCS_STATUS_INVALID_REQ);
    }

    // Flush and add certs for this platform    
    await pckcertDao.deleteCerts(qeId, pceId);

    // unescape certificates
    const decodedCerts = certs.map(cert => ({
      tcbm: toUpper(cert.tcbm),
      cert: decodeURIComponent(cert.cert)
    }));

    for (const { tcbm, cert } of decodedCerts) {
      await pckcertDao.upsertPckCert(qeId, pceId, tcbm, cert);
    }    

    // We will update platforms both in cache and in the request list
    // make a full list based on the cache data and the input data
    const cachedPlatformTcbs = await platformTcbsDao.getPlatformTcbsById(qeId, pceId);
    const newPlatforms = platforms.filter(o => o.pce_id === rawPceId && o.qe_id === rawQeId);
    const newRawTcbs = newPlatforms.filter(o => Boolean(o.cpu_svn) && Boolean(o.pce_svn));

    // put all together
    const platformsCleaned = [...new Set([...cachedPlatformTcbs, ...newRawTcbs])];

    // parse arbitary cert to get fmspc value
    const x509 = new X509();
    if (!x509.parseCert(decodedCerts[0].cert)) {
      logger.error('Invalid certificate format.');
      throw new PccsError(PccsStatus.PCCS_STATUS_INVALID_REQ);
    }

    const { fmspc, ca } = x509;
    if (!fmspc || !ca) {
      logger.error('Invalid certificate format.');
      throw new PccsError(PccsStatus.PCCS_STATUS_INVALID_REQ);
    }

    // get tcbinfo for the fmspc
    const tcbinfo = collaterals.tcbinfos.find((o) => o.fmspc === fmspc);
    if (!tcbinfo) {
      logger.error("Can't find TCB info.");
      throw new PccsError(PccsStatus.PCCS_STATUS_INVALID_REQ);
    }

    let tcbinfoStr;
    if (version < 4) {
      tcbinfoStr = tcbinfo.tcbinfo_early ? JSON.stringify(tcbinfo.tcbinfo_early) :
                   tcbinfo.tcbinfo ? JSON.stringify(tcbinfo.tcbinfo) :
                   null;
    } else {
      tcbinfoStr = tcbinfo.sgx_tcbinfo_early ? JSON.stringify(tcbinfo.sgx_tcbinfo_early) :
              (tcbinfo.sgx_tcbinfo ? JSON.stringify(tcbinfo.sgx_tcbinfo) :
              null);
    }
    if (tcbinfoStr === null) {
      logger.error("Can't find TCB info.");
      throw new PccsError(PccsStatus.PCCS_STATUS_INVALID_REQ);
    }
    for (let platform of platformsCleaned) {
      // get the best cert with PCKCertSelectionTool
      const cert_index = pckLibWrapper.pck_cert_select(
        platform.cpu_svn,
        platform.pce_svn,
        platform.pce_id,
        tcbinfoStr,
        decodedCerts.map(c => c.cert),
        decodedCerts.length
      );
      if (cert_index === -1) {
        logger.error('Failed to select the best certificate for ' + platform);
        throw new PccsError(PccsStatus.PCCS_STATUS_INVALID_REQ);
      }

      // update platform_tcbs table
      await platformTcbsDao.upsertPlatformTcbs(
        qeId,
        pceId,
        toUpper(platform.cpu_svn),
        toUpper(platform.pce_svn),
        decodedCerts[cert_index].tcbm
      );
    }

    // update platforms table for new platforms only
    for (const platform of newPlatforms) {
      await platformsDao.upsertPlatform(
        qeId,
        pceId,
        toUpper(platform.platform_manifest),
        toUpper(platform.enc_ppid),
        toUpper(fmspc),
        toUpper(ca)
      );
    }
  }
}

async function processTcbInfo(tcbinfo, version) {
  const newTcbInfo = { fmspc: toUpper(tcbinfo.fmspc), version };

  const tcbTypes = version < 4 
    ? ['tcbinfo', 'tcbinfo_early'] 
    : ['sgx_tcbinfo', 'tdx_tcbinfo', 'sgx_tcbinfo_early', 'tdx_tcbinfo_early'];

  for (const type of tcbTypes) {
    if (tcbinfo[type]) {
      newTcbInfo.type = type.startsWith('tdx') ? Constants.PROD_TYPE_TDX : Constants.PROD_TYPE_SGX;
      newTcbInfo.tcbinfo = Buffer.from(JSON.stringify(tcbinfo[type]));
      newTcbInfo.update_type = type.includes('early') ? Constants.UPDATE_TYPE_EARLY : Constants.UPDATE_TYPE_STANDARD;
      await fmspcTcbDao.upsertFmspcTcb(newTcbInfo);
    }
  }
}

async function processPckCacrl(pckcacrl) {
  if (pckcacrl) {
    if (pckcacrl.processorCrl) {
      await pckcrlDao.upsertPckCrl(Constants.CA_PROCESSOR, Buffer.from(pckcacrl.processorCrl, 'hex'));
    }
    if (pckcacrl.platformCrl) {
      await pckcrlDao.upsertPckCrl(Constants.CA_PLATFORM, Buffer.from(pckcacrl.platformCrl, 'hex'));
    }
  }
}

async function processCertificates(certificates, version) {
  const rootCert = [];

  // Process SGX_PCK_CERTIFICATE_ISSUER_CHAIN for both CA_PROCESSOR and CA_PLATFORM
  const pckCertChainTypes = [Constants.CA_PROCESSOR, Constants.CA_PLATFORM];
  for (const type of pckCertChainTypes) {
    if (certificates[Constants.SGX_PCK_CERTIFICATE_ISSUER_CHAIN]?.[type]) {
      rootCert.push(
        await pcsCertificatesDao.upsertPckCertificateIssuerChain(
          type,
          certificates[Constants.SGX_PCK_CERTIFICATE_ISSUER_CHAIN][type]
        )
      );
    }
  }

  // Process TCB Info Issuer Chain
  if (certificates[appUtil.getTcbInfoIssuerChainName(version)]) {
    rootCert.push(
      await pcsCertificatesDao.upsertTcbInfoIssuerChain(
        certificates[appUtil.getTcbInfoIssuerChainName(version)]
      )
    );
  }

  // Process Enclave Identity Issuer Chain
  if (certificates[Constants.SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN]) {
    rootCert.push(
      await pcsCertificatesDao.upsertEnclaveIdentityIssuerChain(
        certificates[Constants.SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN]
      )
    );
  }

  return rootCert;
}

function verifyCertChain(rootCert) {
  for (let i = 0; i < rootCert.length - 1; i++) {
    if (!verify_cert(rootCert[i], rootCert[i + 1])) {
      return false;
    }
  }
  return true;
}

async function processRootCacrl(rootcacrl, rootcacrlCdp) {
  if (rootcacrl) {
    await pcsCertificatesDao.upsertRootCACrl(Buffer.from(rootcacrl, 'hex'));
    if (rootcacrlCdp) {
      await crlCacheDao.upsertCrl(rootcacrlCdp, Buffer.from(rootcacrl, 'hex'));
    }
  }
}

export async function addPlatformCollateral(collateralJson, version) {
  return await sequelize.transaction(async (t) => {
    await validateCollateral(collateralJson, version);

    const { collaterals } = collateralJson;
    const { tcbinfos } = collaterals;

    // process the PCK certificates
    await processPckCerts(collateralJson, version);

    // process the TCB infos
    for (const tcbinfo of tcbinfos) {
      await processTcbInfo(tcbinfo, version);
    }

    // process the PCK CRLs
    await processPckCacrl(collaterals.pckcacrl);

    // process the QE Identity
    await upsertIdentity(Constants.QE_IDENTITY_ID, collaterals.qeidentity, version, Constants.UPDATE_TYPE_STANDARD);
    await upsertIdentity(Constants.QE_IDENTITY_ID, collaterals.qeidentity_early, version, Constants.UPDATE_TYPE_EARLY);

    // process the TDQE Identity
    await upsertIdentity(Constants.TDQE_IDENTITY_ID, collaterals.tdqeidentity, version, Constants.UPDATE_TYPE_STANDARD);
    await upsertIdentity(Constants.TDQE_IDENTITY_ID, collaterals.tdqeidentity_early, version, Constants.UPDATE_TYPE_EARLY);

    // process the QvE Identity
    await upsertIdentity(Constants.QVE_IDENTITY_ID, collaterals.qveidentity, version, Constants.UPDATE_TYPE_STANDARD);
    await upsertIdentity(Constants.QVE_IDENTITY_ID, collaterals.qveidentity_early, version, Constants.UPDATE_TYPE_EARLY);

    // process the PCK Certchain
    await pckCertchainDao.upsertPckCertchain(Constants.CA_PROCESSOR);
    await pckCertchainDao.upsertPckCertchain(Constants.CA_PLATFORM);

    // process the intermediate or signing certificates
    const rootCert = await processCertificates(collaterals.certificates, version);
    if (!verifyCertChain(rootCert)) {
      throw new PccsError(PccsStatus.PCCS_STATUS_INTEGRITY_ERROR);
    }

    // process the rootcacrl
    await processRootCacrl(collaterals.rootcacrl, collaterals.rootcacrl_cdp);
  });
}
