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
import PccsError from '../../utils/PccsError.js';
import PccsStatus from '../../constants/pccs_status_code.js';
import Constants from '../../constants/index.js';
import logger from '../../utils/Logger.js';
import X509 from '../../x509/x509.js';
import * as pckcertDao from '../../dao/pckcertDao.js';
import * as pckCertchainDao from '../../dao/pckCertchainDao.js';
import * as platformTcbsDao from '../../dao/platformTcbsDao.js';
import * as pcsCertificatesDao from '../../dao/pcsCertificatesDao.js';
import * as enclaveIdentityDao from '../../dao/enclaveIdentityDao.js';
import * as pckcrlDao from '../../dao/pckcrlDao.js';
import * as fmspcTcbDao from '../../dao/fmspcTcbDao.js';
import * as platformsDao from '../../dao/platformsDao.js';
import * as crlCacheDao from '../../dao/crlCacheDao.js';
import * as pcsClient from '../../pcs_client/pcs_client.js';
import * as pckLibWrapper from '../../lib_wrapper/pcklib_wrapper.js';
import * as appUtil from '../../utils/apputil.js';
import { sequelize } from '../../dao/models/index.js';
import { cachingModeManager } from '../caching_modes/cachingModeManager.js';

async function getPckServerResponse(platform_manifest, enc_ppid, pceid) {
  if (platform_manifest) {
    return pcsClient.getCertsWithManifest(platform_manifest, pceid);
  } else if (enc_ppid && enc_ppid.match(/^0+$/)) {
    throw new PccsError(PccsStatus.PCCS_STATUS_NO_CACHE_DATA);
  } else {
    return pcsClient.getCerts(enc_ppid, pceid);
  }
}

function filterPckCerts(pckcerts) {
  const pckcerts_not_available = pckcerts.filter(pckCert => pckCert.cert === 'Not available');
  const pckcerts_valid = pckcerts.filter(pckCert => pckCert.cert !== 'Not available');
  return { pckcerts_valid, pckcerts_not_available };
}

function getFmspcAndCaType(pck_server_res) {
  let fmspc = pcsClient.getHeaderValue(pck_server_res.headers, Constants.SGX_FMSPC);
  let ca_type = pcsClient.getHeaderValue(pck_server_res.headers, Constants.SGX_PCK_CERTIFICATE_CA_TYPE);
  if (!fmspc || !ca_type) {
    throw new PccsError(PccsStatus.PCCS_STATUS_INTERNAL_ERROR);
  }
  fmspc = fmspc.toUpperCase();
  ca_type = ca_type.toUpperCase()
  return { fmspc, ca_type };
}

async function getTcbInfo(type, fmspc, version, update_type) {
  const pckServerRes = await pcsClient.getTcb(type, fmspc, version, update_type);
  if (pckServerRes.statusCode == Constants.HTTP_SUCCESS) {
    return {
      tcbinfo: pckServerRes.rawBody,
      tcbinfo_str: pckServerRes.body,
      tcbinfo_issuer_chain: pcsClient.getHeaderValue(
        pckServerRes.headers,
        appUtil.getTcbInfoIssuerChainName(version)
      )
    };
  }
  else {
    return null;
  }
}

function parsePckServerResponseBody(body) {
  if (typeof body === 'object') {
      return body;
  } else if (typeof body === 'string') {
      return JSON.parse(body);
  } else {
      throw new PccsError(PccsStatus.PCCS_STATUS_INTERNAL_ERROR);
  }
}

async function fetchTcbInfo(fmspc) {
  const tcbInfos = {};
  // Fetch SGX TCB info
  tcbInfos.sgx_early = await getTcbInfo(Constants.PROD_TYPE_SGX, fmspc, global.PCS_VERSION, Constants.UPDATE_TYPE_EARLY);
  tcbInfos.sgx_standard = await getTcbInfo(Constants.PROD_TYPE_SGX, fmspc, global.PCS_VERSION, Constants.UPDATE_TYPE_STANDARD);
  
  if (!tcbInfos.sgx_standard) {
    throw new PccsError(PccsStatus.PCCS_STATUS_NO_CACHE_DATA);
  }

  // Fetch TDX TCB info if applicable
  if (global.PCS_VERSION >= 4) {
    tcbInfos.tdx_early = await getTcbInfo(Constants.PROD_TYPE_TDX, fmspc, global.PCS_VERSION, Constants.UPDATE_TYPE_EARLY);
    tcbInfos.tdx_standard = await getTcbInfo(Constants.PROD_TYPE_TDX, fmspc, global.PCS_VERSION, Constants.UPDATE_TYPE_STANDARD);
  }

  return tcbInfos;
}

async function upsertTcbInfos(tcbInfos, fmspc, {transaction}) {
  for (const [key, tcbInfo] of Object.entries(tcbInfos)) {
    if (tcbInfo) {
      await fmspcTcbDao.upsertFmspcTcb({
        type: key.includes('sgx') ? Constants.PROD_TYPE_SGX : Constants.PROD_TYPE_TDX,
        fmspc: tcbInfo.fmspc || fmspc,
        version: global.PCS_VERSION,
        tcbinfo: tcbInfo.tcbinfo,
        update_type: key.includes('early') ? Constants.UPDATE_TYPE_EARLY : Constants.UPDATE_TYPE_STANDARD
      }, {transaction});
    }
  }
}

// Try to get PCK certs from Intel PCS for the platform with {pce_id, platform_manifest},
// and if platform manifest is not provided, then use {pce_id, enc_ppid} instead.
// Refresh the cache DB after a successful PCK certs retrieval.
// If raw TCB is not null, call the PCK cert selection tool to select the "best" cert for this
// raw TCB and update cache DB
export async function getPckCertFromPCS(
  qeid,
  cpusvn,
  pcesvn,
  pceid,
  enc_ppid,
  platform_manifest
) {
  let result = {};
  if (!enc_ppid && !platform_manifest) {
    throw new PccsError(PccsStatus.PCCS_STATUS_INVALID_REQ);
  }

  let pck_server_res = await getPckServerResponse(platform_manifest, enc_ppid, pceid);
  // check HTTP status
  if (pck_server_res.statusCode != Constants.HTTP_SUCCESS) {
    throw new PccsError(PccsStatus.PCCS_STATUS_NO_CACHE_DATA);
  }

  // PCK certificate issuer chain in response header
  const pck_certchain = pcsClient.getHeaderValue(
    pck_server_res.headers,
    Constants.SGX_PCK_CERTIFICATE_ISSUER_CHAIN
  );

  // Parse the response body
  let pckcerts = parsePckServerResponseBody(pck_server_res.body);

  // The latest PCS service may return 'Not available' in the certs array, need to filter them out
  const { pckcerts_valid, pckcerts_not_available } = filterPckCerts(pckcerts);
  await cachingModeManager.processNotAvailableTcbs(
    qeid,
    pceid,
    enc_ppid,
    platform_manifest,
    pckcerts_not_available
  );

  if (pckcerts_valid.length == 0) {
    throw new PccsError(PccsStatus.PCCS_STATUS_NO_CACHE_DATA);
  }

  // Make PEM certificates array
  let pem_certs = pckcerts_valid.map((o) => decodeURIComponent(o.cert));
  const { fmspc, ca_type } = getFmspcAndCaType(pck_server_res);

  // get tcbInfos for this fmspc
  const tcb_infos = await fetchTcbInfo(fmspc);
  let tcb_info_str = tcb_infos.sgx_early ? tcb_infos.sgx_early.tcbinfo_str : tcb_infos.sgx_standard.tcbinfo_str;

  // Before we flush the caching database, get current raw TCBs that are already cached
  // We need to re-run PCK cert selection tool for existing raw TCB levels due to certs change
  let cached_platform_tcbs = await platformTcbsDao.getPlatformTcbsById(qeid, pceid);

  // Database operations
  await sequelize.transaction(async (t) => {
    await platformsDao.upsertPlatform(qeid, pceid, platform_manifest, enc_ppid, fmspc, ca_type, {transaction: t});

    await pckcertDao.deleteCerts(qeid, pceid, {transaction: t});
    await Promise.all(pckcerts_valid.map(pckcert => 
      pckcertDao.upsertPckCert(qeid, pceid, pckcert.tcbm, decodeURIComponent(pckcert.cert), {transaction: t})
    ));

    await platformTcbsDao.deletePlatformTcbsById(qeid, pceid, {transaction: t});

    // Upsert TCB infos
    await upsertTcbInfos(tcb_infos, fmspc, {transaction: t});

    await pckCertchainDao.upsertPckCertchain(ca_type, {transaction: t});
    await pcsCertificatesDao.upsertPckCertificateIssuerChain(ca_type, pck_certchain, {transaction: t});
    await pcsCertificatesDao.upsertTcbInfoIssuerChain(tcb_infos.sgx_standard.tcbinfo_issuer_chain, {transaction: t});

    // Re-run PCK cert selection tool for all cached TCB levels
    for (const platform_tcb of cached_platform_tcbs) {
      let cert_index = pckLibWrapper.pck_cert_select(
        platform_tcb.cpu_svn,
        platform_tcb.pce_svn,
        platform_tcb.pce_id,
        tcb_info_str,
        pem_certs,
        pem_certs.length
      );

      if (cert_index == -1) {
        throw new PccsError(PccsStatus.PCCS_STATUS_NO_CACHE_DATA);
      }

      await platformTcbsDao.upsertPlatformTcbs(
        platform_tcb.qe_id,
        platform_tcb.pce_id,
        platform_tcb.cpu_svn,
        platform_tcb.pce_svn,
        pckcerts_valid[cert_index].tcbm,
        { transaction: t }
      );
    }  
  });

  if (!cpusvn || !pcesvn) return {}; // end here if raw TCB not provided
  // get the best cert with PCKCertSelectionTool for this raw TCB
  let cert_index = pckLibWrapper.pck_cert_select(
    cpusvn,
    pcesvn,
    pceid,
    tcb_info_str,
    pem_certs,
    pem_certs.length
  );
  if (cert_index == -1) {
    throw new PccsError(PccsStatus.PCCS_STATUS_NO_CACHE_DATA);
  }

  // create an entry for the new TCB level unless it's LAZY mode and
  // there are 'Not available' certificates for some TCB levels
  let hasNotAvailableCerts = pckcerts_not_available.length > 0;
  if (cachingModeManager.needUpdatePlatformTcbs(hasNotAvailableCerts)) {
    await platformTcbsDao.upsertPlatformTcbs(
      qeid,
      pceid,
      cpusvn,
      pcesvn,
      pckcerts_valid[cert_index].tcbm
    );
  }

  result[Constants.SGX_TCBM] = pckcerts_valid[cert_index].tcbm;
  result[Constants.SGX_FMSPC] = fmspc;
  result[Constants.SGX_PCK_CERTIFICATE_CA_TYPE] = ca_type;
  result[Constants.SGX_PCK_CERTIFICATE_ISSUER_CHAIN] = pck_certchain;
  result['cert'] = pem_certs[cert_index];

  return result;
}

export async function getPckCrlFromPCS(ca) {
  const pck_server_res = await pcsClient.getPckCrl(ca);

  if (pck_server_res.statusCode != Constants.HTTP_SUCCESS) {
    throw new PccsError(PccsStatus.PCCS_STATUS_NO_CACHE_DATA);
  }

  let result = {};
  result[Constants.SGX_PCK_CRL_ISSUER_CHAIN] = pcsClient.getHeaderValue(
    pck_server_res.headers,
    Constants.SGX_PCK_CRL_ISSUER_CHAIN
  );
  let crl = pck_server_res.rawBody;
  result['pckcrl'] = crl;

  await sequelize.transaction(async (t) => {
    // update or insert PCK CRL
    await pckcrlDao.upsertPckCrl(ca, crl);
    // update or insert certificate chain
    await pcsCertificatesDao.upsertPckCrlCertchain(
      ca,
      pcsClient.getHeaderValue(
        pck_server_res.headers,
        Constants.SGX_PCK_CRL_ISSUER_CHAIN
      )
    );
  });
  return result;
}

export async function getTcbInfoFromPCS(type, fmspc, version, update_type) {
  const pck_server_res = await pcsClient.getTcb(type, fmspc, version, update_type);

  if (pck_server_res.statusCode != Constants.HTTP_SUCCESS) {
    throw new PccsError(PccsStatus.PCCS_STATUS_NO_CACHE_DATA);
  }

  let result = {};
  let issuerChainName = appUtil.getTcbInfoIssuerChainName(version);
  result[issuerChainName] = pcsClient.getHeaderValue(
    pck_server_res.headers,
    issuerChainName
  );
  result['tcbinfo'] = pck_server_res.rawBody;

  await sequelize.transaction(async (t) => {
    // update or insert TCB Info
    await fmspcTcbDao.upsertFmspcTcb({
      type: type,
      fmspc: fmspc,
      version: version,
      update_type: update_type,
      tcbinfo: result['tcbinfo'],
    });
    // update or insert certificate chain
    await pcsCertificatesDao.upsertTcbInfoIssuerChain(result[issuerChainName]);
  });

  return result;
}

export async function getEnclaveIdentityFromPCS(enclave_id, version, update_type) {
  const pck_server_res = await pcsClient.getEnclaveIdentity(enclave_id, version, update_type);

  if (pck_server_res.statusCode != Constants.HTTP_SUCCESS) {
    throw new PccsError(PccsStatus.PCCS_STATUS_NO_CACHE_DATA);
  }

  let result = {};
  result[Constants.SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN] =
    pcsClient.getHeaderValue(
      pck_server_res.headers,
      Constants.SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN
    );
  result['identity'] = pck_server_res.rawBody;

  await sequelize.transaction(async (t) => {
    // update or insert QE Identity
    await enclaveIdentityDao.upsertEnclaveIdentity(
      enclave_id,
      pck_server_res.rawBody,
      version,
      update_type
    );
    // update or insert certificate chain
    await pcsCertificatesDao.upsertEnclaveIdentityIssuerChain(
      pcsClient.getHeaderValue(
        pck_server_res.headers,
        Constants.SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN
      )
    );
  });

  return result;
}

export async function getRootCACrlFromPCS(rootca) {
  return await sequelize.transaction(async (t) => {
    if (rootca == null) {
      // Root Cert not cached
      const pck_server_res = await pcsClient.getEnclaveIdentity(
        Constants.QE_IDENTITY_ID,
        global.PCS_VERSION,
        Constants.UPDATE_TYPE_STANDARD
      );
      if (pck_server_res.statusCode == Constants.HTTP_SUCCESS) {
        // update certificates
        await pcsCertificatesDao.upsertEnclaveIdentityIssuerChain(
          pcsClient.getHeaderValue(
            pck_server_res.headers,
            Constants.SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN
          )
        );
        // Root cert should be cached now, query DB again
        rootca = await pcsCertificatesDao.getCertificateById(
          Constants.PROCESSOR_ROOT_CERT_ID
        );
        if (rootca == null) {
          return null;
        }
      } else {
        return null;
      }
    }

    const x509 = new X509();
    if (!x509.parseCert(decodeURIComponent(rootca.cert)) || !x509.cdp_uri) {
      // Certificate is invalid
      throw new Error('Invalid PCS certificate!');
    }

    rootca.crl = await pcsClient.getFileFromUrl(x509.cdp_uri);

    await pcsCertificatesDao.upsertPcsCertificates({
      id: rootca.id,
      cert: rootca.cert,
      crl: rootca.crl,
    });

    return rootca.crl;
  });
}

export async function getCrlFromPCS(uri) {
  let crl = await pcsClient.getFileFromUrl(uri);

  await crlCacheDao.upsertCrl(uri, crl);

  return crl;
}
