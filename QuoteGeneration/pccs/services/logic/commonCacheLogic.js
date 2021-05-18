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
import * as pckcertDao from '../../dao/pckcertDao.js';
import * as pckCertchainDao from '../../dao/pckCertchainDao.js';
import * as platformTcbsDao from '../../dao/platformTcbsDao.js';
import * as pcsCertificatesDao from '../../dao/pcsCertificatesDao.js';
import * as qeidentityDao from '../../dao/qeidentityDao.js';
import * as qveidentityDao from '../../dao/qveidentityDao.js';
import * as pckcrlDao from '../../dao/pckcrlDao.js';
import * as fmspcTcbDao from '../../dao/fmspcTcbDao.js';
import * as platformsDao from '../../dao/platformsDao.js';
import * as pcsClient from '../../pcs_client/pcs_client.js';
import * as pckLibWrapper from '../../lib_wrapper/pcklib_wrapper.js';
import { sequelize } from '../../dao/models/index.js';
import X509 from '../../x509/x509.js';
import { cachingModeManager } from '../caching_modes/cachingModeManager.js';

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

  let pck_server_res;
  if (platform_manifest) {
    // if platform manifest is provided, will call Intel PCS API with platform manifest
    pck_server_res = await pcsClient.getCertsWithManifest(
      platform_manifest,
      pceid
    );
  } else {
    // if enc_ppid is all zero, return NOT_FOUND
    if (enc_ppid.match(/^0+$/)) {
      throw new PccsError(PccsStatus.PCCS_STATUS_NOT_FOUND);
    }

    // Call Intel PCS API with encrypted PPID
    pck_server_res = await pcsClient.getCerts(enc_ppid, pceid);
  }

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
  let pckcerts = null;
  if (typeof pck_server_res.body === 'object') {
    pckcerts = pck_server_res.body;
  } else if (typeof pck_server_res.body === 'string') {
    pckcerts = JSON.parse(pck_server_res.body);
  } else {
    throw new PccsError(PccsStatus.PCCS_STATUS_INTERNAL_ERROR);
  }

  // The latest PCS service may return 'Not available' in the certs array, need to filter them out
  let pckcerts_not_available = pckcerts.filter((pckcert) => {
    return pckcert.cert == 'Not available';
  });
  await cachingModeManager.processNotAvailableTcbs(
    qeid,
    pceid,
    enc_ppid,
    platform_manifest,
    pckcerts_not_available
  );

  // Certificates that are valid
  let pckcerts_valid = pckcerts.filter((pckcert) => {
    return pckcert.cert != 'Not available';
  });
  if (pckcerts_valid.length == 0) {
    throw new PccsError(PccsStatus.PCCS_STATUS_NO_CACHE_DATA);
  }

  // Get fmspc and ca type from response header
  const fmspc = pcsClient
    .getHeaderValue(pck_server_res.headers, Constants.SGX_FMSPC)
    .toUpperCase();
  const ca_type = pcsClient
    .getHeaderValue(
      pck_server_res.headers,
      Constants.SGX_PCK_CERTIFICATE_CA_TYPE
    )
    .toUpperCase();

  if (fmspc == null || ca_type == null) {
    throw new PccsError(PccsStatus.PCCS_STATUS_INTERNAL_ERROR);
  }

  // get tcbinfo for this fmspc
  pck_server_res = await pcsClient.getTcb(fmspc);
  if (pck_server_res.statusCode != Constants.HTTP_SUCCESS) {
    throw new PccsError(PccsStatus.PCCS_STATUS_NO_CACHE_DATA);
  }
  const tcbinfo = pck_server_res.rawBody;
  const tcbinfo_str = pck_server_res.body;
  const tcbinfo_issuer_chain = pcsClient.getHeaderValue(
    pck_server_res.headers,
    Constants.SGX_TCB_INFO_ISSUER_CHAIN
  );

  // Before we flush the caching database, get current raw TCBs that are already cached
  // We need to re-run PCK cert selection tool for existing raw TCB levels due to certs change
  let cached_platform_tcbs = await platformTcbsDao.getPlatformTcbsById(
    qeid,
    pceid
  );

  await sequelize.transaction(async (t) => {
    // Update the platform entry in the cache
    await platformsDao.upsertPlatform(
      qeid,
      pceid,
      platform_manifest,
      enc_ppid,
      fmspc,
      ca_type
    );

    // flush pck_cert
    await pckcertDao.deleteCerts(qeid, pceid);
    for (const pckcert of pckcerts_valid) {
      await pckcertDao.upsertPckCert(
        qeid,
        pceid,
        pckcert.tcbm,
        unescape(pckcert.cert)
      );
    }

    // delete old TCB mappings
    await platformTcbsDao.deletePlatformTcbsById(qeid, pceid);

    // Update or insert fmspc_tcbs
    await fmspcTcbDao.upsertFmspcTcb({
      fmspc: fmspc,
      tcbinfo: tcbinfo,
    });
    // Update or insert PCK Certchain
    await pckCertchainDao.upsertPckCertchain(ca_type);
    // Update or insert PCS certificates
    await pcsCertificatesDao.upsertPckCertificateIssuerChain(
      ca_type,
      pck_certchain
    );
    await pcsCertificatesDao.upsertTcbInfoIssuerChain(tcbinfo_issuer_chain);
  });

  // For all cached TCB levels, re-run PCK cert selection tool
  let pem_certs = pckcerts_valid.map((o) => unescape(o.cert));
  for (const platform_tcb of cached_platform_tcbs) {
    let cert_index = pckLibWrapper.pck_cert_select(
      platform_tcb.cpu_svn,
      platform_tcb.pce_svn,
      platform_tcb.pce_id,
      tcbinfo_str,
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
      pckcerts_valid[cert_index].tcbm
    );
  }
  if (!cpusvn || !pcesvn) return {}; // end here if raw TCB not provided
  // get the best cert with PCKCertSelectionTool for this raw TCB
  let cert_index = pckLibWrapper.pck_cert_select(
    cpusvn,
    pcesvn,
    pceid,
    tcbinfo_str,
    pem_certs,
    pem_certs.length
  );
  if (cert_index == -1) {
    throw new PccsError(PccsStatus.PCCS_STATUS_NO_CACHE_DATA);
  }

  // create an entry for the new TCB level
  await platformTcbsDao.upsertPlatformTcbs(
    qeid,
    pceid,
    cpusvn,
    pcesvn,
    pckcerts_valid[cert_index].tcbm
  );

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

export async function getTcbInfoFromPCS(fmspc) {
  const pck_server_res = await pcsClient.getTcb(fmspc);

  if (pck_server_res.statusCode != Constants.HTTP_SUCCESS) {
    throw new PccsError(PccsStatus.PCCS_STATUS_NO_CACHE_DATA);
  }

  let result = {};
  result[Constants.SGX_TCB_INFO_ISSUER_CHAIN] = pcsClient.getHeaderValue(
    pck_server_res.headers,
    Constants.SGX_TCB_INFO_ISSUER_CHAIN
  );
  result['tcbinfo'] = pck_server_res.rawBody;

  await sequelize.transaction(async (t) => {
    // update or insert TCB Info
    await fmspcTcbDao.upsertFmspcTcb({
      fmspc: fmspc,
      tcbinfo: result['tcbinfo'],
    });
    // update or insert certificate chain
    await pcsCertificatesDao.upsertTcbInfoIssuerChain(
      pcsClient.getHeaderValue(
        pck_server_res.headers,
        Constants.SGX_TCB_INFO_ISSUER_CHAIN
      )
    );
  });

  return result;
}

export async function getQeIdentityFromPCS() {
  const pck_server_res = await pcsClient.getQeIdentity();

  if (pck_server_res.statusCode != Constants.HTTP_SUCCESS) {
    throw new PccsError(PccsStatus.PCCS_STATUS_NO_CACHE_DATA);
  }

  let result = {};
  result[
    Constants.SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN
  ] = pcsClient.getHeaderValue(
    pck_server_res.headers,
    Constants.SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN
  );
  result['qeid'] = pck_server_res.rawBody;

  await sequelize.transaction(async (t) => {
    // update or insert QE Identity
    await qeidentityDao.upsertQeIdentity(pck_server_res.rawBody);
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

export async function getQveIdentityFromPCS() {
  const pck_server_res = await pcsClient.getQveIdentity();

  if (pck_server_res.statusCode != Constants.HTTP_SUCCESS) {
    throw new PccsError(PccsStatus.PCCS_STATUS_NO_CACHE_DATA);
  }

  let result = {};
  result[
    Constants.SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN
  ] = pcsClient.getHeaderValue(
    pck_server_res.headers,
    Constants.SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN
  );
  result['qveid'] = pck_server_res.rawBody;

  await sequelize.transaction(async (t) => {
    // update or insert QvE Identity
    await qveidentityDao.upsertQveIdentity(pck_server_res.rawBody);
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
      const pck_server_res = await pcsClient.getQeIdentity();
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
    if (!x509.parseCert(unescape(rootca.cert)) || !x509.cdp_uri) {
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
