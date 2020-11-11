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
import Config from 'config';
import Constants from '../constants/index.js';
import X509 from '../x509/x509.js';
import * as pcsCertificatesDao from '../dao/pcsCertificatesDao.js';
import * as pcsClient from '../pcs_client/pcs_client.js';
import { sequelize } from '../dao/models/index.js';

export async function getRootCACrlFromPCS(rootca) {
  return await sequelize.transaction(async (t) => {
    if (rootca == null) {
      // Root Cert not cached
      const pck_server_res = await pcsClient.getQeIdentity();
      if (pck_server_res.statusCode == Constants.HTTP_SUCCESS) {
        // update certificates
        await pcsCertificatesDao.upsertEnclaveIdentityIssuerChain(
          pck_server_res.headers[Constants.SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN]
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

    let crl_bin = await pcsClient.getFileFromUrl(x509.cdp_uri);
    rootca.crl = Buffer.from(crl_bin, 'utf8').toString('hex');

    await pcsCertificatesDao.upsertPcsCertificates({
      id: rootca.id,
      cert: rootca.cert,
      crl: rootca.crl,
    });

    return rootca.crl;
  });
}

export async function getRootCaCrl() {
  let rootca = await pcsCertificatesDao.getCertificateById(
    Constants.PROCESSOR_ROOT_CERT_ID
  );

  if (rootca != null && rootca.crl != null) {
    return rootca.crl;
  }

  if (
    Config.get(Constants.CONFIG_OPTION_CACHE_FILL_MODE) ==
    Constants.CACHE_FILL_MODE_LAZY
  ) {
    let crl_hex = await this.getRootCACrlFromPCS(rootca);
    return crl_hex;
  } else {
    throw new PccsError(PccsStatus.PCCS_STATUS_NO_CACHE_DATA);
  }
}
