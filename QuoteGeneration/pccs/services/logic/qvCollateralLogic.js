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
import Constants from '../../constants/index.js';
import * as pcsCertificatesDao from '../../dao/pcsCertificatesDao.js';
import * as enclaveIdentityDao from '../../dao/enclaveIdentityDao.js';
import * as pckcrlDao from '../../dao/pckcrlDao.js';
import * as CommonCacheLogic from './commonCacheLogic.js';

async function fetchWithFallback(daoMethod, pcsMethod, ...args) {
  let result = await daoMethod(...args);
  if (result == null) {
    await pcsMethod(...args);
  }
}

export async function checkQuoteVerificationCollateral(update) {
  await fetchWithFallback(pckcrlDao.getPckCrl, CommonCacheLogic.getPckCrlFromPCS, Constants.CA_PROCESSOR);
  await fetchWithFallback(pckcrlDao.getPckCrl, CommonCacheLogic.getPckCrlFromPCS, Constants.CA_PLATFORM);

  const pcsVersion = global.PCS_VERSION;
  const identityTypes = [Constants.QE_IDENTITY_ID, Constants.QVE_IDENTITY_ID];
  let updateTypes = [];

  if (update === Constants.UPDATE_TYPE_STANDARD) {
      updateTypes = [Constants.UPDATE_TYPE_STANDARD];
  } else if (update === Constants.UPDATE_TYPE_EARLY) {
      updateTypes = [Constants.UPDATE_TYPE_EARLY];
  } else if (update === Constants.UPDATE_TYPE_ALL) {
      updateTypes = [Constants.UPDATE_TYPE_EARLY, Constants.UPDATE_TYPE_STANDARD];
  } else {
    throw new PccsError(PccsStatus.PCCS_STATUS_INVALID_REQ);
  }
  // Fetching for both versions 3 and 4 if PCS_VERSION is 4
  const versionsToFetch = pcsVersion === 4 ? [3, 4] : [pcsVersion];

  for (const id of identityTypes) {
    for (const version of versionsToFetch) {
      for (const updateType of updateTypes) {
        await fetchWithFallback(
          enclaveIdentityDao.getEnclaveIdentity, 
          CommonCacheLogic.getEnclaveIdentityFromPCS, 
          id, 
          version,
          updateType
        );
      }
    }
  }

  // Additional identity type to fetch if PCS_VERSION is 4
  if (pcsVersion === 4) {
    for (const updateType of updateTypes) {
      await fetchWithFallback(
        enclaveIdentityDao.getEnclaveIdentity, 
        CommonCacheLogic.getEnclaveIdentityFromPCS, 
        Constants.TDQE_IDENTITY_ID, 
        4,
        updateType
      );
    }
  }

  // Root CA crl
  let rootca = await pcsCertificatesDao.getCertificateById(
    Constants.PROCESSOR_ROOT_CERT_ID
  );
  if (rootca == null || rootca.crl == null) {
    await CommonCacheLogic.getRootCACrlFromPCS(rootca);
  }
}
