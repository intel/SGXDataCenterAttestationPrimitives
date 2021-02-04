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

import Config from 'config';
import got from 'got';
import caw from 'caw';
import logger from '../utils/Logger.js';
import PccsError from '../utils/PccsError.js';
import PccsStatus from '../constants/pccs_status_code.js';

const HTTP_TIMEOUT = 60000; // 60 seconds
let HttpsAgent;
if (Config.has('proxy') && Config.get('proxy')) {
  // use proxy settings in config file
  HttpsAgent = {
    https: caw(Config.get('proxy'), { protocol: 'https' }),
  };
} else {
  // use system proxy
  HttpsAgent = {
    https: caw({ protocol: 'https' }),
  };
}

async function do_request(url, options) {
  try {
    logger.debug(url);
    logger.debug(JSON.stringify(options));

    // global opitons ( proxy, timeout, etc)
    options.timeout = HTTP_TIMEOUT;
    options.agent = HttpsAgent;

    let response = await got(url, options);
    logger.info('Request-ID is : ' + response.headers['request-id']);
    return response;
  } catch (err) {
    logger.debug(err);
    if (err.response && err.response.headers) {
      logger.info('Request-ID is : ' + err.response.headers['request-id']);
    }
    throw new PccsError(PccsStatus.PCCS_STATUS_PCS_ACCESS_FAILURE);
  }
}

export async function getCert(enc_ppid, cpusvn, pcesvn, pceid) {
  const options = {
    searchParams: {
      encrypted_ppid: enc_ppid,
      cpusvn: cpusvn,
      pcesvn: pcesvn,
      pceid: pceid,
    },
    method: 'GET',
    headers: { 'Ocp-Apim-Subscription-Key': Config.get('ApiKey') },
  };

  return do_request(Config.get('uri') + 'pckcert', options);
}

export async function getCerts(enc_ppid, pceid) {
  const options = {
    searchParams: {
      encrypted_ppid: enc_ppid,
      pceid: pceid,
    },
    method: 'GET',
    headers: { 'Ocp-Apim-Subscription-Key': Config.get('ApiKey') },
  };

  return do_request(Config.get('uri') + 'pckcerts', options);
}

export async function getCertsWithManifest(platform_manifest, pceid) {
  const options = {
    json: {
      platformManifest: platform_manifest,
      pceid: pceid,
    },
    method: 'POST',
    headers: { 'Ocp-Apim-Subscription-Key': Config.get('ApiKey') },
  };

  return do_request(Config.get('uri') + 'pckcerts', options);
}

export async function getPckCrl(ca) {
  const options = {
    searchParams: {
      ca: ca.toLowerCase(),
      encoding: 'der',
    },
    method: 'GET',
  };

  return do_request(Config.get('uri') + 'pckcrl', options);
}

export async function getTcb(fmspc) {
  const options = {
    searchParams: {
      fmspc: fmspc,
    },
    method: 'GET',
  };

  return do_request(Config.get('uri') + 'tcb', options);
}

export async function getQeIdentity() {
  const options = {
    searchParams: {},
    method: 'GET',
  };

  return do_request(Config.get('uri') + 'qe/identity', options);
}

export async function getQveIdentity() {
  const options = {
    searchParams: {},
    method: 'GET',
  };

  return do_request(Config.get('uri') + 'qve/identity', options);
}

export async function getFileFromUrl(uri) {
  logger.debug(uri);

  const options = {
    agent: HttpsAgent,
    timeout: HTTP_TIMEOUT,
  };

  try {
    return await got(uri, options).buffer();
  } catch (err) {
    throw err;
  }
}

export function getHeaderValue(headers, key) {
  return headers[key.toLowerCase()];
}
