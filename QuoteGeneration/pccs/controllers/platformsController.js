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

import { platformsRegService, platformsService } from '../services/index.js';
import PccsError from '../utils/PccsError.js';
import PccsStatus from '../constants/pccs_status_code.js';
import Constants from '../constants/index.js';
import logger from '../utils/Logger.js';

export async function postPlatforms(req, res, next) {
  try {
    // validate request parameters
    let update = req.query.update;
    if (update) {
      update = update.toUpperCase();
      if (![Constants.UPDATE_TYPE_STANDARD, Constants.UPDATE_TYPE_EARLY, Constants.UPDATE_TYPE_ALL].includes(update)) {
        logger.error("Invalid update type : " + update);
        throw new PccsError(PccsStatus.PCCS_STATUS_INVALID_REQ);
      }
    }
    else {
      update = Constants.UPDATE_TYPE_STANDARD;
    }

    // call registration service
    await platformsRegService.registerPlatforms(req.body, update);

    // send response
    res
      .status(PccsStatus.PCCS_STATUS_SUCCESS[0])
      .send(PccsStatus.PCCS_STATUS_SUCCESS[1]);
  } catch (err) {
    next(err);
  }
}

export async function getPlatforms(req, res, next) {
  const HTTP_HEADER_PLATFORM_COUNT = 'platform-count';

  try {
    let platformsJson;
    if (!req.query.source || req.query.source == 'reg') {
      // call registration service to get registered platforms
      platformsJson = await platformsRegService.getRegisteredPlatforms();
      await platformsRegService.deleteRegisteredPlatforms(
        Constants.PLATF_REG_NEW
      );
    } else if (req.query.source == 'reg_na') {
      // call registration service to get registered 'Not available' platforms
      platformsJson = await platformsRegService.getRegisteredNaPlatforms();
      await platformsRegService.deleteRegisteredPlatforms(
        Constants.PLATF_REG_NOT_AVAILABLE
      );
    } else {
      let fmspc = req.query.source;
      if (fmspc.length < 2 || fmspc[0] != '[' || fmspc[fmspc.length - 1] != ']') {
        logger.error("Invalid fmspc : " + fmspc);
        throw new PccsError(PccsStatus.PCCS_STATUS_INVALID_REQ);
      }
      fmspc = fmspc
        .substring(1, fmspc.length - 1)
        .trim()
        .toUpperCase();
      let fmspc_arr;
      if (fmspc.length > 0) fmspc_arr = fmspc.split(',');
      else fmspc_arr = [];
      platformsJson = await platformsService.getCachedPlatforms(fmspc_arr);
    }

    // send response
    res
      .status(PccsStatus.PCCS_STATUS_SUCCESS[0])
      .header(HTTP_HEADER_PLATFORM_COUNT, platformsJson.length)
      .send(platformsJson);
  } catch (err) {
    next(err);
  }
}
