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
import PccsError from '../utils/PccsError.js';
import PccsStatus from '../constants/pccs_status_code.js';
import Ajv from 'ajv';
import { APPRAISAL_POLICY_REG_SCHEMA } from './pccs_schemas.js';
import * as appraisalPolicyDao from '../dao/appraisalPolicyDao.js';
import { sequelize } from '../dao/models/index.js';
import logger from '../utils/Logger.js';

const ajv = new Ajv();

function normalizeRegData(regPolicyJson) {
  // normalize the registration data
  regPolicyJson.fmspc = regPolicyJson.fmspc.toUpperCase();
}

export async function getDefaultAppraisalPolicies(fmspc) {
  return appraisalPolicyDao.getDefaultAppraisalPolicies(fmspc);
}

export async function putAppraisalPolicy(regPolicyJson) {
  //check parameters
  let valid = ajv.validate(APPRAISAL_POLICY_REG_SCHEMA, regPolicyJson);
  if (!valid) {
    logger.error("Failed to validate the appraisal policy file.")
    throw new PccsError(PccsStatus.PCCS_STATUS_INVALID_REQ);
  }

  // normalize registration data
  normalizeRegData(regPolicyJson);

  const { createHash } = await import('node:crypto');
  const id = createHash('sha384').update(regPolicyJson.policy, 'utf8').digest('hex');
  regPolicyJson.id = id

  // get policy type
  let payload = JSON.parse(Buffer.from(regPolicyJson.policy.split(".")[1], "base64url"));
  regPolicyJson.type = getPolicyTypeByClassId(payload);

  return await sequelize.transaction(async (t) => {
    await appraisalPolicyDao.upsertAppraisalPolicy(regPolicyJson);
    return id;
  });
}

const CLASS_ID_TO_TYPE_MAP = {
  "3123ec35-8d38-4ea5-87a5-d6c48b567570": 0, // SGX
  "9eec018b-7481-4b1c-8e1a-9f7c0c8c777f": 1, // TDX 1.0
  "f708b97f-0fb2-4e6b-8b03-8a5bcd1221d3": 2  // TDX 1.5
};

const tdqe_class_id = "3769258c-75e6-4bc7-8d72-d2b0e224cad2";

function getPolicyTypeByClassId(payload) {
  if (!payload || !payload.policy_payload) {
    throw new PccsError(PccsStatus.PCCS_STATUS_INVALID_REQ);
  }

  let policyPayload;
  try {
    policyPayload = JSON.parse(payload.policy_payload);
  } catch (e) {
    logger.error("Failed to parse appraisal policy payload.")
    throw new PccsError(PccsStatus.PCCS_STATUS_INVALID_REQ);
  }

  if (!policyPayload.policy_array) {
    logger.error("Policy array not found.")
    throw new PccsError(PccsStatus.PCCS_STATUS_INVALID_REQ);
  }

  for (const policy of policyPayload.policy_array) {
    if (!policy.environment || !policy.environment.class_id) {
      logger.error("Invalid policy data.")
      throw new PccsError(PccsStatus.PCCS_STATUS_INVALID_REQ);
    }

    const classId = policy.environment.class_id.toLowerCase();

    if (CLASS_ID_TO_TYPE_MAP.hasOwnProperty(classId)) {
      return CLASS_ID_TO_TYPE_MAP[classId];
    }
    else if (classId != tdqe_class_id) {
      logger.error("Unknown policy class_id.");
      throw new PccsError(PccsStatus.PCCS_STATUS_INVALID_REQ);    
    }
  }

  logger.error("Failed to get a valid policy type.");
  throw new PccsError(PccsStatus.PCCS_STATUS_INVALID_REQ);
}
