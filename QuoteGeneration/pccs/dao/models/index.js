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
import * as fs from 'fs';
import Config from 'config';
import Sequelize from 'sequelize';
import logger from '../../utils/Logger.js';
import clshooked from 'cls-hooked';
import FmspcTcbs from './fmspc_tcbs.js';
import PckCert from './pck_cert.js';
import PckCertchain from './pck_certchain.js';
import PckCrl from './pck_crl.js';
import PcsCertificates from './pcs_certificates.js';
import PcsVersion from './pcs_version.js';
import PlatformTcbs from './platform_tcbs.js';
import PlatformsRegistered from './platforms_registered.js';
import Platforms from './platforms.js';
import EnclaveIdentities from './enclave_identities.js';
import CrlCache from './crl_cache.js';
import AppraisalPolicy from './appraisal_policy.js';
import mysqlPromise from 'mysql2/promise.js';

const pccs_namespace = clshooked.createNamespace('pccs-namespace');
Sequelize.useCLS(pccs_namespace);

// get config options for ssl
function getSSLConfig(sslConfig) {
  if (sslConfig && sslConfig.required && fs.existsSync(sslConfig.ca)) {
    return { ssl: { ca: fs.readFileSync(sslConfig.ca) } };
  }
  return null;
}

function initModels(sequelize) {
  FmspcTcbs.init(sequelize);
  PckCert.init(sequelize);
  PckCertchain.init(sequelize);
  PckCrl.init(sequelize);
  PcsCertificates.init(sequelize);
  PcsVersion.init(sequelize);
  PlatformTcbs.init(sequelize);
  PlatformsRegistered.init(sequelize);
  Platforms.init(sequelize);
  EnclaveIdentities.init(sequelize);
  CrlCache.init(sequelize);
  AppraisalPolicy.init(sequelize);
}

async function initializeDatabase() {
  let dbConfig = Config.get(Config.get('DB_CONFIG'));
  let dbOptions = { ...dbConfig.options };
  if (dbOptions.logging === true) {
    dbOptions.logging = (msg) => logger.info(msg);
  }
  
  const sslOptions = getSSLConfig(dbConfig.ssl);
  if (sslOptions) {
    dbOptions.dialectOptions = sslOptions;
  }

  const sequelize = new Sequelize(
    dbConfig.database,
    dbConfig.username,
    dbConfig.password,
    dbOptions
  );

  try {
    await sequelize.authenticate();
  } catch (err) {
    if (Config.get('DB_CONFIG') === 'mysql') {
      // Handle MySQL specific error
      await handleMySQLError(dbConfig, dbOptions, err);
    } else {
      logger.error(err);
      process.exit(1);
    }
  }

  return sequelize;
}

async function handleMySQLError(dbConfig, dbOptions, err) {
  logger.error('Failed to connect DB. Try to create it ...');
  try {
    const connOptions = {
      host: dbOptions.host,
      port: dbOptions.port,
      user: dbConfig.username,
      password: dbConfig.password,
      ...getSSLConfig(dbConfig.ssl)
    };
    const connection = await mysqlPromise.createConnection(connOptions);
    await connection.query(
      `CREATE DATABASE IF NOT EXISTS \`${dbConfig.database}\` CHARACTER SET utf8 COLLATE utf8_general_ci;`
    );
  } catch (err2) {
    logger.error(err2);
    process.exit(1);
  }
}

const sequelize = await initializeDatabase();
initModels(sequelize); // Initialize all models

export {
  Sequelize,
  sequelize,
  FmspcTcbs,
  PckCert,
  PckCertchain,
  PckCrl,
  PcsCertificates,
  PcsVersion,
  PlatformTcbs,
  PlatformsRegistered,
  Platforms,
  EnclaveIdentities,
  CrlCache,
  AppraisalPolicy,
};
