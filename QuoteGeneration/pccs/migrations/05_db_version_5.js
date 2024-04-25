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

async function up(sequelize) {
  await sequelize.transaction(async (t) => {
    logger.info('DB Migration (Ver.4 -> 5) -- Start');

    // update pcs_version table
    logger.debug('DB Migration -- Update pcs_version table');
    let sql = 'UPDATE pcs_version SET db_version=5,api_version=4';
    await sequelize.query(sql);

    // update fmspc_tcbs table
    // this is done by 1.Create new table 2.Copy data 3.Drop old table 4.Rename new into old
    logger.debug('DB Migration -- update fmspc_tcbs');
    sql =
      'CREATE TABLE IF NOT EXISTS fmspc_tcbs_temp (fmspc VARCHAR(255) NOT NULL, type INTEGER NOT NULL, version INTEGER NOT NULL, ' +
      ' update_type VARCHAR(255) NOT NULL, tcbinfo BLOB, root_cert_id INTEGER, signing_cert_id INTEGER, ' +
      ' created_time DATETIME NOT NULL, updated_time DATETIME NOT NULL, PRIMARY KEY(fmspc, type, version, update_type));';
    await sequelize.query(sql);

    sql =
      "INSERT INTO fmspc_tcbs_temp (fmspc, type, version, update_type, tcbinfo, root_cert_id, signing_cert_id, created_time, updated_time) " +
      " SELECT fmspc, type, version, 'STANDARD' as update_type, tcbinfo, root_cert_id, signing_cert_id, created_time, updated_time " +
      " FROM fmspc_tcbs ";
    await sequelize.query(sql);

    sql = 'DROP TABLE fmspc_tcbs';
    await sequelize.query(sql);

    sql = 'ALTER TABLE fmspc_tcbs_temp RENAME TO fmspc_tcbs';
    await sequelize.query(sql);

    // update enclave_identities table
    // this is done by 1.Create new table 2.Copy data 3.Drop old table 4.Rename new into old
    logger.debug('DB Migration -- update enclave_identities');
    sql =
      'CREATE TABLE IF NOT EXISTS enclave_identities_temp (id INTEGER NOT NULL, version INTEGER NOT NULL, update_type VARCHAR(255) NOT NULL, ' +
      ' identity BLOB, root_cert_id INTEGER, signing_cert_id INTEGER, created_time DATETIME NOT NULL, updated_time DATETIME NOT NULL, PRIMARY KEY(id, version, update_type));';
    await sequelize.query(sql);

    sql =
      "INSERT INTO enclave_identities_temp (id, version, update_type, identity, root_cert_id, signing_cert_id, created_time, updated_time) " +
      " SELECT id, version, 'STANDARD' as update_type, identity, root_cert_id, signing_cert_id, created_time, updated_time " +
      " FROM enclave_identities ";
    await sequelize.query(sql);

    sql = 'DROP TABLE enclave_identities';
    await sequelize.query(sql);

    sql = 'ALTER TABLE enclave_identities_temp RENAME TO enclave_identities';
    await sequelize.query(sql);

    logger.info('DB Migration -- Done.');
  });
}

export default { up };
