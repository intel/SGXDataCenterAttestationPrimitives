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
import * as path from 'path';
import { fileURLToPath } from 'url';
import logger from '../utils/Logger.js';
import { load, DataType, open, close, createPointer, arrayConstructor, restorePointer } from 'ffi-rs';

////////////// Load library ////////////////////////////////
const __dirname = path.dirname(fileURLToPath(import.meta.url));
let libpath = 'PCKCertSelectionLib.dll';
if (process.platform === 'linux') {
  libpath = path.join(__dirname, '../lib/libPCKCertSelection.so');
}
open({
  library: 'libPCKCertSelection', // key
  path: libpath // path
})

export function pck_cert_select(
  cpu_svn,
  pce_svn,
  pce_id,
  tcb_info,
  pem_certs,
  ncerts
) {
  let my_pce_svn = Buffer.from(pce_svn, 'hex').readUInt16LE();
  let my_pce_id = Buffer.from(pce_id, 'hex').readUInt16LE();

  let cert_index = 0
  const best_index_ptr = createPointer({
    paramsType: [DataType.I32],
    paramsValue: [cert_index]
  })

  const ret = load({
    library: 'libPCKCertSelection', // path to the dynamic library file
    funcName: 'pck_cert_select', // the name of the function to call
    retType: DataType.I32, // the return value type
    paramsType: [DataType.U8Array, DataType.I32, DataType.I32, DataType.String, DataType.StringArray, DataType.I32, DataType.External], // the parameter types
    paramsValue: [Buffer.from(cpu_svn, 'hex'), my_pce_svn, my_pce_id, tcb_info, pem_certs, ncerts, best_index_ptr[0]] // the actual parameter values
  })

  if (ret == 0) {
      cert_index = restorePointer({
        retType: [DataType.I32],
        paramsValue: best_index_ptr
      })
      return cert_index;
  } else {
    logger.error('PCK selection library returned ' + ret);
    return -1;
  }
}

// Ensure the library is closed before the process exits
process.on('exit', () => {
  close('libPCKCertSelection');
});