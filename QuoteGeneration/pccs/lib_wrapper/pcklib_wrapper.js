/**
 *
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
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

const ref = require("ref-napi");
const ffi = require('ffi-napi');
const Struct = require('ref-struct-napi');
const refArray = require('ref-array-napi');
const path = require('path');

const intPtr = ref.refType('int');
const StringArray = refArray('string');
const ByteArray = refArray('byte', 16);
const cpu_svn_t = Struct({
  'bytes': ByteArray 
});
const cpu_svn_ptr = ref.refType(cpu_svn_t);

exports.pck_cert_select = function(cpu_svn, pce_svn, pce_id, tcb_info, pem_certs, ncerts){
	let dllpath = 'PCKCertSelectionLib.dll';
	if (process.platform === "linux") {
		dllpath = path.join(__dirname , '../lib/libPCKCertSelection.so');
	}
    let pcklib = ffi.Library(dllpath,
        {'pck_cert_select': [ 'int', [ cpu_svn_ptr, 'uint16', 'uint16', 'string', StringArray, 'uint32', intPtr]]});
    var my_cpu_svn = new cpu_svn_t;
    var buf = Buffer.from(cpu_svn, 'hex');
    my_cpu_svn.bytes = new ByteArray;
    for (let i = 0; i < buf.length; i++)
        my_cpu_svn.bytes[i] = buf[i];

    var my_pce_svn = Buffer.from(pce_svn, 'hex').readInt16LE();
    var my_pce_id = Buffer.from(pce_id, 'hex').readInt16LE();
    var best_index_ptr = ref.alloc('int');
    let ret = pcklib.pck_cert_select(my_cpu_svn.ref(), my_pce_svn, my_pce_id, tcb_info, pem_certs, ncerts, best_index_ptr);
    if (ret == 0) {
        var best_index = best_index_ptr.deref();
        return best_index;
    }
    else {
        return -1;
    }
}
