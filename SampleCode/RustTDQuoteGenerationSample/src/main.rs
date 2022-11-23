/*
 * Copyright (C) 2011-2022 Intel Corporation. All rights reserved.
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

use tdx_attest_rs;
use rand::Rng;
use std::fs;

fn main() {
    let mut rng = rand::thread_rng();
    let report_data = tdx_attest_rs::tdx_report_data_t{
        d: [rng.gen::<u8>(); 64usize],
    };
    println!("TDX report data: {:?}", report_data.d);

    let mut tdx_report = tdx_attest_rs::tdx_report_t{
        d: [0; 1024usize],
    };
    let result = tdx_attest_rs::tdx_att_get_report(Some(&report_data), &mut tdx_report);
    if result != tdx_attest_rs::tdx_attest_error_t::TDX_ATTEST_SUCCESS {
        println!("Failed to get the report.");
        return;
    }
    println!("TDX report: {:?}", tdx_report.d);

    let mut selected_att_key_id = tdx_attest_rs::tdx_uuid_t{
        d: [0; 16usize],
    };
    let (result, quote) = tdx_attest_rs::tdx_att_get_quote(Some(&report_data), None, Some(&mut selected_att_key_id), 0);
    if result != tdx_attest_rs::tdx_attest_error_t::TDX_ATTEST_SUCCESS {
        println!("Failed to get the quote.");
        return;
    }
    match quote {
        Some(q) => {
            println!("ATT key id: {:?}", selected_att_key_id);
            println!("TDX quote data: {:?}", q);
            println!("Successfully get the TD Quote.");
            fs::write("quote.dat", q).expect("Unable to write quote file.");
        },
        None => {
            println!("Failed to get the quote.");
            return;
        },
    }
    return;
}
