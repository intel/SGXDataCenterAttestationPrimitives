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
use std::io::{self, BufReader, Read};
use std::fs::{self, File};
use std::slice;
use structopt::StructOpt;
use sgx_dcap_ql_rs;

#[derive(StructOpt)]
/// demostrate the usage of sgx_dcap_ql_rs Crate
enum Sample {
    /// write QE target_info that used for an enclave to generate report
    TargetInfo {
        /// The path to the file to write target_info
        #[structopt(parse(from_os_str), default_value = "target_info.dat")]
        target_info: std::path::PathBuf,
    },
    /// read app enclave report and cervert it to quote
    Quote {
        /// The path to the file to read app enclave report
        #[structopt(parse(from_os_str), default_value = "report.dat")]
        report: std::path::PathBuf,
    },
}

fn read_struct<T>(path: std::path::PathBuf) -> io::Result<T> {
    let struct_size = ::std::mem::size_of::<T>();
    let mut reader = BufReader::new(File::open(path).expect("Unable to open report file."));
    unsafe {
        let mut r = core::mem::MaybeUninit::<T>::uninit();
        let buffer = slice::from_raw_parts_mut(r.as_mut_ptr() as *mut u8, struct_size);
        reader.read_exact(buffer).expect("Unable to read report file.");
        Ok(r.assume_init())
    }
}

fn get_target_info(path: std::path::PathBuf) {
    let mut target_info: sgx_dcap_ql_rs::sgx_target_info_t = Default::default();
    let result = sgx_dcap_ql_rs::sgx_qe_get_target_info(&mut target_info);
    if result != sgx_dcap_ql_rs::quote3_error_t::SGX_QL_SUCCESS {
        println!("Failed to get the target_info.");
        return;
    }
    println!("Successfully get the target_info.");

    unsafe {
        fs::write(path,
            ::std::slice::from_raw_parts(
                &target_info as *const sgx_dcap_ql_rs::sgx_target_info_t as *const u8,
                ::std::mem::size_of::<sgx_dcap_ql_rs::sgx_target_info_t>()))
            .expect("Unable to write target_info file.");
    }
    println!("Successfully write the target_info.");
}

fn get_quote(path: std::path::PathBuf) {
    let sgx_report = read_struct::<sgx_dcap_ql_rs::sgx_report_t>(path)
        .expect("Unable to read report file.");
    println!("Successfully read the report.");
    match std::env::var("SGX_AESM_ADDR") {
        Ok(_) => (),
        _ => {
            println!("Need to call sgx_qe_get_target_info first in out-of-proc mode.");
            let mut target_info: sgx_dcap_ql_rs::sgx_target_info_t = Default::default();
            sgx_dcap_ql_rs::sgx_qe_get_target_info(&mut target_info);
        },
    }
    let (result, quote) = sgx_dcap_ql_rs::sgx_qe_get_quote(&sgx_report);
    if result != sgx_dcap_ql_rs::quote3_error_t::SGX_QL_SUCCESS {
        println!("Failed to get the quote. Error code: {:?}", result);
        return;
    }
    match quote {
        Some(q) => {
            println!("quote data: {:?}", q);
            println!("Successfully get the SGX Quote.");
            fs::write("quote.dat", q).expect("Unable to write quote file.");
        },
        None => {
            return;
        },
    }
}

fn main() {
    match Sample::from_args() {
        Sample::TargetInfo{target_info} => {
            get_target_info(target_info);
        },
        Sample::Quote{report} => {
            get_quote(report);
        },
    }
}
