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

//! This is the Intel SGX DCAP Quote Library for Rust.
#![allow(non_camel_case_types)]

pub use sgx_dcap_ql_sys::quote3_error_t;
pub use sgx_dcap_ql_sys::sgx_target_info_t;
pub use sgx_dcap_ql_sys::sgx_report_t;

/// Request rarget info of Quote enclave.
///
/// # Param
/// - **sgx_target_info_t**\
/// contain the QE's target information. This is used by the application's enclave to generate a REPORT verifiable by the QE.
/// # Return
/// - ***SGX_QL_SUCCESS***\
/// Successfully retrieved the target information.\
/// - ***SGX_QL_OUT_OF_EPC***\
/// There is not enough EPC memory to load one of the Architecture Enclaves needed to complete this operation.\
/// - ***SGX_QL_ERROR_OUT_OF_MEMORY***\
/// Heap memory allocation error in library or enclave.\
/// - ***SGX_QL_ERROR_UNEXPECTED***\
/// An unexpected internal error occurred.\
///
/// # Examples
/// ```
/// use sgx_dcap_ql_rs::*;
///
/// let mut target_info: sgx_target_info_t = Default::default();
/// let result = sgx_qe_get_target_info(&mut target_info);
/// ```
pub fn sgx_qe_get_target_info(
    qe_target_info: &mut sgx_target_info_t,
) -> quote3_error_t {
    unsafe {
        sgx_dcap_ql_sys::sgx_qe_get_target_info(qe_target_info)
    }
}

/// Request a Quote of the calling TD.
///
/// # Param
/// - **app_report**\
/// A set of data that the caller/TD wants to cryptographically bind to the Quote, typically a hash. May be all zeros for the Report data.
/// # Return
/// - ***SGX_QL_SUCCESS***\
/// Successfully generated the Quote.\
/// - ***SGX_QL_ERROR_INVALID_PARAMETER***\
/// The parameter is incorrect.\
/// - ***SGX_QL_ATT_KEY_NOT_INITIALIZED***\
/// The platform quoting infrastructure does not have available attestation key to generate quotes.\
/// - ***SGX_QL_ATT_KEY_CERT_DATA_INVALID***\
/// The data returned by the platform library's sgx_ql_get_quote_config() is invalid.\
/// - ***SGX_QL_OUT_OF_EPC***\
/// There is not enough EPC memory to load one of the Architecture Enclaves needed to complete this operation.\
/// - ***SGX_QL_ERROR_OUT_OF_MEMORY***\
/// Heap memory allocation error in library or enclave.\
/// - ***SGX_QL_ERROR_UNEXPECTED***\
/// An unexpected internal error occurred.\
///
/// # Examples
/// ```
/// use sgx_dcap_ql_rs::*;
///
/// let sgx_report:sgx_report_t = Default::default();
/// let (result, quote) = sgx_qe_get_quote(&sgx_report);
/// ```
pub fn sgx_qe_get_quote(
    app_report: &sgx_report_t,
) -> (quote3_error_t, Option<Vec<u8>>) {
    let mut buf_len = 0;
    unsafe {
        let result = sgx_dcap_ql_sys::sgx_qe_get_quote_size(&mut buf_len);
        match result {
            quote3_error_t::SGX_QL_SUCCESS => {
                let mut quote = vec![0u8; buf_len as usize];
                let result = sgx_dcap_ql_sys::sgx_qe_get_quote(app_report, buf_len, quote.as_mut_ptr());
                match result {
                    quote3_error_t::SGX_QL_SUCCESS => {
                        return (result, Some(quote))
                    },
                    _ => return (result, None),
                }
            },
            _ => return (result, None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sgx_qe_get_target_info() {
        let mut target_info: sgx_target_info_t = Default::default();
        let result = sgx_qe_get_target_info(&mut target_info);
        assert!(result == quote3_error_t::SGX_QL_INTERFACE_UNAVAILABLE
             || result == quote3_error_t::SGX_QL_SUCCESS);
    }

    #[test]
    fn test_sgx_qe_get_quote() {
        let sgx_report:sgx_report_t = Default::default();
        let (result, quote) = sgx_qe_get_quote(&sgx_report);
        match quote {
            q =>       println!("quote {:?}", q),
        }
        assert!(result == quote3_error_t::SGX_QL_INTERFACE_UNAVAILABLE
             || result == quote3_error_t::SGX_QL_INVALID_REPORT);
    }
}
