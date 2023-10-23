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

//! This is the Intel TDX attestation library for Rust.
#![allow(non_camel_case_types)]

use std::mem;
use std::option::Option;
pub use tdx_attest_sys::tdx_attest_error_t;
pub use tdx_attest_sys::tdx_report_data_t;
pub use tdx_attest_sys::tdx_report_t;
pub use tdx_attest_sys::tdx_rtmr_event_t;
pub use tdx_attest_sys::tdx_uuid_t;

/// Request a Quote of the calling TD.
///
/// # Param
/// - **tdx_report_data**\
/// A set of data that the caller/TD wants to cryptographically bind to the Quote, typically a hash. May be all zeros for the Report data.
/// - **att_key_id_list**\
/// List (array) of the attestation key IDs supported by the Quote verifier.
/// - **att_key_id**\
/// The selected attestation key ID when the function returns.
/// - **flags**\
/// Reserved, must be zero.
///
/// # Return
/// - ***TDX_ATTEST_SUCCESS***\
/// Successfully generated the Quote.\
/// - ***TDX_ATTEST_ERROR_UNSUPPORTED_ATT_KEY_ID***\
/// The platform Quoting infrastructure does not support any of the keys.\
/// - ***TDX_ATT_ERROR_INVALID_PARAMETER***\
/// The parameter is incorrect.\
/// - ***TDX_ATTEST_ERROR_DEVICE_FAILURE***\
/// Failed to acess tdx attest device.\
/// - ***TDX_ATTEST_ERROR_VSOCK_FAILURE***\
/// vsock related failure.\
/// - ***TDX_ATTEST_ERROR_OUT_OF_MEMORY***\
/// Heap memory allocation error in library or enclave.\
/// - ***TDX_ATT_ERROR_UNEXPECTED***\
/// An unexpected internal error occurred.\
///
/// # Examples
/// ```
/// use tdx_attest_rs::*;
///
/// let tdx_report_data = tdx_report_data_t{
///    d: [0; 64usize],
/// };
/// let att_key_id_list = [tdx_uuid_t{
///     d: [0; 16usize],
/// }; 2usize];
/// let list_size = 1024;
/// let mut att_key_id = tdx_uuid_t{
///     d: [0; 16usize],
/// };
/// let result = tdx_att_get_quote(Some(&tdx_report_data), Some(&att_key_id_list), Some(&mut att_key_id), 0);
/// ```
pub fn tdx_att_get_quote(
    tdx_report_data: Option<&tdx_report_data_t>,
    att_key_id_list: Option<&[tdx_uuid_t]>,
    att_key_id: Option<&mut tdx_uuid_t>,
    flags: u32,
) -> (tdx_attest_error_t, Option<Vec<u8>>) {
    let p_tdx_report_data = match tdx_report_data {
        Some(p) => p as *const tdx_report_data_t,
        None => std::ptr::null_mut(),
    };
    let (p_att_key_id_list, att_key_id_list_size) = match att_key_id_list {
        Some(p) => (p.as_ptr() as *const tdx_uuid_t, p.len() as u32),
        None => (std::ptr::null(), 0u32),
    };
    let p_att_key_id = match att_key_id {
        Some(p) => p as *mut tdx_uuid_t,
        None => std::ptr::null_mut(),
    };
    let mut buf = std::ptr::null_mut();
    let mut buf_len = 0;
    unsafe {
        let result = tdx_attest_sys::tdx_att_get_quote(
            p_tdx_report_data,
            p_att_key_id_list,
            att_key_id_list_size,
            p_att_key_id,
            &mut buf,
            &mut buf_len,
            flags,
        );
        match result {
            tdx_attest_error_t::TDX_ATTEST_SUCCESS => {
                assert!(!buf.is_null());
                assert!(buf_len > 0);
                let quote = std::slice::from_raw_parts(buf, buf_len as usize).to_vec();
                tdx_attest_sys::tdx_att_free_quote(buf);
                return (result, Some(quote));
            }
            _ => return (result, None),
        }
    }
}

/// Request a TDX Report of the calling TD.
///
/// # Param
/// - **tdx_report_data**\
/// A set of data that the caller/TD wants to cryptographically bind to the Quote, typically a hash. May be all zeros for the Report data.
/// - **tdx_report**\
/// the generated TDX Report.
///
/// # Return
/// - ***TDX_ATTEST_SUCCESS***\
/// Successfully generate report.\
/// - ***TDX_ATTEST_ERROR_INVALID_PARAMETER***\
/// The parameter is incorrect.
/// - ***TDX_ATTEST_ERROR_DEVICE_FAILURE***\
/// Failed to acess tdx attest device.\
/// - ***TDX_ATTEST_ERROR_REPORT_FAILURE***\
/// Failed to get the TD Report.\
/// - ***TDX_ATT_ERROR_UNEXPECTED***\
/// An unexpected internal error occurred.\
///
/// # Examples
/// ```
/// use tdx_attest_rs::*;
///
/// let tdx_report_data = tdx_report_data_t{
///    d: [0; 64usize],
/// };
/// let mut tdx_report =tdx_report_t{
///     d: [0; 1024usize],
/// };
/// let result = tdx_att_get_report(Some(&tdx_report_data), &mut tdx_report);
/// ```
pub fn tdx_att_get_report(
    tdx_report_data: Option<&tdx_report_data_t>,
    tdx_report: &mut tdx_report_t,
) -> tdx_attest_error_t {
    let p_tdx_report_data = match tdx_report_data {
        Some(p) => p as *const tdx_report_data_t,
        None => std::ptr::null_mut(),
    };
    unsafe { tdx_attest_sys::tdx_att_get_report(p_tdx_report_data, tdx_report) }
}

/// Extend one of the TDX runtime measurement registers (RTMRs).
///
/// # Param
/// - **rtmr_event**\
/// A set of data that contains the index of the RTMR to extend, the data with which to extend it and a description of the data.
///
/// # Return
/// - ***TDX_ATTEST_SUCCESS***\
/// Successfully extended the RTMR.\
/// - ***TDX_ATTEST_ERROR_INVALID_PARAMETER***\
/// The parameter is incorrect.
/// - ***TDX_ATTEST_ERROR_DEVICE_FAILURE***\
/// Failed to acess tdx attest device.\
/// - ***TDX_ATTEST_ERROR_INVALID_RTMR_INDEX***\
/// Only supported RTMR index is 2 and 3.\
/// - ***TDX_ATTEST_ERROR_EXTEND_FAILURE***\
/// Failed to extend data.\
/// - ***TDX_ATTEST_ERROR_NOT_SUPPORTED***\
/// rtmr_event.event_data_size != 0.\
/// - ***TDX_ATT_ERROR_UNEXPECTED***\
/// An unexpected internal error occurred.\
///
/// # Examples
/// ```
/// use tdx_attest_rs::*;
///
/// let rtmr_event = [0u8; 68usize];
/// let result = tdx_att_extend(&rtmr_event);
/// ```

pub fn tdx_att_extend(rtmr_event: &[u8]) -> tdx_attest_error_t {
    if rtmr_event.len() < mem::size_of::<tdx_rtmr_event_t>() {
        return tdx_attest_error_t::TDX_ATTEST_ERROR_INVALID_PARAMETER;
    }
    unsafe {
        let s: tdx_rtmr_event_t = std::ptr::read(rtmr_event.as_ptr() as *const _);
        if rtmr_event.len() - mem::size_of::<tdx_rtmr_event_t>() != s.event_data_size as usize {
            return tdx_attest_error_t::TDX_ATTEST_ERROR_INVALID_PARAMETER;
        }
        tdx_attest_sys::tdx_att_extend(rtmr_event.as_ptr() as *const tdx_rtmr_event_t)
    }
}

/// Retrieve the list of attestation key IDs supported by the platform.
///
/// # Param
///
/// # Return
/// - ***TDX_ATTEST_SUCCESS***\
/// Successfully populated the att_key_id_list.\
/// - ***TDX_ATT_ERROR_UNEXPECTED***\
/// An unexpected internal error occurred.\
///
/// # Examples
/// ```
/// use tdx_attest_rs::*;
/// let (result, att_key_id_list) = tdx_att_get_supported_att_key_ids();
/// ```
pub fn tdx_att_get_supported_att_key_ids() -> (tdx_attest_error_t, Option<Vec<tdx_uuid_t>>) {
    let mut list_count = 0;
    unsafe {
        let result = tdx_attest_sys::tdx_att_get_supported_att_key_ids(
            std::ptr::null_mut() as *mut tdx_uuid_t,
            &mut list_count,
        );
        match result {
            tdx_attest_error_t::TDX_ATTEST_SUCCESS => {
                let mut att_key_id_list = vec![tdx_uuid_t { d: [0; 16usize] }; list_count as usize];
                let result = tdx_attest_sys::tdx_att_get_supported_att_key_ids(
                    att_key_id_list.as_mut_ptr(),
                    &mut list_count,
                );
                match result {
                    tdx_attest_error_t::TDX_ATTEST_SUCCESS => {
                        return (result, Some(att_key_id_list))
                    }
                    _ => return (result, None),
                }
            }
            _ => return (result, None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tdx_att_get_report() {
        let tdx_report_data = tdx_report_data_t { d: [0; 64usize] };
        let mut tdx_report = tdx_report_t { d: [0; 1024usize] };
        let result = tdx_att_get_report(Some(&tdx_report_data), &mut tdx_report);
        assert_eq!(result, tdx_attest_error_t::TDX_ATTEST_ERROR_DEVICE_FAILURE);
    }

    #[test]
    fn test_tdx_att_get_quote() {
        let tdx_report_data = tdx_report_data_t { d: [0; 64usize] };
        let mut att_key_id = tdx_uuid_t { d: [0; 16usize] };
        let (result, quote) =
            tdx_att_get_quote(Some(&tdx_report_data), None, Some(&mut att_key_id), 0);
        println!("att_key_id {:?}", att_key_id.d);
        match quote {
            q => println!("quote {:?}", q),
        }
        assert_eq!(result, tdx_attest_error_t::TDX_ATTEST_ERROR_DEVICE_FAILURE);
    }

    #[test]
    fn test_tdx_att_extend() {
        let mut rtmr_event = [0u8; mem::size_of::<tdx_rtmr_event_t>()];
        rtmr_event[0] = 1;
        let result = tdx_att_extend(&rtmr_event);
        assert_eq!(result, tdx_attest_error_t::TDX_ATTEST_ERROR_DEVICE_FAILURE);
    }

    #[test]
    fn test_tdx_att_get_supported_att_key_ids() {
        let (result, att_key_ids) = tdx_att_get_supported_att_key_ids();
        let ids = att_key_ids.unwrap();
        println!("att_key_id size {:?}", ids.len());
        for id in ids {
            println!("att_key_id {:?}", id.d);
        }
        assert_eq!(result, tdx_attest_error_t::TDX_ATTEST_SUCCESS);
    }
}
