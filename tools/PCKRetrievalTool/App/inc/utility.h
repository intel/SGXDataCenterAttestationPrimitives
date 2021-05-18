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
/** File: utility.h
 *
 * Description: Definitions of some utility functions
 *
 */

#ifndef _UTILITY_H_
#define _UTILITY_H_

#include <stdint.h>
#include <string>

typedef enum {
    UEFI_OPERATION_SUCCESS = 0,
    UEFI_OPERATION_UNEXPECTED_ERROR,
    UEFI_OPERATION_VARIABLE_NOT_AVAILABLE,
    UEFI_OPERATION_LIB_NOT_AVAILABLE,
    UEFI_OPERATION_FAIL
} uefi_status_t;

// for multi-package platform, get the platform manifet
// return value:
//  UEFI_OPERATION_SUCCESS: successfully get the platform manifest.
//  UEFI_OPERATION_VARIABLE_NOT_AVAILABLE: it means platform manifest is not avaible: it is not multi-package platform or platform manifest has been consumed.
//  UEFI_OPERATION_LIB_NOT_AVAILABLE: it means that the uefi shared library doesn't exist
//  UEFI_OPERATION_FAIL:  it is one add package request, now we don't support it. 
//  UEFI_OPERATION_UNEXPECTED_ERROR: error happens.
uefi_status_t get_platform_manifest(uint8_t ** buffer, uint16_t& out_buffer_size);

// for multi-package platform, set registration status 
// return value:
//  UEFI_OPERATION_SUCCESS: successfully set the platform's registration status.
//  UEFI_OPERATION_LIB_NOT_AVAILABLE: it means that the uefi shared library doesn't exist, maybe the registration agent package is not installed
//  UEFI_OPERATION_UNEXPECTED_ERROR: error happens.
uefi_status_t set_registration_status();

// generate ecdsa quote
// return value:
//  0: successfully generate the ecdsa quote
// -1: error happens.
int generate_quote(uint8_t **quote_buffer, uint32_t& quote_size);

bool is_valid_proxy_type(std::string& proxy_type);

bool is_valid_use_secure_cert(std::string& use_secure_cert);

#ifdef _MSC_VER
bool get_program_path(TCHAR *p_file_path, size_t buf_size);
#else                                       
bool get_program_path(char *p_file_path, size_t buf_size);
#endif
#endif
