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
/**
 * File: qcnl_config.cpp 
 *  
 * Description: Read configuration data
 *
 */

#include <Windows.h>
#include <tchar.h>
#include <stdlib.h>
#include <string>
#include "qcnl_config.h"

using namespace std;

#define MAX_URL_LENGTH  2083
#define REG_KEY_SGX_QCNL                _T("SOFTWARE\\Intel\\SGX\\QCNL")
#define REG_VALUE_QCNL_PCCS_URL         _T("PCCS_URL")
#define REG_VALUE_QCNL_USE_SECURE_CERT  _T("USE_SECURE_CERT")
#define REG_VALUE_QCNL_COLLATERAL_SERVICE _T("COLLATERAL_SERVICE")
#define REG_VALUE_QCNL_PCCS_VERSION     _T("PCCS_API_VERSION")
#define REG_VALUE_QCNL_RETRY_TIMES      _T("RETRY_TIMES")
#define REG_VALUE_QCNL_RETRY_DELAY      _T("RETRY_DELAY")

QcnlConfig::QcnlConfig():_server_url("https://localhost:8081/sgx/certification/v3/"),
        _use_secure_cert(true),
        _collateral_service_url(_server_url),
        _collateral_version("3.0"),
        _retry_times(0),
        _retry_delay(0)
{
    // read registry
    // Read configuration data from registry
    // Open the Registry Key
    HKEY key = NULL;
    LSTATUS status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, REG_KEY_SGX_QCNL, 0, KEY_READ, &key);
    if (ERROR_SUCCESS != status) {
        return;
    }

    DWORD type, count;
    TCHAR url[MAX_URL_LENGTH] = { 0 };

    // Get PCCS URL
    count = MAX_URL_LENGTH * sizeof(TCHAR);
    status = RegQueryValueEx(key, REG_VALUE_QCNL_PCCS_URL, NULL, &type, (LPBYTE)url, &count);
    if (ERROR_SUCCESS == status && type == REG_SZ) {
        size_t input_len = _tcsnlen(url, MAX_URL_LENGTH);
        size_t output_len = 0;
        char url_multi[MAX_URL_LENGTH];

        if (wcstombs_s(&output_len, url_multi, MAX_URL_LENGTH, url, input_len) != 0) {
            // Use default value
        }
        else {
            _server_url = url_multi;
        }
    }

    // Get Collateral Service URL
    memset(url, 0, sizeof(url));
    status = RegQueryValueEx(key, REG_VALUE_QCNL_COLLATERAL_SERVICE, NULL, &type, (LPBYTE)url, &count);
    if (ERROR_SUCCESS == status && type == REG_SZ) {
        size_t input_len = _tcsnlen(url, MAX_URL_LENGTH);
        size_t output_len = 0;
        char collateral_service_url_multi[MAX_URL_LENGTH];

        if (wcstombs_s(&output_len, collateral_service_url_multi, MAX_URL_LENGTH, url, input_len) != 0) {
            // Use default value
        }
        else {
            _collateral_service_url = collateral_service_url_multi;
        }
    }
    else {
        // If collateral service url is not defined, use the default service url
        _collateral_service_url = _server_url;
    }

    // Get PCCS Version
    const DWORD vlen = 20;
    TCHAR collateral_version[vlen] = { 0 };
    count = vlen * sizeof(TCHAR);
    status = RegQueryValueEx(key, REG_VALUE_QCNL_PCCS_VERSION, NULL, &type, (LPBYTE)collateral_version, &count);
    if (ERROR_SUCCESS == status && type == REG_SZ) {
        size_t input_len = _tcsnlen(collateral_version, vlen);
        size_t output_len = 0;
        char collateral_version_multi[20];

        if (wcstombs_s(&output_len, collateral_version_multi, vlen, collateral_version, input_len) != 0) {
            // Use default value
        }
        else {
            _collateral_version = collateral_version_multi;
        }
        
    }

    count = sizeof(DWORD);
    DWORD dwSecureCert = 0;
    status = RegQueryValueEx(key, REG_VALUE_QCNL_USE_SECURE_CERT, NULL, &type, (LPBYTE)&dwSecureCert, &count);
    if (ERROR_SUCCESS == status && type == REG_DWORD) {
        _use_secure_cert = (dwSecureCert != 0);
    }

    DWORD dwRetryTimes = 0;
    status = RegQueryValueEx(key, REG_VALUE_QCNL_RETRY_TIMES, NULL, &type, (LPBYTE)&dwRetryTimes, &count);
    if (ERROR_SUCCESS == status && type == REG_DWORD) {
        _retry_times = (uint32_t)dwRetryTimes;
    }

    DWORD dwRetryDelay = 0;
    status = RegQueryValueEx(key, REG_VALUE_QCNL_RETRY_DELAY, NULL, &type, (LPBYTE)&dwRetryDelay, &count);
    if (ERROR_SUCCESS == status && type == REG_DWORD) {
        _retry_delay = (uint32_t)dwRetryDelay;
    }

    RegCloseKey(key);
}
