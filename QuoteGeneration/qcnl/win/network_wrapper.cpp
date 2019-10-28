/*
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
/**
 * File: network_wrapper.cpp 
 *  
 * Description: Network access logic
 *
 */
#include <Windows.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <winhttp.h>
#include "sgx_default_qcnl_wrapper.h"
#include "network_wrapper.h"

#define DEFAULT_CONNECT_TIME_OUT_VALUE  (5*1000)
#define HTTP_DOWNLOAD_MAX_SIZE          (100*1024*1024) //http response msg should be not more than 100M
#define MAX_URL                         2083

extern bool g_use_secure_cert;
extern bool g_isWin81OrLater;

static sgx_qcnl_error_t windows_last_error_to_qcnl_error(void)
{
    DWORD ec = GetLastError();
    switch (ec) {
    case ERROR_WINHTTP_CONNECTION_ERROR:
    case ERROR_WINHTTP_CANNOT_CONNECT:
        return SGX_QCNL_NETWORK_COULDNT_CONNECT;
    case ERROR_WINHTTP_TIMEOUT:
        return SGX_QCNL_NETWORK_OPERATION_TIMEDOUT;//All network related error
    case ERROR_WINHTTP_AUTO_PROXY_SERVICE_ERROR:
    case ERROR_WINHTTP_AUTODETECTION_FAILED:
    case ERROR_WINHTTP_BAD_AUTO_PROXY_SCRIPT:
        return SGX_QCNL_NETWORK_PROXY_FAIL;
    case ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED:
    case ERROR_WINHTTP_CLIENT_CERT_NO_ACCESS_PRIVATE_KEY:
    case ERROR_WINHTTP_CLIENT_CERT_NO_PRIVATE_KEY:
    case ERROR_WINHTTP_HEADER_ALREADY_EXISTS:
    case ERROR_WINHTTP_LOGIN_FAILURE:
    case ERROR_WINHTTP_NAME_NOT_RESOLVED:
        return SGX_QCNL_NETWORK_ERROR;
    case ERROR_WINHTTP_INVALID_URL:
        return SGX_QCNL_INVALID_PARAMETER;
    default:
        return SGX_QCNL_UNEXPECTED_ERROR;
    }
}

sgx_qcnl_error_t qcnl_https_get(const char* url, 
                                      char **resp_msg, 
                                      uint32_t& resp_size, 
                                      char **resp_header, 
                                      uint32_t& header_size) 
{
    sgx_qcnl_error_t ret = SGX_QCNL_UNEXPECTED_ERROR;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;

    do {
        //WinHTTP API explicitly use UNICODE so that we should use WCHAR instead of TCHAR
        WCHAR wurl[MAX_URL];
        WCHAR whostname[MAX_URL];
        size_t count;
        count = 0;
        if (mbstowcs_s(&count, wurl, url, strlen(url)) != 0) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }
        URL_COMPONENTS urlComp;
        ZeroMemory(&urlComp, sizeof(urlComp));
        urlComp.dwStructSize = sizeof(urlComp);
        urlComp.lpszHostName = whostname;//we will only crack hostname, urlpath 
        urlComp.dwHostNameLength = MAX_PATH;//copy hostname to a buffer to get 0-terminated string
        urlComp.dwUrlPathLength = (DWORD)-1;

        // Crack the URL
        if (!WinHttpCrackUrl(wurl, (DWORD)wcsnlen_s(wurl, MAX_URL), 0, &urlComp))
        {
            ret = SGX_QCNL_INVALID_PARAMETER;
            break;
        }

        DWORD dwAutoProxy = WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY;
        if (!g_isWin81OrLater)
            dwAutoProxy = WINHTTP_ACCESS_TYPE_DEFAULT_PROXY;
        // Use WinHttpOpen to obtain a session handle.
        hSession = WinHttpOpen(L"SGX default qcnl",
            dwAutoProxy,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession)
        {
            ret = windows_last_error_to_qcnl_error();
            break;
        }

        // Specify an HTTP server.
        hConnect = WinHttpConnect(hSession, urlComp.lpszHostName,
            static_cast<INTERNET_PORT>(urlComp.nPort), 0);
        if (!hConnect)
        {
            ret = windows_last_error_to_qcnl_error();
            break;
        }

        // Create an HTTP request handle.
        hRequest = WinHttpOpenRequest(hConnect, L"GET", urlComp.lpszUrlPath,
            L"HTTP/1.0", WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);
        if (!hRequest)
        {
            ret = windows_last_error_to_qcnl_error();
            break;
        }

        //set default connection timeout value
        DWORD value = DEFAULT_CONNECT_TIME_OUT_VALUE;
        if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_CONNECT_TIMEOUT, &value, sizeof(value))) {
            ret = windows_last_error_to_qcnl_error();
            break;
        }

        if (!g_use_secure_cert)
        {
            DWORD dwFlags =
                SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
            if (!WinHttpSetOption(
                hRequest,
                WINHTTP_OPTION_SECURITY_FLAGS,
                &dwFlags,
                sizeof(dwFlags)))
            {
                ret = windows_last_error_to_qcnl_error();
                break;
            }
        }

        // Send a request.
        if (!WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0,
            0, 0))
        {
            ret = windows_last_error_to_qcnl_error();
            break;
        }

        // End the request.
        if (!WinHttpReceiveResponse(hRequest, NULL))
        {
            ret = windows_last_error_to_qcnl_error();
            break;
        }

        LPVOID lpOutBuffer = NULL;
        DWORD dwStatus = 0;
        DWORD dwSize = sizeof(dwStatus);
        // Query response code
        if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            NULL, &dwStatus, &dwSize, 0)) //query for server response error code
        {
            ret = windows_last_error_to_qcnl_error();
            break;
        }

        if (dwStatus == HTTP_STATUS_OK) // 200
        {
            // Get response header
            (void)WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                WINHTTP_HEADER_NAME_BY_INDEX, NULL,
                &dwSize, WINHTTP_NO_HEADER_INDEX);
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            {
                ret = SGX_QCNL_UNEXPECTED_ERROR;
                break;
            }

            // Allocate memory for the buffer.
            lpOutBuffer = new WCHAR[dwSize / sizeof(WCHAR)];

            // Now, use WinHttpQueryHeaders to retrieve the header.
            if (!WinHttpQueryHeaders(hRequest,
                WINHTTP_QUERY_RAW_HEADERS_CRLF,
                WINHTTP_HEADER_NAME_BY_INDEX,
                lpOutBuffer, &dwSize,
                WINHTTP_NO_HEADER_INDEX))
            {
                delete[] lpOutBuffer;
                ret = windows_last_error_to_qcnl_error();
                break;
            }
            header_size = WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)lpOutBuffer, -1, NULL, 0, NULL, NULL);
            if (header_size == 0)
            {
                delete[] lpOutBuffer;
                ret = windows_last_error_to_qcnl_error();
                break;
            }
            *resp_header = static_cast<char *>(malloc(header_size + 1));
            if (WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)lpOutBuffer, -1, *resp_header, header_size, NULL, NULL) == 0)
            {
                delete[] lpOutBuffer;
                ret = windows_last_error_to_qcnl_error();
                break;
            }
            (*resp_header)[header_size] = 0;
            header_size++;
            delete[] lpOutBuffer;
        }
        else if (dwStatus == HTTP_STATUS_NOT_FOUND) // 404
        {
            ret = SGX_QCNL_ERROR_STATUS_NOT_FOUND;
            break;
        }
        else {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }

        resp_size = 0;
        // Keep checking for data until there is nothing left.
        do
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
            {
                ret = windows_last_error_to_qcnl_error();
                break;
            }
            if (dwSize == 0)
            {
                ret = SGX_QCNL_SUCCESS;
                break;
            }

            if (*resp_msg == NULL) {
                *resp_msg = static_cast<char *>(malloc(dwSize));
                if (*resp_msg == NULL) {
                    ret = SGX_QCNL_OUT_OF_MEMORY;
                    break;
                }
            }
            else {
                if (UINT32_MAX - resp_size < dwSize || resp_size + dwSize > HTTP_DOWNLOAD_MAX_SIZE) {
                    free(*resp_msg);
                    *resp_msg = NULL;
                    ret = SGX_QCNL_OUT_OF_MEMORY;
                    break;
                }
                char *p_buffer_expanded = static_cast<char *>(malloc(resp_size + dwSize));
                if (p_buffer_expanded == NULL) {
                    ret = SGX_QCNL_OUT_OF_MEMORY;
                    break;
                }

                (void)memcpy_s(p_buffer_expanded, resp_size + dwSize, *resp_msg, resp_size);
                free(*resp_msg);
                *resp_msg = p_buffer_expanded;
            }

            memset(*resp_msg + resp_size, 0, dwSize);
            DWORD download_size = 0;
            //get response message from server
            if (!WinHttpReadData(hRequest, *resp_msg + resp_size, dwSize, &download_size)) {
                ret = windows_last_error_to_qcnl_error();
                free(*resp_msg);
                *resp_msg = NULL;
                break;
            }
            else {
                resp_size += download_size;
            }
        } while (TRUE);
    }
    while (0);

    // Close any open handles.
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    // free allocated buffers in case this function retuns error
    if (ret != SGX_QCNL_SUCCESS) 
    {
        if (*resp_msg)
        {
            free(*resp_msg);
            *resp_msg = NULL;
            resp_size = 0;
        }
        if (*resp_header)
        {
            free(*resp_header);
            *resp_header = NULL;
            header_size = 0;
        }
    }

    return ret;
}
