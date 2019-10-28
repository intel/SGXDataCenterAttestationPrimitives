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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <map>
#include <fstream>
#include "sgx_default_qcnl_wrapper.h"
#include "se_memcpy.h"

extern bool g_use_secure_cert;

typedef struct _network_malloc_info_t{
    char *base;
    uint32_t size;
}network_malloc_info_t;

static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *stream)
{
    network_malloc_info_t* s=reinterpret_cast<network_malloc_info_t *>(stream);
    uint32_t start=0;
    if(s->base==NULL){
        s->base = reinterpret_cast<char *>(malloc(size*nmemb));
        s->size = static_cast<uint32_t>(size*nmemb);
        if(s->base==NULL)return 0;
    }else{
        uint32_t newsize = s->size+static_cast<uint32_t>(size*nmemb);
        char *p=reinterpret_cast<char *>(realloc(s->base, newsize));
        if(p == NULL){
            return 0;
        }
        start = s->size;
        s->base = p;
        s->size = newsize;
    }
    if (memcpy_s(s->base +start, s->size-start, ptr, size*nmemb) != 0) {
        return 0;
    }
    return size*nmemb;
}

/**
* This method converts CURL error codes to QCNL error codes
*
* @param curl_error Curl library error codes
*
* @return Collateral Network Library Error Codes
*/
static sgx_qcnl_error_t curl_error_to_qcnl_error(CURLcode curl_error)
{
    switch(curl_error){
        case CURLE_OK:
            return SGX_QCNL_SUCCESS;
        case CURLE_COULDNT_RESOLVE_PROXY:
            return SGX_QCNL_NETWORK_PROXY_FAIL;
        case CURLE_COULDNT_RESOLVE_HOST:
            return SGX_QCNL_NETWORK_HOST_FAIL;
        case CURLE_COULDNT_CONNECT:
            return SGX_QCNL_NETWORK_COULDNT_CONNECT;
        case CURLE_WRITE_ERROR:
            return SGX_QCNL_NETWORK_WRITE_ERROR;
        case CURLE_OPERATION_TIMEDOUT:
            return SGX_QCNL_NETWORK_OPERATION_TIMEDOUT;
        case CURLE_SSL_CONNECT_ERROR:
            return SGX_QCNL_NETWORK_HTTPS_ERROR;
        case CURLE_UNKNOWN_OPTION:
            return SGX_QCNL_NETWORK_UNKNOWN_OPTION;
        case CURLE_PEER_FAILED_VERIFICATION:
            return SGX_QCNL_NETWORK_HTTPS_ERROR;
        default:
            return SGX_QCNL_NETWORK_ERROR;
    }
}

/**
* This method calls curl library to perform https GET request and returns response body and header
*
* @param url HTTPS Get URL 
* @param resp_msg Output buffer of response body
* @param resp_size Size of response body
* @param resp_header Output buffer of response header
* @param header_size Size of response header
*
* @return SGX_QCNL_SUCCESS Call https get successfully. Other return codes indicate an error occured.
*/
sgx_qcnl_error_t qcnl_https_get(const char* url, 
                                      char **resp_msg, 
                                      uint32_t& resp_size, 
                                      char **resp_header, 
                                      uint32_t& header_size) 
{
    CURL *curl = NULL;
    CURLcode curl_ret;
    sgx_qcnl_error_t ret = SGX_QCNL_NETWORK_ERROR;
    network_malloc_info_t res_header = {0,0};
    network_malloc_info_t res_body = {0,0};

    do {
        curl = curl_easy_init();
        if (!curl)
            break;

        if (curl_easy_setopt(curl, CURLOPT_URL, url) != CURLE_OK)
            break;;

        if (!g_use_secure_cert) {
            // if not set this option, the below error code will be returned for self signed cert
            // CURLE_SSL_CACERT (60) Peer certificate cannot be authenticated with known CA certificates.
            if (curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L) != CURLE_OK)
                break;
            // if not set this option, the below error code will be returned for self signed cert
            // // CURLE_PEER_FAILED_VERIFICATION (51) The remote server's SSL certificate or SSH md5 fingerprint was deemed not OK.
            if (curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L) != CURLE_OK)
                break;
        }

        // Set write callback functions
        if(curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback)!=CURLE_OK)
            break;
        if(curl_easy_setopt(curl, CURLOPT_WRITEDATA, reinterpret_cast<void *>(&res_body))!=CURLE_OK)
            break;

        // Set header callback functions
        if(curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, write_callback)!=CURLE_OK)
            break;
        if(curl_easy_setopt(curl, CURLOPT_HEADERDATA, reinterpret_cast<void *>(&res_header))!=CURLE_OK)
            break;

        // Perform request
        if((curl_ret = curl_easy_perform(curl))!=CURLE_OK) {
            ret = curl_error_to_qcnl_error(curl_ret);
            break;
        }
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code == 404) {
            ret = SGX_QCNL_ERROR_STATUS_NOT_FOUND;
            break;
        }
        else if (http_code != 200) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }

        *resp_msg = res_body.base;
        resp_size = res_body.size;
        *resp_header = res_header.base;
        header_size = res_header.size;

        ret = SGX_QCNL_SUCCESS;

    } while(0);

    if (curl) {
        curl_easy_cleanup(curl);
    }
    if (ret != SGX_QCNL_SUCCESS) {
        if(res_body.base){
            free(res_body.base);
        }
        if(res_header.base){
            free(res_header.base);
        }
    }

    return ret;
}
