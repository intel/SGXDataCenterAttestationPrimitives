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
 * File: certification_provider.cpp
 *
 * Description: CertificationProvider class implementation
 *
 */
#include "certification_provider.h"
#include "local_cache.h"
#include "qcnl_util.h"
#include <vector>

// calculate sha256 hash
string sha256_hash(const void *data, size_t data_size) {
    string hash = sha256(data, data_size);
    if (hash.empty()) {
        qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] sha256 error. \n");
    }
    return hash;
}

////////////////////// CertificationProvider class ///////////////////////////////////////
CertificationProvider::CertificationProvider(const string &base_url) {
    this->base_url_ = base_url;
}

CertificationProvider::~CertificationProvider() {
}

sgx_qcnl_error_t CertificationProvider::get_certification(http_header_map &header_map,
                                                          const string &query_string,
                                                          PccsResponseObject *pccs_resp_obj) {

    if (this->base_url_.empty()) {
        return SGX_QCNL_INVALID_CONFIG;
    }

    sgx_qcnl_error_t ret = SGX_QCNL_UNEXPECTED_ERROR;
    char *resp_msg = NULL;
    uint32_t resp_size = 0;
    char *resp_header = NULL;
    uint32_t header_size = 0;
    string url = this->base_url_ + query_string;

    ret = qcnl_https_request(url.c_str(), header_map, NULL, 0, NULL, 0, &resp_msg, resp_size, &resp_header, header_size);
    if (ret != SGX_QCNL_SUCCESS) {
        return ret;
    } else if (!resp_msg || resp_size == 0) {
        return SGX_QCNL_UNEXPECTED_ERROR;
    }

    pccs_resp_obj->set_raw_header(resp_header, header_size).set_raw_body(resp_msg, resp_size);

    if (resp_msg) {
        free(resp_msg);
        resp_msg = NULL;
    }
    if (resp_header) {
        free(resp_header);
        resp_header = NULL;
    }

    return ret;
}

////////////////////// CacheProvider class ///////////////////////////////////////
CacheProvider::CacheProvider(const string &base_url) {
    this->base_url_ = base_url;
}

CacheProvider::~CacheProvider() {
}

sgx_qcnl_error_t CacheProvider::get_certification(const string &query_string,
                                                  PccsResponseObject *pccs_resp_obj) {
    string url = this->base_url_ + query_string;
    string cache_key = sha256_hash(url.data(), url.size());
    sgx_qcnl_error_t ret = SGX_QCNL_UNEXPECTED_ERROR;

    qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Fetching from the local cache for: '%s' \n", url.c_str());

    vector<uint8_t> value;
    if (!LocalCache::Instance().get_data(cache_key, value)) {
        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Cache missed. \n");
        return SGX_QCNL_CACHE_MISSING;
    }

    do {
        if (value.size() < sizeof(CacheItemHeader) ||
            value.size() > UINT32_MAX) {
            break;
        }

        // Check expiry
        CacheItemHeader cache_header = {0};
        if (memcpy_s(&cache_header, sizeof(CacheItemHeader), value.data(), sizeof(CacheItemHeader)) != 0)
            break;
        if (is_cache_item_expired(cache_header.expiry)) {
            qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Cache expired. \n");
            ret = SGX_QCNL_CACHE_EXPIRED;
            break;
        }

        // Parse header
        uint8_t *p_data = value.data() + sizeof(CacheItemHeader);
        uint32_t header_size = *reinterpret_cast<uint32_t const *>(p_data);
        if (header_size > value.size() - sizeof(CacheItemHeader) - 2 * sizeof(uint32_t))
            break;
        p_data += sizeof(uint32_t);
        pccs_resp_obj->set_raw_header((const char *)p_data, header_size);

        // Parse body
        p_data += header_size;
        uint32_t body_size = *reinterpret_cast<uint32_t const *>(p_data);
        if (body_size != value.size() - sizeof(CacheItemHeader) - 2 * sizeof(uint32_t) - header_size)
            break;
        p_data += sizeof(uint32_t);
        pccs_resp_obj->set_raw_body((const char *)p_data, body_size);

        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Fetched from the local cache successfully. \n");

        ret = SGX_QCNL_SUCCESS;
    } while (false);

    if (ret != SGX_QCNL_SUCCESS) {
        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Cache item expired or corrupted. \n");
        LocalCache::Instance().remove_data(cache_key);
    }

    return ret;
}

sgx_qcnl_error_t CacheProvider::set_certification(uint32_t default_expiry_seconds,
                                                  const string &query_string,
                                                  PccsResponseObject *pccs_resp_obj) {
    // Cache-Control:max-age has higher priority over config file
    uint32_t cache_max_age = pccs_resp_obj->get_cache_max_age();
    uint32_t expiry_seconds = (cache_max_age > 0) ? cache_max_age : default_expiry_seconds;

    if (expiry_seconds > 0) {
        string url = this->base_url_ + query_string;
        string cache_key = sha256_hash(url.data(), url.size());
        if (cache_key.empty()) {
            return SGX_QCNL_UNEXPECTED_ERROR;
        }

        vector<uint8_t> value;

        time_t current_time = time(NULL);
        CacheItemHeader cache_header = {0};
        cache_header.expiry = current_time + expiry_seconds;

        // Append cache header
        uint8_t *p_data = reinterpret_cast<uint8_t *>(&cache_header);
        value.insert(value.end(), p_data, p_data + sizeof(cache_header));

        // Append repsonse header and body
        string header = pccs_resp_obj->get_raw_header();
        size_t header_size = header.size();
        string body = pccs_resp_obj->get_raw_body();
        size_t body_size = body.size();
        value.insert(value.end(), (uint8_t *)&header_size, (uint8_t *)&header_size + 4);
        value.insert(value.end(), header.data(), header.data() + header_size);
        value.insert(value.end(), (uint8_t *)&body_size, (uint8_t *)&body_size + 4);
        value.insert(value.end(), body.data(), body.data() + body_size);

        LocalCache::Instance().set_data(cache_key, value);

        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Caching collateral '%s' for %d seconds. \n", url.c_str(), expiry_seconds);
    }

    return SGX_QCNL_SUCCESS;
}