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
/** File: certification_provider.h
 *
 * Description: Header file of CertificationProvider class
 *
 */
#ifndef CERTIFICATIONPROVIDER_H_
#define CERTIFICATIONPROVIDER_H_
#pragma once

#include "network_wrapper.h"
#include "pccs_response_object.h"
#include "qcnl_config.h"
#include "sgx_default_qcnl_wrapper.h"
#include <string>

#ifdef _MSC_VER
#include <time.h>
#endif

using namespace std;

class CertificationProvider {
private:
protected:
    string base_url_;

public:
    CertificationProvider(const string &base_url);
    ~CertificationProvider();

    sgx_qcnl_error_t get_certification(http_header_map &header_map,
                                       const string &query_string,
                                       PccsResponseObject *pccs_resp_obj);
};

class CacheProvider {
private:
    bool is_cache_item_expired(time_t expiry) {
        time_t current_time = time(NULL);

        if (current_time == ((time_t)-1) || current_time >= expiry)
            return true;

        return false;
    }

protected:
    string base_url_;

public:
    CacheProvider(const string &base_url);
    ~CacheProvider();

    sgx_qcnl_error_t get_certification(const string &query_string,
                                       PccsResponseObject *pccs_resp_obj);
    sgx_qcnl_error_t set_certification(uint32_t default_expiry_seconds,
                                       const string &query_string,
                                       PccsResponseObject *pccs_resp_obj);
};

#endif // CERTIFICATIONPROVIDER_H_