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
/** File: qcnl_config.h 
 *  
 * Description: Configurations for QCNL library
 *
 */
#ifndef QCNLCONFIG_H
#define QCNLCONFIG_H
#include <string>

using namespace std;

class QcnlConfig
{
private:
    // Default URL for PCCS server if configuration file doesn't exist
    string _server_url;
    // Use secure HTTPS certificate or not
    bool _use_secure_cert;
    // If defined in config file, will use this URL to get collateral
    string _collateral_service_url;
    // PCCS's API version
    string _collateral_version;
    // Max retry times
    uint32_t _retry_times;
    // Retry delay time in seconds
    uint32_t _retry_delay;

public:
    static QcnlConfig& Instance() {
        static QcnlConfig myInstance;
        return myInstance;
    }

    QcnlConfig(QcnlConfig const&) = delete;
    QcnlConfig(QcnlConfig&&) = delete;
    QcnlConfig& operator=(QcnlConfig const&) = delete;
    QcnlConfig& operator=(QcnlConfig &&) = delete;

    string getServerUrl()
    {
        return _server_url;
    }

    bool is_server_secure()
    {
        return _use_secure_cert;
    }

    string getCollateralServiceUrl()
    {
        return _collateral_service_url;
    }

    string getCollateralVersion()
    {
        return _collateral_version;
    }

    uint32_t getRetryTimes()
    {
        return _retry_times;
    }

    uint32_t getRetryDelay()
    {
        return _retry_delay;
    }

protected:
    QcnlConfig();
    ~QcnlConfig() {}
};

#endif //QCNLCONFIG_H