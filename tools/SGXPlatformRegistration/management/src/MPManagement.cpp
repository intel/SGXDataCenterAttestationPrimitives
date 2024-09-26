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
 * File: MPManagement.cpp
 *   
 * Description: Implemenation of the MPManagement class.  These are the 
 * methods that will read and write to the UEFI variables to provide 
 * the ability to configure, collect data and collect status of the 
 * SGX MP platform. 
 */
#include <string.h>
#include "MPUefi.h"
#include "management_logger.h"
#include "MPManagement.h"
#include "sgx_capable.h"

extern LogLevel glog_level;

MPManagement::MPManagement(const string uefi_path) {
	m_mpuefi = new MPUefi(uefi_path, glog_level);
}

MpResult MPManagement::getPackageInfoKeyBlobs(uint8_t *buffer, uint16_t &buffer_size) {
    MpRegistrationStatus status;
    MpResult res = MP_UNEXPECTED_ERROR;
    
    do {
        if (NULL == buffer ) {
            res = MP_INVALID_PARAMETER;
            break;
        }
        
        res = m_mpuefi->getRegistrationStatus(status);
        if (MP_SUCCESS != res) {
            break;
        }

        if (MP_TASK_IN_PROGRESS != status.packageInfoStatus) {
            management_log_message(MP_REG_LOG_LEVEL_ERROR, "getPackageInfoKeyBlobs: PacakgeInfo task completed.\n");
            res = MP_NO_PENDING_DATA;
            break;
        }

        uint8_t keyBlobs[MAX_DATA_SIZE];
        memset(keyBlobs, 0, sizeof(keyBlobs));
        uint16_t size = sizeof(keyBlobs);
        res = m_mpuefi->getKeyBlobs((uint8_t*)keyBlobs, size);
        if (MP_SUCCESS != res) {
            if (MP_NO_PENDING_DATA == res) {
                res = MP_UEFI_INTERNAL_ERROR;
            }
            break;
        }

        if (buffer_size < size) {
            buffer_size = size;
            res = MP_USER_INSUFFICIENT_MEM;
            break;
        }
        buffer_size = size;

        memcpy(buffer, keyBlobs, size);
        status.packageInfoStatus = MP_TASK_COMPLETED;
        res = m_mpuefi->setRegistrationStatus(status);
        if (MP_SUCCESS != res) {
            break;
        }

        res = MP_SUCCESS;
    } while(0);
    
    return res;
}

MpResult MPManagement::getRegistrationErrorCode(RegistrationErrorCode &error_code) {
    MpRegistrationStatus status;
    MpResult res = MP_UNEXPECTED_ERROR;
    
    do {
        res = m_mpuefi->getRegistrationStatus(status);
        if (MP_SUCCESS != res) {
            break;
        }

        error_code = status.errorCode;
        res = MP_SUCCESS;
    } while(0);
    
    return res;
}

MpResult MPManagement::getRegistrationStatus(MpTaskStatus &status) {
    MpRegistrationStatus regStatus;
    MpResult res = MP_UNEXPECTED_ERROR;
    
    do {
        res = m_mpuefi->getRegistrationStatus(regStatus);
        if (MP_SUCCESS != res) {
            break;
        }

        if(regStatus.registrationStatus) {
            status = MP_TASK_COMPLETED;
        }
        else {
            status = MP_TASK_IN_PROGRESS;
        }

        res = MP_SUCCESS;
    } while(0);
    
    return res;
}

MpResult MPManagement::getRequestData(uint8_t *buffer, uint16_t &buffer_size, MpRequestType expectedRequestType) {
    MpRegistrationStatus status;
    MpRequestType type;
    MpResult res = MP_UNEXPECTED_ERROR;
    string expectedArtifactTypeName = (expectedRequestType == MpRequestType::MP_REQ_REGISTRATION)? "PlatformManifest" : "ADD_REQUEST";
    string functionName = (expectedRequestType == MpRequestType::MP_REQ_REGISTRATION) ? "getPlatformManifest" : "getAddPackageRequest";

    do {
        if (NULL == buffer ) {
            res = MP_INVALID_PARAMETER;
            break;
        }

        res = m_mpuefi->getRegistrationStatus(status);
        if (MP_SUCCESS != res) {
            management_log_message(MP_REG_LOG_LEVEL_ERROR, "%s: Platform doesn't support SGX MP Registration.\n", functionName.c_str());
            break;
        }

        if (MP_TASK_IN_PROGRESS != status.registrationStatus) {
            management_log_message(MP_REG_LOG_LEVEL_ERROR, "%s: Registration completed, no pending %s.\n", functionName.c_str(), expectedArtifactTypeName.c_str());
            res = MP_NO_PENDING_DATA;
            break;
        }
                
        res = m_mpuefi->getRequestType(type);
        if (MP_SUCCESS != res) {
            break;
        }

        if (expectedRequestType != type) {
            management_log_message(MP_REG_LOG_LEVEL_ERROR, "%s: The pending request is not %s.\n", functionName.c_str(), expectedArtifactTypeName.c_str());
            res = MP_NO_PENDING_DATA;
            break;
        }

        uint8_t requestData[MAX_REQUEST_SIZE];
        uint16_t size = sizeof(requestData);
        memset(&requestData, 0, sizeof(requestData));
        res = m_mpuefi->getRequest((uint8_t*)&requestData, size);
        if (MP_SUCCESS != res) {
            if (MP_NO_PENDING_DATA == res) {
                res = MP_UEFI_INTERNAL_ERROR;
            }
            break;
        }
        if (buffer_size < size) {
            buffer_size = size;
            res = MP_USER_INSUFFICIENT_MEM;
            break;
        }

        memcpy(buffer, &requestData, size);
        buffer_size = size;
        status.registrationStatus = MP_TASK_COMPLETED;
        res = m_mpuefi->setRegistrationStatus(status);
        if (MP_SUCCESS != res) {
            break;
        }
        res = MP_SUCCESS;
    } while (0);
    return res;
}

MpResult MPManagement::getPlatformManifest(uint8_t *buffer, uint16_t &buffer_size) {
    return getRequestData(buffer, buffer_size, MP_REQ_REGISTRATION);
}

MpResult MPManagement::getAddPackageRequest(uint8_t *buffer, uint16_t &buffer_size) {
    return getRequestData(buffer, buffer_size, MP_REQ_ADD_PACKAGE);
}

MpResult MPManagement::setMembershipCertificates(const uint8_t *membershipCertificates, uint16_t membershipCertificatesSize) {
    MpResult res = m_mpuefi->setServerResponse(membershipCertificates, membershipCertificatesSize);
    if (MP_SUCCESS == res) {
        management_log_message(MP_REG_LOG_LEVEL_INFO, "Server response have been successfully written to platform.\n");
    }
    return res;
}


MpResult MPManagement::getSgxStatus(MpSgxStatus &status) {
    MpResult res = MP_UNEXPECTED_ERROR;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_device_status_t sgxStatus;

    do {
        ret = sgx_cap_get_status(&sgxStatus);
        if (SGX_SUCCESS != ret) {
            management_log_message(MP_REG_LOG_LEVEL_ERROR, "getSgxStatus: sgx_cap_get_status failed, error: %d\n", res);
            break;
        }

        status = (MpSgxStatus)sgxStatus;
        res = MP_SUCCESS;
    } while (0);

    return res;
}

MpResult MPManagement::getRegistrationServerInfo(uint16_t &flags, string &outUrl, uint8_t *serverId, uint16_t &serverIdSize) {
    MpResult res = m_mpuefi->getRegistrationServerInfo(flags, outUrl, serverId, serverIdSize); 
    if (MP_SUCCESS != res) {
        management_log_message(MP_REG_LOG_LEVEL_ERROR, "getRegistrationServerInfo: Reading the registration server info failed, error: %d\n", res);
        return MP_UNEXPECTED_ERROR;
    }

    return MP_SUCCESS;
}

MpResult MPManagement::setRegistrationServerInfo(const uint16_t &flags, const string &url, const uint8_t *serverId, const uint16_t &serverIdSize) {
    MpResult res = MP_UNEXPECTED_ERROR;

    do {
        res = m_mpuefi->setRegistrationServerInfo(flags, url, serverId, serverIdSize);
        if (MP_SUCCESS != res) {
            break;
        }

        res = MP_SUCCESS;
    } while (0);

    return res;
}

MPManagement::~MPManagement() {
    if (NULL != m_mpuefi) {
        delete m_mpuefi;
        m_mpuefi = NULL;
    }
}
