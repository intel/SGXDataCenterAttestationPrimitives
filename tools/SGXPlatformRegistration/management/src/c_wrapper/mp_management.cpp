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
 * File: mp_managment.cpp
 *   
 * Description: Implemenation of the C funcitons that wrapp the class methods 
 * defined in the MPManagement class.
 */
#include "MPManagement.h"
#include "mp_management.h"
#include <string>

using std::string;

MPManagement* g_mpManagement = NULL;

void mp_management_init(const char* path)
{
    if (!path || g_mpManagement) {
        return;
    }
    g_mpManagement = new MPManagement(string(path));
}

MpResult mp_management_get_package_info_key_blobs(uint8_t *buffer, uint16_t *size) {
    if (!size) {
        return MP_INVALID_PARAMETER;
    }
    return g_mpManagement->getPackageInfoKeyBlobs(buffer, *size);
}

MpResult mp_management_get_platform_manifest(uint8_t *buffer, uint16_t *size) {
    if (!buffer || !size) {
        return MP_INVALID_PARAMETER;
    }
    return g_mpManagement->getPlatformManifest(buffer, *size);
}

MpResult mp_management_get_add_package(uint8_t *buffer, uint16_t *size) {
    if (!buffer || !size) {
        return MP_INVALID_PARAMETER;
    }
    return g_mpManagement->getAddPackageRequest(buffer, *size);
}

MpResult mp_management_set_membership_certificates(const uint8_t *membershipCertificates, uint16_t membershipCertificatesSize) {
    if (!membershipCertificates) {
        return MP_INVALID_PARAMETER;
    }
    return g_mpManagement->setMembershipCertificates(membershipCertificates, membershipCertificatesSize);
}

MpResult mp_management_get_registration_error_code(RegistrationErrorCode *error_code) {
    if (!error_code) {
        return MP_INVALID_PARAMETER;
    }
    return g_mpManagement->getRegistrationErrorCode(*error_code);
}

MpResult mp_management_get_registration_status(MpTaskStatus *status) {
    if (!status) {
        return MP_INVALID_PARAMETER;
    }
    return g_mpManagement->getRegistrationStatus(*status);
}

MpResult mp_management_get_sgx_status(MpSgxStatus *status) {
    if (!status) {
        return MP_INVALID_PARAMETER;
    }
    return g_mpManagement->getSgxStatus(*status);
}


MpResult mp_management_set_registration_server_info(uint16_t flags, string url, const uint8_t *serverId, uint16_t serverIdSize) {
    if (!serverId) {
        return MP_INVALID_PARAMETER;
    }
    return g_mpManagement->setRegistrationServerInfo(flags, url, serverId, serverIdSize);
}

MpResult mp_management_get_registration_server_info(uint16_t *flags, char *outUrlBuffer, uint16_t *outUrlBufferSize, uint8_t *serverId, uint16_t *serverIdSize) {
    if (!flags || !outUrlBuffer || !outUrlBufferSize || !serverId || !serverIdSize) {
        return MP_INVALID_PARAMETER;
    }
    std::string outUrl;
    auto retval = g_mpManagement->getRegistrationServerInfo(*flags, outUrl, serverId, *serverIdSize);
    if(retval == MP_SUCCESS) {

        uint16_t stringOutputBufferSize = *outUrlBufferSize;
        *outUrlBufferSize = static_cast<uint16_t>(outUrl.size() + 1);  // Set required # of bytes (or bytes written)

        if (stringOutputBufferSize < *outUrlBufferSize) {
            return MP_USER_INSUFFICIENT_MEM;
        }

        outUrl.copy(outUrlBuffer, *outUrlBufferSize);
        outUrlBuffer[outUrl.size()] = '\0';
    }
    return retval;
}

void mp_management_terminate() 
{
    if (g_mpManagement) {
        delete g_mpManagement;
        g_mpManagement = NULL;
    }
}
