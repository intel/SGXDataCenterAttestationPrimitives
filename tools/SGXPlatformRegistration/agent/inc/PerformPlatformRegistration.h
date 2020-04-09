/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
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
 * File: PerformPlatformRegistration.h
 *
 * Description: Class definition the agent uses to perform the 
 * PlatformManifest registration flows.  It will transport the platform 
 * manifest to the registration server using the network library.
 */
#ifndef __PERFORM_PLATFORM_REGISTRATION_H
#define __PERFORM_PLATFORM_REGISTRATION_H

#include "PerformBase.h"

class PerformPlatformRegistration : public PerformBase {
	public:
	PerformPlatformRegistration(MPNetwork *mpNetwork, MPUefi *mpUefi) :
    PerformBase(mpNetwork, mpUefi) {}
    private:
        virtual MpResult sendBinaryRequst(const uint8_t *request, const uint16_t &requestSize, uint8_t *response,
            uint16_t &responseSize, HttpStatusCode &responseCode, RegistrationErrorCode &errorCode);
		virtual MpResult useResponse(const uint8_t *response, const uint16_t &responseSize);
		virtual HttpStatusCode getSuccessHttpResponseCode();
};

#endif // #ifndef __PERFORM_PLATFORM_REGISTRATION_H
