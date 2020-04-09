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
 * File: RegistrationLogic.h
 *
 * Description: Parent class definition the agent uses to perform 
 * the registration flows.  It will implement transport registration 
 * data between the BIOS and the registration server using the UEFI 
 * and network libraries.
 */
#ifndef __PERFORM_BASE_H
#define __PERFORM_BASE_H

#include "MPUefi.h"
#include "MPNetwork.h"

#define REGISTRATION_RETRY_TIMES 5
 
#pragma pack(push, 1)
class PerformBase {
    public:
        PerformBase(MPNetwork *mpNetwork, MPUefi *mpUefi)
            : m_network(mpNetwork), m_uefi(mpUefi) {}
		virtual ~PerformBase() {};
		bool perform(const uint8_t *request, const uint16_t &requestSize, uint8_t retryTimes);
	protected: 
        MPNetwork *m_network;
        MPUefi *m_uefi;
    private:
        virtual MpResult sendBinaryRequst(const uint8_t *request, const uint16_t &requestSize, uint8_t *response, 
            uint16_t &responseSize, HttpStatusCode &statusCode, RegistrationErrorCode &errorCode) = 0;
		virtual MpResult useResponse(const uint8_t *response, const uint16_t &responseSize) = 0;
		virtual HttpStatusCode getSuccessHttpResponseCode() = 0;
};
#pragma pack(pop) 
#endif // #ifndef __PERFORM_BASE_H

