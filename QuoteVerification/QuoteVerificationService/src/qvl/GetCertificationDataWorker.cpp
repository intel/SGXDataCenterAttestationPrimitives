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

#include "GetCertificationDataWorker.h"


namespace intel::sgx::dcap::qvlwrapper {
    void GetCertificationDataWorker::Run() {
        qvlStatus = sgxAttestationGetQECertificationDataSize(quote, quoteSize, &qeCertificationDataSize);
        if (qvlStatus != STATUS_OK) {
            SetError("sgxAttestationGetQECertificationDataSize failed");
            return;
        }

        qeCertificationData = new uint8_t[qeCertificationDataSize];

        qvlStatus = sgxAttestationGetQECertificationData(quote, quoteSize, qeCertificationDataSize,
                                                         qeCertificationData,
                                                         &qeCertificationDataType);

        if (qvlStatus != STATUS_OK) {
            SetError("sgxAttestationGetQECertificationData failed");
            return;
        }
    }

    void GetCertificationDataWorker::OnOK() {
        auto returnObj = Napi::Object::New(Env());
        returnObj.Set("type", qeCertificationDataType);
        returnObj.Set("data",Napi::Buffer<uint8_t>::Copy(Env(), qeCertificationData, qeCertificationDataSize));
        promise.Resolve(returnObj);

        delete qeCertificationData;
    }

    void GetCertificationDataWorker::OnError(const Napi::Error &e) {
        auto returnObj = Napi::Object::New(Env());
        returnObj.Set("status", (int) qvlStatus);
        returnObj.Set("error", e.Message());
        promise.Reject(returnObj);

        delete qeCertificationData;
    }
}
