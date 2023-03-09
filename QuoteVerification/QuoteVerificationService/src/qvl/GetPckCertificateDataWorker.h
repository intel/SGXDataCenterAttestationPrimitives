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

#ifndef QUOTEVERIFICATIONLIBRARYWRAPPER_GetPckCertificateDataWORKER_H
#define QUOTEVERIFICATIONLIBRARYWRAPPER_GetPckCertificateDataWORKER_H

#include <napi.h>
#include "BaseWorker.h"
#include <SgxEcdsaAttestation/AttestationParsers.h>
#include <utility> // std::move

namespace intel::sgx::dcap::qvlwrapper {

    class GetPckCertificateDataWorker : public BaseWorker {
    public:
        GetPckCertificateDataWorker(Napi::Env &env, Napi::Promise::Deferred &promise, const std::string& requestId,
                             std::string pemCertificate)
                : BaseWorker(env, promise, requestId), pemCertificate(std::move(pemCertificate)) {}

        ~GetPckCertificateDataWorker() override = default;

        void Run() override;

        void OnOK() override;

        void OnError(const Napi::Error &e) override;

    private:
        const std::string pemCertificate; // input
        std::vector<uint8_t> fmspc; // output
        dcap::parser::x509::SgxType sgxType; // output
        bool dynamicPlatform; // output
        bool cachedKeys; // output
        bool smtEnabled; // output
        std::vector<uint8_t> cpusvn; // output
        std::uint32_t pcesvn; // output
    };

}
#endif //QUOTEVERIFICATIONLIBRARYWRAPPER_GetPckCertificateDataWORKER_H
