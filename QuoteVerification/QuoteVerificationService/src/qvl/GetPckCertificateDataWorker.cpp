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

#include "GetPckCertificateDataWorker.h"
#include <SgxEcdsaAttestation/AttestationParsers.h>

namespace intel::sgx::dcap::qvlwrapper {
    using namespace intel::sgx::dcap::parser;

    void GetPckCertificateDataWorker::Run() {
        try {
            const auto certificate = x509::PckCertificate::parse(pemCertificate);
            fmspc = certificate.getFmspc();
            pcesvn = certificate.getTcb().getPceSvn();
            cpusvn = certificate.getTcb().getCpuSvn();

            sgxType = certificate.getSgxType();
            if (sgxType == parser::x509::Scalable || sgxType == parser::x509::ScalableWithIntegrity) {
                const auto platformCertificate = x509::PlatformPckCertificate(certificate);
                const auto &configuration = platformCertificate.getConfiguration();
                cachedKeys = configuration.isCachedKeys();
                dynamicPlatform = configuration.isDynamicPlatform();
                smtEnabled = configuration.isSmtEnabled();
            }
        }
        catch (std::exception& e) {
            std::string msg = "Error getting data from PCK certificate: ";
            msg.append(e.what());
            SetError(msg);
            return;
        }
    }

    void GetPckCertificateDataWorker::OnOK() {
        auto returnObj = Napi::Object::New(Env());
        auto buffer = Napi::Buffer<uint8_t>::Copy(Env(), fmspc.data(), fmspc.size());
        returnObj.Set("fmspc", buffer);
        buffer = Napi::Buffer<uint8_t>::Copy(Env(), cpusvn.data(), cpusvn.size());
        returnObj.Set("cpusvn", buffer);
        returnObj.Set("pcesvn", pcesvn);
        switch (sgxType) {
            case x509::Standard:
                returnObj.Set("sgxType", "Standard");
                break;
            case x509::Scalable:
                returnObj.Set("sgxType", "Scalable");
                returnObj.Set("dynamicPlatform", dynamicPlatform);
                returnObj.Set("cachedKeys", cachedKeys);
                returnObj.Set("smtEnabled", smtEnabled);
                break;
            case x509::ScalableWithIntegrity:
                returnObj.Set("sgxType", "ScalableWithIntegrity");
                returnObj.Set("dynamicPlatform", dynamicPlatform);
                returnObj.Set("cachedKeys", cachedKeys);
                returnObj.Set("smtEnabled", smtEnabled);
                break;
        }
        promise.Resolve(returnObj);
    }

    void GetPckCertificateDataWorker::OnError(const Napi::Error &e) {
        auto returnObj = Napi::Object::New(Env());
        returnObj.Set("error", e.Message());
        promise.Reject(returnObj);
    }
}
