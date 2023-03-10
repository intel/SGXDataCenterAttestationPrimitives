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

#include <napi.h>
#include <iostream>
#include <SgxEcdsaAttestation/QuoteVerification.h>
#include "GetPckCertificateDataWorker.h"
#include "GetCertificationDataWorker.h"
#include "VersionWorker.h"
#include "GetCrlDistributionPointWorker.h"
#include "VerifyQuoteWorker.h"

namespace intel::sgx::dcap::qvlwrapper {

Napi::Value GetCertificationData(const Napi::CallbackInfo &info) {

    Napi::Env env = info.Env();
    auto deferred = Napi::Promise::Deferred::New(env);

    auto requestId = std::string(info[0].As<Napi::String>());
    auto quote = info[1].As<Napi::Buffer<uint8_t>>();
    auto worker = new GetCertificationDataWorker(env, deferred, requestId, quote.Data(), quote.Length());
    worker->Queue();
    return deferred.Promise();
}

Napi::Value Version(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();

    auto deferred = Napi::Promise::Deferred::New(env);

    auto requestId = std::string(info[0].As<Napi::String>());
    auto worker = new VersionWorker(env, deferred, requestId);

    worker->Queue();
    return deferred.Promise();
}

Napi::Value GetPckCertificateData(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    auto deferred = Napi::Promise::Deferred::New(env);
    auto requestId = std::string(info[0].As<Napi::String>());
    auto pemCertificate = std::string(info[1].As<Napi::String>());
    auto worker = new GetPckCertificateDataWorker(env, deferred, requestId, pemCertificate);
    worker->Queue();
    return deferred.Promise();
}

Napi::Value GetCrlDistributionPoint(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    auto deferred = Napi::Promise::Deferred::New(env);
    auto requestId = std::string(info[0].As<Napi::String>());
    auto pemCertificate = std::string(info[1].As<Napi::String>());
    auto worker = new GetCrlDistributionPointWorker(env, deferred, requestId, pemCertificate);
    worker->Queue();
    return deferred.Promise();
}

Napi::Value VerifyQuote(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();

    auto requestId = std::string(info[0].As<Napi::String>());
    auto quote = info[1].As<Napi::Buffer<uint8_t>>();
    auto pckCert = std::string(info[2].As<Napi::String>());
    auto tcbInfo = std::string(info[3].As<Napi::String>());
    auto qeIdentity = std::string(info[4].As<Napi::String>());

    auto pckCertIssuerCertChain = std::string(info[5].As<Napi::String>());
    auto tcbInfoIssuerCertChain = std::string(info[6].As<Napi::String>());

    auto pckCrl = std::string(info[7].As<Napi::String>());
    auto rootCaCrl = std::string(info[8].As<Napi::String>());
    auto trustedRootCaPem = std::string(info[9].As<Napi::String>());
    auto tcbInfoSigningChainTrustedRoot = std::string(info[10].As<Napi::String>());

    auto deferred = Napi::Promise::Deferred::New(env);

    auto worker = new VerifyQuoteWorker(env, deferred, requestId, quote.Data(), quote.Length(),
                                        pckCert, tcbInfo, qeIdentity, pckCertIssuerCertChain,
                                        tcbInfoIssuerCertChain, pckCrl, rootCaCrl, trustedRootCaPem,
                                        tcbInfoSigningChainTrustedRoot);

    worker->Queue();
    return deferred.Promise();
}

void LoggerSetup(const Napi::CallbackInfo &info) {
    auto name = std::string(info[0].As<Napi::String>());

    auto consoleLogLevel = std::string(info[1].As<Napi::String>());
    auto fileLogLevel = std::string(info[2].As<Napi::String>());
    auto fileName = std::string(info[3].As<Napi::String>());
    auto pattern = std::string(info[4].As<Napi::String>());

    sgxAttestationLoggerSetup(name.c_str(), consoleLogLevel.c_str(), fileLogLevel.c_str(), fileName.c_str(),
                              pattern.c_str());
}

Napi::Object InitAll(Napi::Env env, Napi::Object exports) {

    exports.Set(Napi::String::New(env, "getCertificationData"),
                Napi::Function::New(env, GetCertificationData));

    exports.Set(Napi::String::New(env, "version"),
                Napi::Function::New(env, Version));

    exports.Set(Napi::String::New(env, "getPckCertificateData"),
                Napi::Function::New(env, GetPckCertificateData));

    exports.Set(Napi::String::New(env, "getCrlDistributionPoint"),
                Napi::Function::New(env, GetCrlDistributionPoint));

    exports.Set(Napi::String::New(env, "verifyQuote"),
                Napi::Function::New(env, VerifyQuote));

    exports.Set(Napi::String::New(env, "loggerSetup"),
                Napi::Function::New(env, LoggerSetup));

    return exports;
}

NODE_API_MODULE(qvl, InitAll)

}
