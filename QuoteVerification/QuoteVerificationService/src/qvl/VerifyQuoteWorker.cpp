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

#include "VerifyQuoteWorker.h"

namespace intel::sgx::dcap::qvlwrapper {
    void VerifyQuoteWorker::Run() {
        auto pckCertChain = pckCertIssuerCertChain + pckCert;
        const char *crls[] = {rootCaCrl.c_str(), pckCrl.c_str()};

        qvlStatus = sgxAttestationVerifyPCKCertificate(pckCertChain.c_str(), crls, trustedRootCaPem.c_str(), nullptr);
        if (qvlStatus != STATUS_OK) {
            errorSource = VERIFY_PCK_CERTIFICATE;
            SetError("PCK certificate verification failed");
            return;
        }

        qvlStatus = sgxAttestationVerifyTCBInfo(tcbInfo.c_str(), tcbInfoIssuerCertChain.c_str(), rootCaCrl.c_str(),
                                                tcbInfoSigningChainTrustedRoot.c_str(), nullptr);
        if (qvlStatus != STATUS_OK) {
            errorSource = VERIFY_TCB_INFO;
            SetError("TCB info verification failed");
            return;
        }

        qvlStatus = sgxAttestationVerifyEnclaveIdentity(qeIdentity.c_str(), tcbInfoIssuerCertChain.c_str(),
                                                     rootCaCrl.c_str(), tcbInfoSigningChainTrustedRoot.c_str(), nullptr);
        if (qvlStatus != STATUS_OK) {
            errorSource = VERIFY_ENCLAVE_IDENTITY;
            SetError("Enclave identity verification failed");
            return;
        }

        qvlStatus = sgxAttestationVerifyQuote(quote, quoteSize, pckCert.c_str(), pckCrl.c_str(), tcbInfo.c_str(),
                                           qeIdentity.c_str());
        if (qvlStatus != STATUS_OK) {
            errorSource = VERIFY_QUOTE;
            SetError("Quote verification failed");
            return;
        }
    }

    void VerifyQuoteWorker::OnOK() {
        auto returnObj = Napi::Object::New(Env());
        returnObj.Set("status", static_cast<int>(qvlStatus));
        promise.Resolve(returnObj);
    }

    void VerifyQuoteWorker::OnError(const Napi::Error &e) {
        auto returnObj = Napi::Object::New(Env());
        returnObj.Set("status", static_cast<int>(qvlStatus));
        returnObj.Set("errorSource", static_cast<int>(errorSource));
        returnObj.Set("error", e.Message());
        promise.Resolve(returnObj);
    }
}
