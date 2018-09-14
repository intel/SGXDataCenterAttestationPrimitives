/*
* Copyright (c) 2017, Intel Corporation
*
* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:

* 1. Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
* 3. Neither the name of the copyright holder nor the names of its contributors
*    may be used to endorse or promote products derived from this software
*    without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
* THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
* BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
* OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
* OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
* OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
* WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
* OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
* EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef INTEL_SGX_QVL_TCB_INFO_VERIFIER_H_
#define INTEL_SGX_QVL_TCB_INFO_VERIFIER_H_

#include "CommonVerifier.h"
#include "TCBInfoJsonVerifier.h"
#include "PckCrlVerifier.h"

#include <PckParser/CertStore.h>
#include <PckParser/CrlStore.h>

namespace intel { namespace sgx { namespace qvl {

class TCBInfoVerifier
{
public:
    explicit TCBInfoVerifier(const CommonVerifier& commonVerifier);

    TCBInfoVerifier() = default;
    TCBInfoVerifier(const TCBInfoVerifier&) = default;
    TCBInfoVerifier(TCBInfoVerifier&&) = default;
    ~TCBInfoVerifier() = default;

    TCBInfoVerifier& operator=(const TCBInfoVerifier&) = default;
    TCBInfoVerifier& operator=(TCBInfoVerifier&&) = default;

    Status verify(
            const TCBInfoJsonVerifier &tcbJson,
            const CertificateChain &chain,
            const pckparser::CrlStore &rootCaCrl,
            const pckparser::CertStore &trustedRoot) const;

    /**
    * Verify correctness of TCB signing certificate
    * Checks subject, issuer, validity period, extensions and signature.
    *
    * @param tcbCert - TCB certificate to verify
    * @param rootCaCert - root certificate
    * @return Status code of the operation
    */
    Status verifyTCBCert(const pckparser::CertStore &tcbCert, const pckparser::CertStore &rootCaCert) const;

private:
    CommonVerifier _commonVerifier;
    PckCrlVerifier _crlVerifier;
};

}}} // namespace intel { namespace sgx { namespace qvl {

#endif // INTEL_SGX_QVL_TCB_INFO_VERIFIER_H_
