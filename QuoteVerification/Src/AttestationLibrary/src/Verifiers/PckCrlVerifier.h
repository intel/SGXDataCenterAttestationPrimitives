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

#ifndef INTEL_SGX_QVL_PCK_CRL_VERIFIER_H_
#define INTEL_SGX_QVL_PCK_CRL_VERIFIER_H_

#include "CommonVerifier.h"

#include <PckParser/CrlStore.h>

namespace intel { namespace sgx { namespace qvl {

class PckCrlVerifier
{
public:
    explicit PckCrlVerifier(const CommonVerifier& commonVerifier);

    PckCrlVerifier() = default;
    PckCrlVerifier(const PckCrlVerifier&) = default;
    PckCrlVerifier(PckCrlVerifier&&) = default;
    ~PckCrlVerifier() = default;

    PckCrlVerifier& operator=(const PckCrlVerifier&) = default;
    PckCrlVerifier& operator=(PckCrlVerifier&&) = default;

    Status verify(const pckparser::CrlStore &crl, const pckparser::CertStore &crlIssuer) const;
    Status verify(const pckparser::CrlStore &crl, const CertificateChain &chain, const pckparser::CertStore &trustedRoot) const; 

    /**
    * Verify correctness of CRL issuer cerificate chain
    *
    * @param chain - parsed certificate chain object
    * @param crl - crl certificate
    * @return Status code of the operation
    */
    Status verifyCRLIssuerCertChain(const CertificateChain& chain, const pckparser::CrlStore& crl) const;

    bool checkValidityPeriodAndIssuer(const pckparser::CrlStore& crl);

private:
    CommonVerifier _commonVerifier;
};

}}} // namespace intel { namespace sgx { namespace qvl {


#endif
