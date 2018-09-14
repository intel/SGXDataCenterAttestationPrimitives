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

#ifndef INTEL_SGX_QVL_VERIFIERS_INTERFACE_H_
#define INTEL_SGX_QVL_VERIFIERS_INTERFACE_H_

#include <SgxEcdsaAttestation/QuoteVerification.h>
#include <CertVerification/CertificateChain.h>

#include "PckParser/CertStore.h"

namespace intel { namespace sgx { namespace qvl {

class CommonVerifier final
{
public: 
    CommonVerifier() = default;
    CommonVerifier(const CommonVerifier&) = default;
    CommonVerifier(CommonVerifier&&) = default;
    ~CommonVerifier() = default;

    CommonVerifier& operator=(const CommonVerifier&) = default;
    CommonVerifier& operator=(CommonVerifier&&) = default;

    /**
    * Verify correctness of root certificate
    * Checks subject, issuer, validity period, extensions and signature.
    *
    * @param rootCa - root certificate to verify
    * @return Status code of the operation
    */
    Status verifyRootCACert(const pckparser::CertStore &rootCa) const;
    
    /**
    * Verify correctness of intermediate PCK certificate
    * Checks subject, issuer, validity period, extensions and signature.
    *
    * @param intermediate - certificate to verify
    * @param root - root certificate
    * @return Status code of the operation
    */ 
    Status verifyIntermediate(const pckparser::CertStore &intermediate, const pckparser::CertStore &root) const;

    bool checkStandardExtensions(const std::vector<pckparser::Extension> &extensions, const std::vector<int> &opensslExtensionNids) const;
    bool checkSGXExtensions(const std::vector<pckparser::SgxExtension> &extensions, const std::vector<pckparser::SgxExtension::Type> &requiredSgxExtensions) const;
    bool checkValueFormat(const pckparser::SgxExtension& ext) const;
};

}}} // namespace intel { namespace sgx { namespace qvl {

#endif
