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

#include "TCBInfoVerifier.h"

#include <CertVerification/X509Constants.h>
#include <OpensslHelpers/SignatureVerification.h>

namespace intel { namespace sgx { namespace qvl {

TCBInfoVerifier::TCBInfoVerifier(const CommonVerifier& commonVerifier)
    : _commonVerifier{commonVerifier}
{
}

Status TCBInfoVerifier::verify(
        const TCBInfoJsonVerifier &tcbJson,
        const CertificateChain &chain,
        const pckparser::CrlStore &rootCaCrl,
        const pckparser::CertStore &trustedRoot) const
{
    const auto rootCert = chain.get(constants::ROOT_CA_SUBJECT);
    if(!rootCert)
    {
        return STATUS_SGX_ROOT_CA_MISSING;
    }
    const auto rootVerificationStatus = _commonVerifier.verifyRootCACert(*rootCert);
    if(rootVerificationStatus != STATUS_OK)
    {
        return rootVerificationStatus;
    }

    const auto tcbSigningCert = chain.get(constants::TCB_SUBJECT);
    if(!tcbSigningCert)
    {
        return STATUS_SGX_TCB_SIGNING_CERT_MISSING;
    }
    const auto tcbCertVerificationStatus = verifyTCBCert(*tcbSigningCert, *rootCert);
    if(tcbCertVerificationStatus != STATUS_OK)
    {
        return tcbCertVerificationStatus;
    }

    const auto crlVerificationStatus = _crlVerifier.verify(rootCaCrl, *rootCert);
    if(crlVerificationStatus != STATUS_OK)
    {
        return crlVerificationStatus;
    }

    if(rootCaCrl.isRevoked(*tcbSigningCert))
    {
        return STATUS_SGX_TCB_SIGNING_CERT_REVOKED;
    }

    if(!crypto::verifySha256EcdsaSignature(tcbJson.getSignature(), tcbJson.getInfoBody(), tcbSigningCert->getPubKey()))
    {
        return STATUS_TCB_INFO_INVALID_SIGNATURE;
    }

    if(trustedRoot.getSubject() != qvl::constants::ROOT_CA_SUBJECT)
    {
        return STATUS_TRUSTED_ROOT_CA_INVALID;
    }

    if(rootCert->getSignature().rawDer != trustedRoot.getSignature().rawDer)
    {
        return STATUS_SGX_TCB_SIGNING_CERT_CHAIN_UNTRUSTED;
    }

    return STATUS_OK;
}

Status TCBInfoVerifier::verifyTCBCert(const pckparser::CertStore &tcbCert, const pckparser::CertStore &rootCaCert) const
{
    if(tcbCert.getSubject() != constants::TCB_SUBJECT)
    {
        return STATUS_SGX_TCB_SIGNING_CERT_MISSING;
    }

    if(tcbCert.expired())
    {
        return STATUS_SGX_TCB_SIGNING_CERT_INVALID;
    }

    if(!_commonVerifier.checkStandardExtensions(tcbCert.getExtensions(), constants::TCB_REQUIRED_EXTENSIONS))
    {
        return STATUS_SGX_TCB_SIGNING_CERT_INVALID_EXTENSIONS;
    }

    if(tcbCert.getIssuer() != rootCaCert.getSubject()
        || !crypto::verifySignature(tcbCert, rootCaCert.getPubKey()))
    {
        return STATUS_SGX_TCB_SIGNING_CERT_INVALID_ISSUER;
    }

    return STATUS_OK;
}

}}} //namespace intel { namespace sgx { namespace qvl {
