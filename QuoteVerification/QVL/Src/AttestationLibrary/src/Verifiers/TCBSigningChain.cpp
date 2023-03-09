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

#include "TCBSigningChain.h"
#include "Utils/Logger.h"

#include <CertVerification/X509Constants.h>
#include <OpensslHelpers/SignatureVerification.h>

namespace intel { namespace sgx { namespace dcap {

TCBSigningChain::TCBSigningChain()
        : _commonVerifier(new CommonVerifier()),
          _crlVerifier(new PckCrlVerifier())
{
}

TCBSigningChain::TCBSigningChain(std::unique_ptr<CommonVerifier>&& commonVerifier,
                                 std::unique_ptr<PckCrlVerifier>&& crlVerifier)
        : _commonVerifier(std::move(commonVerifier)), _crlVerifier(std::move(crlVerifier))
{
}

Status TCBSigningChain::verify(
        const CertificateChain &chain,
        const pckparser::CrlStore &rootCaCrl,
        const dcap::parser::x509::Certificate &trustedRoot) const
{
    const auto rootCert = chain.getRootCert();
    if(!rootCert)
    {
        LOG_ERROR("ROOT CA is missing");
        return STATUS_SGX_ROOT_CA_MISSING;
    }
    if(!_baseVerifier.commonNameContains(rootCert->getSubject(), constants::SGX_ROOT_CA_CN_PHRASE))
    {
        LOG_ERROR("ROOT CA has wrong subject. Expected: {}, actual: {}", constants::SGX_ROOT_CA_CN_PHRASE,
                  rootCert->getSubject().getCommonName());
        return STATUS_SGX_ROOT_CA_MISSING;
    }

    const auto rootVerificationStatus = _commonVerifier->verifyRootCACert(*rootCert);
    if(rootVerificationStatus != STATUS_OK)
    {
        LOG_ERROR("Root CA verification failed: {}", rootVerificationStatus);
        return rootVerificationStatus;
    }

    const auto tcbSigningCert = chain.getTopmostCert();
    if(!tcbSigningCert)
    {
        LOG_ERROR("TCB Signing Cert is missing");
        return STATUS_SGX_TCB_SIGNING_CERT_MISSING;
    }
    if(!_baseVerifier.commonNameContains(tcbSigningCert->getSubject(), constants::SGX_TCB_SIGNING_CN_PHRASE))
    {
        LOG_ERROR("TCB Signing Cert has wrong common name. Expected: {}, actual: {}", constants::SGX_TCB_SIGNING_CN_PHRASE,
                  tcbSigningCert->getSubject().getCommonName());
        return STATUS_SGX_TCB_SIGNING_CERT_MISSING;
    }

    const auto tcbCertVerificationStatus = verifyTCBCert(*tcbSigningCert, *rootCert);
    if(tcbCertVerificationStatus != STATUS_OK)
    {
        LOG_ERROR("TCB Signing cert verification failed: {}", tcbCertVerificationStatus);
        return tcbCertVerificationStatus;
    }

    const auto crlVerificationStatus = _crlVerifier->verify(rootCaCrl, *rootCert);
    if(crlVerificationStatus != STATUS_OK)
    {
        LOG_ERROR("TCB Signing Root CA CRL verification failed: {}", crlVerificationStatus);
        return crlVerificationStatus;
    }

    if(rootCaCrl.isRevoked(*tcbSigningCert))
    {
        LOG_ERROR("TCB Signing Cert is revoked by Root CA");
        return STATUS_SGX_TCB_SIGNING_CERT_REVOKED;
    }

    if(trustedRoot.getSubject() != trustedRoot.getIssuer())
    {
        LOG_ERROR("TCB Signing Root CA is not self signed");
        return STATUS_TRUSTED_ROOT_CA_INVALID;
    }

    if(rootCert->getSignature().getRawDer() != trustedRoot.getSignature().getRawDer())
    {
        LOG_ERROR("Signature of trusted root doesn't match signature of root cert from TCB Signing Chain. Chain is not trusted.");
        return STATUS_SGX_TCB_SIGNING_CERT_CHAIN_UNTRUSTED;
    }

    return STATUS_OK;
}

Status TCBSigningChain::verifyTCBCert(const dcap::parser::x509::Certificate &tcbCert,
                                      const dcap::parser::x509::Certificate &rootCaCert) const
{

    if(tcbCert.getIssuer() != rootCaCert.getSubject())
    {
        LOG_ERROR("TCB signing certificate has different issuer than provided Root CA. RootCA common name: {}, TCB Cert issuer common name: {}",
                  rootCaCert.getSubject().getCommonName(), tcbCert.getSubject().getCommonName());
        return STATUS_SGX_TCB_SIGNING_CERT_INVALID_ISSUER;
    }

    if(!_commonVerifier->checkSignature(tcbCert, rootCaCert))
    {
        LOG_ERROR("TCB signing certificate signature verification failed");
        return STATUS_SGX_TCB_SIGNING_CERT_INVALID_ISSUER;
    }

    return STATUS_OK;
}

}}}