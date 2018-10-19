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

#include "PckCertVerifier.h"

#include <OpensslHelpers/SignatureVerification.h>
#include <CertVerification/X509Constants.h>

namespace intel { namespace sgx { namespace qvl {

PckCertVerifier::PckCertVerifier() : _commonVerifier(new CommonVerifier()),
                                     _crlVerifier(new PckCrlVerifier())
{
}

PckCertVerifier::PckCertVerifier(std::unique_ptr<CommonVerifier>&& _commonVerifier,
                                 std::unique_ptr<PckCrlVerifier>&& _crlVerifier)
                                 : _commonVerifier(std::move(_commonVerifier)), _crlVerifier(std::move(_crlVerifier))
{
}

Status PckCertVerifier::verify(const CertificateChain &chain, const pckparser::CrlStore &rootCaCrl, const pckparser::CrlStore &intermediateCrl, const pckparser::CertStore &rootCa) const
{
    const auto x509InChainRootCa = chain.getRootCert();
    if(!x509InChainRootCa || !_baseVerifier.commonNameContains(x509InChainRootCa->getSubject(), constants::SGX_ROOT_CA_CN_PHRASE))
    {
        return STATUS_SGX_ROOT_CA_MISSING;
    }

    const auto x509InChainIntermediateCa = chain.getIntermediateCert();
    if(!x509InChainIntermediateCa || !_baseVerifier.commonNameContains(x509InChainIntermediateCa->getSubject(), constants::SGX_INTERMEDIATE_CN_PHRASE))
    {
        return STATUS_SGX_INTERMEDIATE_CA_MISSING;
    }

    const auto x509InChainPckCert = chain.getTopmostCert();
    if(!x509InChainPckCert || !_baseVerifier.commonNameContains(x509InChainPckCert->getSubject(), constants::SGX_PCK_CN_PHRASE))
    {
        return STATUS_SGX_PCK_MISSING;
    }

    const auto rootVerificationStatus = _commonVerifier->verifyRootCACert(*x509InChainRootCa);
    if(rootVerificationStatus != STATUS_OK)
    {
        return rootVerificationStatus;
    }

    const auto intermediateVerificationStatus = _commonVerifier->verifyIntermediate(*x509InChainIntermediateCa, *x509InChainRootCa);
    if(intermediateVerificationStatus != STATUS_OK)
    {
        return intermediateVerificationStatus;
    }

    const auto pckVerificationStatus = verifyPCKCert(*x509InChainPckCert, *x509InChainIntermediateCa);
    if(pckVerificationStatus != STATUS_OK)
    {
        return pckVerificationStatus;
    } 

    if(rootCa.getSubject() != rootCa.getIssuer())
    {
        return STATUS_TRUSTED_ROOT_CA_INVALID;
    }

    if(x509InChainRootCa->getSignature().rawDer != rootCa.getSignature().rawDer)
    {
        return STATUS_SGX_PCK_CERT_CHAIN_UNTRUSTED;
    }

    // 
    // begin of CRL verification
    //
    const auto checkRootCaCrlCorrectness = _crlVerifier->verify(rootCaCrl, *x509InChainRootCa);
    if(checkRootCaCrlCorrectness != STATUS_OK)
    {
        return checkRootCaCrlCorrectness;
    } 

    const auto checkIntermediateCrlCorrectness = _crlVerifier->verify(intermediateCrl, *x509InChainIntermediateCa);
    if(checkIntermediateCrlCorrectness != STATUS_OK)
    {
        return checkIntermediateCrlCorrectness;
    }

    if(rootCaCrl.isRevoked(*x509InChainIntermediateCa))
    {
        return STATUS_SGX_INTERMEDIATE_CA_REVOKED;
    }

    if(intermediateCrl.isRevoked(*x509InChainPckCert))
    {
        return STATUS_SGX_PCK_REVOKED;
    }

    return STATUS_OK;
}

Status PckCertVerifier::verifyPCKCert(const pckparser::CertStore &pckCert, const pckparser::CertStore &intermediate) const
{
    const auto basicPckValidationStatus = verifyPCKCert(pckCert);

    if(basicPckValidationStatus != STATUS_OK)
    {
        return basicPckValidationStatus;
    } 

    if(pckCert.getIssuer() != intermediate.getSubject()
        || !_commonVerifier->checkSignature(pckCert, intermediate))
    {
        return STATUS_SGX_PCK_INVALID_ISSUER;
    }

    return STATUS_OK;
}

Status PckCertVerifier::verifyPCKCert(const pckparser::CertStore &pckCert) const
{

    if(pckCert.expired())
    {
        return STATUS_SGX_PCK_INVALID;
    }

    if(!_commonVerifier->checkStandardExtensions(pckCert.getExtensions(), constants::PCK_REQUIRED_EXTENSIONS)
        || !_commonVerifier->checkSGXExtensions(pckCert.getSGXExtensions(), constants::PCK_REQUIRED_SGX_EXTENSIONS))
    {
        return STATUS_SGX_PCK_INVALID_EXTENSIONS;
    }

    return STATUS_OK;
}

}}} //namespace intel { namespace sgx { namespace qvl
