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


#include "OpensslHelpers/OpensslInit.h"
#include "PckParser/CrlStore.h"
#include "CertVerification/CertificateChain.h"
#include "QuoteVerification/Quote.h"
#include "QuoteVerification/QuoteConstants.h"

#include "Verifiers/PckCertVerifier.h"
#include "Verifiers/PckCrlVerifier.h"
#include "Verifiers/TCBInfoVerifier.h"
#include "Verifiers/TCBInfoJsonVerifier.h"
#include "Verifiers/QuoteVerifier.h"

#include <SgxEcdsaAttestation/QuoteVerification.h>
#include <Version/Version.h>

#include <string>
#include <memory>
#include <algorithm>

#include <iostream>
#include <iomanip>

static constexpr size_t EXPECTED_CERTIFICATE_COUNT_IN_PCK_CHAIN = 3;
static constexpr size_t EXPECTED_CERTIFICATE_COUNT_IN_TCB_CHAIN = 2;

using namespace intel::sgx;

class OpensslGuard
{
public:
    OpensslGuard()
    {
        qvl::crypto::init();
    }

    ~OpensslGuard()
    {
        qvl::crypto::clear();
    }

    OpensslGuard(const OpensslGuard&) = delete;
    OpensslGuard(OpensslGuard&&) = delete;
    OpensslGuard& operator=(const OpensslGuard&) = delete;
    OpensslGuard& operator=(OpensslGuard&&) = delete;
};

static const OpensslGuard opensslGuard;

const char* sgxAttestationGetVersion()
{
    return VERSION;
}

Status sgxAttestationVerifyPCKCertificate(const char *pemCertChain, const char * const crls[], const char *pemRootCaCertificate)
{
    if(!pemCertChain || 
        !pemRootCaCertificate ||
        !crls ||
        !crls[0] ||
        !crls[1])
    {
        return STATUS_UNSUPPORTED_CERT_FORMAT;
    }

    qvl::CertificateChain chain;
    if(!chain.parse(pemCertChain) || chain.length() != EXPECTED_CERTIFICATE_COUNT_IN_PCK_CHAIN)
    {
        return STATUS_UNSUPPORTED_CERT_FORMAT;
    }

    qvl::pckparser::CrlStore rootCaCrl, intermediateCrl;
    if(!rootCaCrl.parse(crls[0]) || !intermediateCrl.parse(crls[1]))
    {
        return STATUS_SGX_CRL_UNSUPPORTED_FORMAT;
    }

    qvl::pckparser::CertStore rootCa;
    if(!rootCa.parse(pemRootCaCertificate))
    {
        return STATUS_TRUSTED_ROOT_CA_UNSUPPORTED_FORMAT;
    }
 
    return qvl::PckCertVerifier{}.verify(chain, rootCaCrl, intermediateCrl, rootCa);
}

Status sgxAttestationVerifyPCKRevocationList(const char* crl, const char *pemCACertChain, const char *pemTrustedRootCaCert)
{
    if(!crl || !pemCACertChain || !pemTrustedRootCaCert)
    {
        return STATUS_SGX_CRL_UNSUPPORTED_FORMAT;
    }

    qvl::pckparser::CrlStore x509Crl;
    if(!x509Crl.parse(crl))
    {
        return STATUS_SGX_CRL_UNSUPPORTED_FORMAT;
    }

    qvl::CertificateChain chain;
    if(!chain.parse(pemCACertChain))
    {
        return STATUS_SGX_CA_CERT_UNSUPPORTED_FORMAT;
    }

    qvl::pckparser::CertStore trustedRootCACert;
    if(!trustedRootCACert.parse(pemTrustedRootCaCert))
    {
        return STATUS_TRUSTED_ROOT_CA_UNSUPPORTED_FORMAT;
    }

    return qvl::PckCrlVerifier{}.verify(x509Crl, chain, trustedRootCACert);
}

Status sgxAttestationVerifyTCBInfo(const char *tcbInfo, const char *pemCertChain, const char *pemRootCaCrl, const char *pemRootCaCertificate)
{
    if(!tcbInfo ||
       !pemCertChain ||
       !pemRootCaCrl ||
       !pemRootCaCertificate)
    {
        return STATUS_UNSUPPORTED_CERT_FORMAT;
    }

    qvl::TCBInfoJsonVerifier tcbiJsonVerifier;
    const auto tcbiParseStatus = tcbiJsonVerifier.parse(tcbInfo);
    if(tcbiParseStatus != STATUS_OK)
    {
        return tcbiParseStatus;
    }

    qvl::CertificateChain chain;
    if(!chain.parse(pemCertChain) || chain.length() != EXPECTED_CERTIFICATE_COUNT_IN_TCB_CHAIN)
    {
        return STATUS_UNSUPPORTED_CERT_FORMAT;
    }

    qvl::pckparser::CertStore trustedRootCa;
    if(!trustedRootCa.parse(pemRootCaCertificate))
    {
        return STATUS_UNSUPPORTED_CERT_FORMAT;
    }

    qvl::pckparser::CrlStore rootCaCrl;
    if(!rootCaCrl.parse(pemRootCaCrl))
    {
        return STATUS_SGX_CRL_UNSUPPORTED_FORMAT;
    }

    return qvl::TCBInfoVerifier{}.verify(tcbiJsonVerifier, chain, rootCaCrl, trustedRootCa);
}

Status sgxAttestationVerifyQuote(const uint8_t* rawQuote, uint32_t quoteSize, const char *pemPckCertificate, const char* pckCrl, const char* tcbInfoJson)
{
    if(!rawQuote ||
       !pemPckCertificate ||
       !pckCrl ||
       !tcbInfoJson)
    {
        return STATUS_MISSING_PARAMETERS;
    }
   
    // We totaly trust user on this, it should be explicitly and clearly
    // mentioned in doc, is there any max quote len other than numeric_limit<uint32_t>::max() ? 
    const std::vector<uint8_t> vecQuote(rawQuote, std::next(rawQuote, quoteSize));
    
    qvl::Quote quote;
    if(!quote.parse(vecQuote) || quote.getHeader().version != qvl::constants::QUOTE_VERSION)
    {
        return Status::STATUS_UNSUPPORTED_QUOTE_FORMAT;
    }
    
    qvl::pckparser::CertStore pckCert;
    if(!pckCert.parse(pemPckCertificate))
    {
        return STATUS_UNSUPPORTED_PCK_CERT_FORMAT;
    }
  
    qvl::pckparser::CrlStore pckCrlStore;
    if(!pckCrlStore.parse(pckCrl))
    {
        return STATUS_UNSUPPORTED_PCK_RL_FORMAT;
    }

    
    qvl::TCBInfoJsonVerifier tcbiJsonVerifier;
    if(STATUS_OK != tcbiJsonVerifier.parse(tcbInfoJson))
    {
        return STATUS_UNSUPPORTED_TCB_INFO_FORMAT;
    }

    return qvl::QuoteVerifier{}.verify(quote, pckCert, pckCrlStore, tcbiJsonVerifier);
}

Status sgxAttestationGetQECertificationDataSize(
        const uint8_t *rawQuote,
        uint32_t quoteSize,
        uint32_t *qeCertificationDataSize)
{
    if(!rawQuote ||
       !qeCertificationDataSize)
    {
        return STATUS_MISSING_PARAMETERS;
    }

    // We totally trust user on this, it should be explicitly and clearly
    // mentioned in doc, is there any max quote len other than numeric_limit<uint32_t>::max() ?
    const std::vector<uint8_t> vecQuote(rawQuote, std::next(rawQuote, quoteSize));

    qvl::Quote quote;
    if(!quote.parse(vecQuote) || quote.getHeader().version != qvl::constants::QUOTE_VERSION)
    {
        return Status::STATUS_UNSUPPORTED_QUOTE_FORMAT;
    }

    *qeCertificationDataSize = static_cast<uint32_t>(quote.getQuoteAuthData().qeCertData.parsedDataSize);

    return STATUS_OK;
}

Status sgxAttestationGetQECertificationData(
        const uint8_t *rawQuote,
        uint32_t quoteSize,
        uint32_t qeCertificationDataSize,
        uint8_t *qeCertificationData,
        uint16_t *qeCertificationDataType)
{
    if(!rawQuote ||
       !qeCertificationData||
       !qeCertificationDataType)
    {
        return STATUS_MISSING_PARAMETERS;
    }

    // We totally trust user on this, it should be explicitly and clearly
    // mentioned in doc, is there any max quote len other than numeric_limit<uint32_t>::max() ?
    const std::vector<uint8_t> vecQuote(rawQuote, std::next(rawQuote, quoteSize));

    qvl::Quote quote;
    if(!quote.parse(vecQuote) || quote.getHeader().version != qvl::constants::QUOTE_VERSION)
    {
        return STATUS_UNSUPPORTED_QUOTE_FORMAT;
    }

    const auto& quoteQeCertData = quote.getQuoteAuthData().qeCertData;

    if(qeCertificationDataSize != quoteQeCertData.parsedDataSize)
    {
        return STATUS_INVALID_QE_CERTIFICATION_DATA_SIZE;
    }

    const auto quoteDataType = quoteQeCertData.type;
    if(std::find(qvl::constants::SUPPORTED_PCK_IDS.cbegin(), qvl::constants::SUPPORTED_PCK_IDS.cend(), quoteDataType) == qvl::constants::SUPPORTED_PCK_IDS.cend())
    {
        return STATUS_UNSUPPORTED_QE_CERTIFICATION_DATA_TYPE;
    }
    *qeCertificationDataType = quoteDataType;

    // buffer pointed to by 'qeCertificationData' must be at least 'qeCertificationDataSize' long
    std::copy(std::begin(quoteQeCertData.data), std::end(quoteQeCertData.data), qeCertificationData);

    return STATUS_OK;
}
