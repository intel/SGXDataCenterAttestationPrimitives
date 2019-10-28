/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
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


#include <string>
#include <memory>
#include <algorithm>
#include <iostream>
#include <iomanip>

#include "OpensslHelpers/OpensslInit.h"
#include "PckParser/CrlStore.h"
#include "CertVerification/CertificateChain.h"
#include "QuoteVerification/Quote.h"
#include "QuoteVerification/QuoteConstants.h"

#include "Verifiers/PckCertVerifier.h"
#include "Verifiers/PckCrlVerifier.h"
#include "Verifiers/TCBInfoVerifier.h"
#include "Verifiers/EnclaveIdentityVerifier.h"
#include "Verifiers/EnclaveReportVerifier.h"
#include "Verifiers/QuoteVerifier.h"
#include "Verifiers/EnclaveIdentityParser.h"
#include "Verifiers/EnclaveIdentity.h"
#include "Utils/TimeUtils.h"

#include <SgxEcdsaAttestation/QuoteVerification.h>
#include <Version/Version.h>

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

void sgxEnclaveAttestationGetVersion(char *version, size_t len)
{
    size_t strln = 1 + strlen(VERSION);
    if (strln > len)
    {
        memcpy(version, VERSION, len);
        return;
    }
    memcpy(version, VERSION, strln);
}

Status sgxAttestationVerifyPCKCertificate(const char *pemCertChain, const char * const crls[], const char *pemRootCaCertificate, const time_t* expirationDate)
{
    time_t currentTime;
    try
    {
        currentTime = qvl::getCurrentTime(expirationDate);
    }
    catch (const std::runtime_error &ex)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if(!pemCertChain ||
        !pemRootCaCertificate ||
        !crls ||
        !crls[0] ||
        !crls[1])
    {
        return STATUS_UNSUPPORTED_CERT_FORMAT;
    }

    qvl::CertificateChain chain;
    const auto status = chain.parse(pemCertChain);

    if(status != STATUS_OK)
    {
        return status;
    }

    if(chain.length() != EXPECTED_CERTIFICATE_COUNT_IN_PCK_CHAIN)
    {
        return STATUS_UNSUPPORTED_CERT_FORMAT;
    }

    qvl::pckparser::CrlStore rootCaCrl, intermediateCrl;
    if(!rootCaCrl.parse(crls[0]) || !intermediateCrl.parse(crls[1]))
    {
        return STATUS_SGX_CRL_UNSUPPORTED_FORMAT;
    }

    try
    {
        auto rootCa = dcap::parser::x509::Certificate::parse(pemRootCaCertificate);
        return qvl::PckCertVerifier{}.verify(chain, rootCaCrl, intermediateCrl, rootCa, currentTime);
    }
    catch (const dcap::parser::FormatException &ex)
    {
        return STATUS_TRUSTED_ROOT_CA_UNSUPPORTED_FORMAT;
    }
}

// Deprecated
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
    const auto status = chain.parse(pemCACertChain);
    if (status != STATUS_OK)
    {
        return STATUS_SGX_CA_CERT_UNSUPPORTED_FORMAT;
    }

    try
    {
        auto trustedRootCACert = dcap::parser::x509::Certificate::parse(pemTrustedRootCaCert);
        return qvl::PckCrlVerifier{}.verify(x509Crl, chain, trustedRootCACert);
    }
    catch (const dcap::parser::FormatException &ex)
    {
        return STATUS_TRUSTED_ROOT_CA_UNSUPPORTED_FORMAT;
    }
    catch (const dcap::parser::InvalidExtensionException &ex)
    {
        return STATUS_TRUSTED_ROOT_CA_UNSUPPORTED_FORMAT;
    }
}

Status sgxAttestationVerifyTCBInfo(const char *tcbInfo, const char *pemCertChain, const char *pemRootCaCrl,
        const char *pemRootCaCertificate, const time_t* expirationDate)
{
    time_t currentTime;
    try
    {
        currentTime = qvl::getCurrentTime(expirationDate);
    }
    catch (const std::runtime_error &ex)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if(!tcbInfo ||
       !pemCertChain ||
       !pemRootCaCrl ||
       !pemRootCaCertificate)
    {
        return STATUS_UNSUPPORTED_CERT_FORMAT;
    }

    dcap::parser::json::TcbInfo tcbInfoJson;
    try
    {
        tcbInfoJson = dcap::parser::json::TcbInfo::parse(tcbInfo);
    }
    catch (const dcap::parser::FormatException &ex)
    {
        return STATUS_SGX_TCB_INFO_UNSUPPORTED_FORMAT;
    }
    catch (const dcap::parser::InvalidExtensionException &ex)
    {
        return STATUS_SGX_TCB_INFO_INVALID;
    }

    qvl::CertificateChain chain;
    const auto status = chain.parse(pemCertChain);
    if (status != STATUS_OK)
    {
        return status;
    }

    if(chain.length() != EXPECTED_CERTIFICATE_COUNT_IN_TCB_CHAIN)
    {
        return STATUS_UNSUPPORTED_CERT_FORMAT;
    }

    qvl::pckparser::CrlStore rootCaCrl;
    if(!rootCaCrl.parse(pemRootCaCrl))
    {
        return STATUS_SGX_CRL_UNSUPPORTED_FORMAT;
    }

    try
    {
        auto trustedRootCa = dcap::parser::x509::Certificate::parse(pemRootCaCertificate);
        return qvl::TCBInfoVerifier{}.verify(tcbInfoJson, chain, rootCaCrl, trustedRootCa, currentTime);
    }
    catch (const dcap::parser::FormatException &ex)
    {
        return STATUS_UNSUPPORTED_CERT_FORMAT;
    }
    catch (const dcap::parser::InvalidExtensionException &ex)
    {
        return STATUS_SGX_ROOT_CA_INVALID_EXTENSIONS;
    }
}

Status sgxAttestationVerifyEnclaveIdentity(const char *enclaveIdentityString, const char *pemCertChain, const char *pemRootCaCrl,
        const char *pemRootCaCertificate, const time_t* expirationDate)
{

    time_t currentTime;
    try
    {
        currentTime = qvl::getCurrentTime(expirationDate);
    }
    catch (const std::runtime_error &ex)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if(!enclaveIdentityString ||
       !pemCertChain ||
       !pemRootCaCrl ||
       !pemRootCaCertificate)
    {
        return STATUS_UNSUPPORTED_CERT_FORMAT;
    }

    qvl::EnclaveIdentityParser parser;
    std::unique_ptr<qvl::EnclaveIdentity> enclaveIdentity;
    try
    {
        enclaveIdentity = parser.parse(enclaveIdentityString);
    }
    catch (const qvl::ParserException &e)
    {
        return e.getStatus();
    }

    qvl::CertificateChain chain;
    const auto status = chain.parse(pemCertChain);
    if(status != STATUS_OK)
    {
        return status;
    }

    if(chain.length() != EXPECTED_CERTIFICATE_COUNT_IN_TCB_CHAIN)
    {
        return STATUS_UNSUPPORTED_CERT_FORMAT;
    }

    qvl::pckparser::CrlStore rootCaCrl;
    if(!rootCaCrl.parse(pemRootCaCrl))
    {
        return STATUS_SGX_CRL_UNSUPPORTED_FORMAT;
    }

    try
    {
        auto trustedRootCa = dcap::parser::x509::Certificate::parse(pemRootCaCertificate);
        return qvl::EnclaveIdentityVerifier{}.verify(*enclaveIdentity, chain, rootCaCrl, trustedRootCa, currentTime);
    }
    catch (const dcap::parser::FormatException &ex)
    {
        return STATUS_UNSUPPORTED_CERT_FORMAT;
    }
    catch (const dcap::parser::InvalidExtensionException &ex)
    {
        return STATUS_SGX_ROOT_CA_INVALID_EXTENSIONS;
    }
}

Status sgxAttestationVerifyQuote(const uint8_t* rawQuote, uint32_t quoteSize, const char *pemPckCertificate, const char* pckCrl,
                                 const char* tcbInfoJson, const char* qeIdentityJson)
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
  
    qvl::pckparser::CrlStore pckCrlStore;
    if(!pckCrlStore.parse(pckCrl))
    {
        return STATUS_UNSUPPORTED_PCK_RL_FORMAT;
    }

    dcap::parser::json::TcbInfo tcbInfo;
    try
    {
        tcbInfo = dcap::parser::json::TcbInfo::parse(tcbInfoJson);
    }
    catch (const dcap::parser::FormatException &ex)
    {
        return STATUS_UNSUPPORTED_TCB_INFO_FORMAT;
    }
    catch (const dcap::parser::InvalidExtensionException &ex)
    {
        return STATUS_UNSUPPORTED_TCB_INFO_FORMAT;
    }

    qvl::EnclaveIdentityParser parser;
    std::unique_ptr<qvl::EnclaveIdentity> enclaveIdentity;
    if (qeIdentityJson != nullptr)
    {
        try {
            enclaveIdentity = parser.parse(qeIdentityJson);
        }
        catch (const qvl::ParserException &e)
        {
            return STATUS_UNSUPPORTED_QE_IDENTITY_FORMAT;
        }
    }

    try
    {
        auto pckCert = dcap::parser::x509::PckCertificate::parse(pemPckCertificate);
        return qvl::QuoteVerifier{}.verify(quote, pckCert, pckCrlStore, tcbInfo, enclaveIdentity.get(), qvl::EnclaveReportVerifier());
    }
    catch (const dcap::parser::FormatException &ex)
    {
        return STATUS_UNSUPPORTED_PCK_CERT_FORMAT;
    }
}

Status sgxAttestationVerifyEnclaveReport(const uint8_t* enclaveReport, const char* enclaveIdentity)
{
    if(!enclaveReport || !enclaveIdentity)
    {
        return STATUS_SGX_ENCLAVE_REPORT_UNSUPPORTED_FORMAT;
    }

    const std::vector<uint8_t> vecEnclaveReport(enclaveReport, enclaveReport + qvl::constants::ENCLAVE_REPORT_BYTE_LEN);
    qvl::Quote quote;
    if(!quote.parseEnclaveReport(vecEnclaveReport))
    {
        return STATUS_SGX_ENCLAVE_REPORT_UNSUPPORTED_FORMAT;
    }

    qvl::EnclaveIdentityParser parser;
    std::unique_ptr<qvl::EnclaveIdentity> enclaveIdentityParsed;
    try
    {
        enclaveIdentityParsed = parser.parse(enclaveIdentity);
    }
    catch(const qvl::ParserException &e)
    {
        return e.getStatus();
    }

    return qvl::EnclaveReportVerifier{}.verify(enclaveIdentityParsed.get(), quote.getBody());
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

    *qeCertificationDataType = quoteQeCertData.type;

    // buffer pointed to by 'qeCertificationData' must be at least 'qeCertificationDataSize' long
    std::copy(std::begin(quoteQeCertData.data), std::end(quoteQeCertData.data), qeCertificationData);

    return STATUS_OK;
}
