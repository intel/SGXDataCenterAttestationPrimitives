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


#include <string>
#include <memory>
#include <algorithm>

#include "PckParser/CrlStore.h"
#include "CertVerification/CertificateChain.h"
#include "QuoteVerification/Quote.h"
#include "QuoteVerification/QuoteConstants.h"
#include "QuoteVerification/QuoteParsers.h"

#include "Verifiers/PckCertVerifier.h"
#include "Verifiers/PckCrlVerifier.h"
#include "Verifiers/TCBInfoVerifier.h"
#include "Verifiers/EnclaveIdentityVerifier.h"
#include "Verifiers/EnclaveReportVerifier.h"
#include "Verifiers/QuoteVerifier.h"
#include "Verifiers/EnclaveIdentityParser.h"
#include "Verifiers/EnclaveIdentityV2.h"
#include "Utils/TimeUtils.h"
#include "Utils/SafeMemcpy.h"

#include <SgxEcdsaAttestation/QuoteVerification.h>
#include <Version/Version.h>
#include <Utils/Logger.h>

// On Windows in one of headers STATUS_INVALID_PARAMETER macro is defined and it conflicts with our status name so undef it.
#undef STATUS_INVALID_PARAMETER

static constexpr size_t EXPECTED_CERTIFICATE_COUNT_IN_PCK_CHAIN = 3;
static constexpr size_t EXPECTED_CERTIFICATE_COUNT_IN_TCB_CHAIN = 2;

using namespace intel::sgx;

const char* sgxAttestationGetVersion()
{
    return VERSION;
}

void sgxEnclaveAttestationGetVersion(char *version, size_t len)
{
    size_t strln = 1 + strlen(VERSION);
    if (strln > len)
    {
        safeMemcpy(version, VERSION, len);
        return;
    }
    safeMemcpy(version, VERSION, strln);
}

Status sgxAttestationVerifyPCKCertificate(const char *pemCertChain, const char * const crls[], const char *pemRootCaCertificate, const time_t* expirationDate)
{
    time_t currentTime;
    try
    {
        currentTime = dcap::getCurrentTime(expirationDate);
    }
    catch (const std::runtime_error&)
    {
        LOG_ERROR("Can't get current time or it was not provided");
        return STATUS_INVALID_PARAMETER;
    }

    if(!pemCertChain ||
        !pemRootCaCertificate ||
        !crls ||
        !crls[0] ||
        !crls[1])
    {
        LOG_ERROR("pemCertChain, pemRootCaCertificate, CRLs (RootCaCrl, IntermediateCaCrl) was not provided");
        return STATUS_UNSUPPORTED_CERT_FORMAT;
    }

    dcap::CertificateChain chain;
    const auto status = chain.parse(pemCertChain);

    if(status != STATUS_OK)
    {
        LOG_ERROR("PCK Cert Chain parse error: {}", status);
        return status;
    }

    if(chain.length() != EXPECTED_CERTIFICATE_COUNT_IN_PCK_CHAIN)
    {
        LOG_ERROR("PCK chain length is not correct. Expected: {}, actual: {}, cert chain: {}",
                  EXPECTED_CERTIFICATE_COUNT_IN_PCK_CHAIN, chain.length(), pemCertChain);
        return STATUS_UNSUPPORTED_CERT_FORMAT;
    }

    dcap::pckparser::CrlStore rootCaCrl, intermediateCrl;
    if(!rootCaCrl.parse(crls[0]))
    {
        LOG_ERROR("rootCaCrl parsing failed. RootCaCrl: {}", crls[0]);
        return STATUS_SGX_CRL_UNSUPPORTED_FORMAT;
    }

    if(!intermediateCrl.parse(crls[1]))
    {
        LOG_ERROR("IntermediateCaCrl parsing failed. IntermediateCaCrl: {}", crls[1]);
        return STATUS_SGX_CRL_UNSUPPORTED_FORMAT;
    }

    try
    {
        auto rootCa = dcap::parser::x509::Certificate::parse(pemRootCaCertificate);
        return dcap::PckCertVerifier{}.verify(chain, rootCaCrl, intermediateCrl, rootCa, currentTime);
    }
    catch (const dcap::parser::FormatException& ex)
    {
        LOG_ERROR("Trusted RootCA parsing failed: {}", ex.what());
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

    dcap::pckparser::CrlStore x509Crl;
    if(!x509Crl.parse(crl))
    {
        return STATUS_SGX_CRL_UNSUPPORTED_FORMAT;
    }

    dcap::CertificateChain chain;
    const auto status = chain.parse(pemCACertChain);
    if (status != STATUS_OK)
    {
        return STATUS_SGX_CA_CERT_UNSUPPORTED_FORMAT;
    }

    try
    {
        auto trustedRootCACert = dcap::parser::x509::Certificate::parse(pemTrustedRootCaCert);
        return dcap::PckCrlVerifier{}.verify(x509Crl, chain, trustedRootCACert);
    }
    catch (const dcap::parser::FormatException&)
    {
        return STATUS_TRUSTED_ROOT_CA_UNSUPPORTED_FORMAT;
    }
    catch (const dcap::parser::InvalidExtensionException&)
    {
        return STATUS_TRUSTED_ROOT_CA_UNSUPPORTED_FORMAT;
    }
}

Status sgxAttestationVerifyTCBInfo(const char *tcbInfo, const char *pemCertChain, const char *stringRootCaCrl,
        const char *pemRootCaCertificate, const time_t* expirationDate)
{
    time_t currentTime;
    try
    {
        currentTime = dcap::getCurrentTime(expirationDate);
    }
    catch (const std::runtime_error&)
    {
        LOG_ERROR("Can't get current time or it was not provided");
        return STATUS_INVALID_PARAMETER;
    }

    if(!tcbInfo ||
       !pemCertChain ||
       !stringRootCaCrl ||
       !pemRootCaCertificate)
    {
        LOG_ERROR("TcbInfo, pemCertChain, stringRootCaCrl, pemRootCaCertificate was not provided");
        return STATUS_UNSUPPORTED_CERT_FORMAT;
    }

    dcap::parser::json::TcbInfo tcbInfoJson;
    try
    {
        tcbInfoJson = dcap::parser::json::TcbInfo::parse(tcbInfo);
    }
    catch (const dcap::parser::FormatException& ex)
    {
        LOG_ERROR("TcbInfo format error: {}, tcbInfo: {}", ex.what(), tcbInfo);
        return STATUS_SGX_TCB_INFO_UNSUPPORTED_FORMAT;
    }
    catch (const dcap::parser::InvalidExtensionException& ex)
    {
        LOG_ERROR("TcbInfo invalid extension error: {}, tcbInfo: {}", ex.what(), tcbInfo);
        return STATUS_SGX_TCB_INFO_INVALID;
    }

    dcap::CertificateChain chain;
    const auto status = chain.parse(pemCertChain);
    if (status != STATUS_OK)
    {
        LOG_ERROR("TCBInfo Signing chain parse error: {}", status);
        return status;
    }

    if(chain.length() != EXPECTED_CERTIFICATE_COUNT_IN_TCB_CHAIN)
    {
        LOG_ERROR("TCBInfo Signing chain length is not correct. Expected: {}, actual: {}, cert chain: {}",
                  EXPECTED_CERTIFICATE_COUNT_IN_TCB_CHAIN, chain.length(), pemCertChain);
        return STATUS_UNSUPPORTED_CERT_FORMAT;
    }

    dcap::pckparser::CrlStore rootCaCrl;
    if(!rootCaCrl.parse(stringRootCaCrl))
    {
        LOG_ERROR("RootCA CRL parsing failed. CRL: {}", stringRootCaCrl);
        return STATUS_SGX_CRL_UNSUPPORTED_FORMAT;
    }

    try
    {
        auto trustedRootCa = dcap::parser::x509::Certificate::parse(pemRootCaCertificate);
        return dcap::TCBInfoVerifier{}.verify(tcbInfoJson, chain, rootCaCrl, trustedRootCa, currentTime);
    }
    catch (const dcap::parser::FormatException& ex)
    {
        LOG_ERROR("Trusted RootCA parsing failed: {}", ex.what());
        return STATUS_UNSUPPORTED_CERT_FORMAT;
    }
    catch (const dcap::parser::InvalidExtensionException& ex)
    {
        LOG_ERROR("Trusted RootCA parsing failed: {}", ex.what());
        return STATUS_SGX_ROOT_CA_INVALID_EXTENSIONS;
    }
}

Status sgxAttestationVerifyEnclaveIdentity(const char *enclaveIdentityString, const char *pemCertChain, const char *stringRootCaCrl,
        const char *pemRootCaCertificate, const time_t* expirationDate)
{
    time_t currentTime;
    try
    {
        currentTime = dcap::getCurrentTime(expirationDate);
    }
    catch (const std::runtime_error&)
    {
        LOG_ERROR("Can't get current time or it was not provided");
        return STATUS_INVALID_PARAMETER;
    }

    if(!enclaveIdentityString ||
       !pemCertChain ||
       !stringRootCaCrl ||
       !pemRootCaCertificate)
    {
        LOG_ERROR("enclaveIdentityString, pemCertChain, stringRootCaCrl, pemRootCaCertificate was not provided");
        return STATUS_UNSUPPORTED_CERT_FORMAT;
    }

    dcap::EnclaveIdentityParser parser;
    std::unique_ptr<dcap::EnclaveIdentityV2> enclaveIdentity;
    try
    {
        enclaveIdentity = parser.parse(enclaveIdentityString);
    }
    catch (const dcap::ParserException &e)
    {
        return e.getStatus();
    }

    dcap::CertificateChain chain;
    const auto status = chain.parse(pemCertChain);
    if(status != STATUS_OK)
    {
        LOG_ERROR("TCBInfo Signing chain parse error: {}", status);
        return status;
    }

    if(chain.length() != EXPECTED_CERTIFICATE_COUNT_IN_TCB_CHAIN)
    {
        LOG_ERROR("TCBInfo Signing chain length is not correct. Expected: {}, actual: {}, cert chain: {}",
                  EXPECTED_CERTIFICATE_COUNT_IN_TCB_CHAIN, chain.length(), pemCertChain);
        return STATUS_UNSUPPORTED_CERT_FORMAT;
    }

    dcap::pckparser::CrlStore rootCaCrl;
    if(!rootCaCrl.parse(stringRootCaCrl))
    {
        LOG_ERROR("RootCA CRL parsing failed. CRL: {}", stringRootCaCrl);
        return STATUS_SGX_CRL_UNSUPPORTED_FORMAT;
    }

    try
    {
        auto trustedRootCa = dcap::parser::x509::Certificate::parse(pemRootCaCertificate);
        return dcap::EnclaveIdentityVerifier{}.verify(*enclaveIdentity, chain, rootCaCrl, trustedRootCa, currentTime);
    }
    catch (const dcap::parser::FormatException& ex)
    {
        LOG_ERROR("Trusted RootCA parsing failed: {}", ex.what());
        return STATUS_UNSUPPORTED_CERT_FORMAT;
    }
    catch (const dcap::parser::InvalidExtensionException& ex)
    {
        LOG_ERROR("Trusted RootCA parsing failed: {}", ex.what());
        return STATUS_SGX_ROOT_CA_INVALID_EXTENSIONS;
    }
}

Status sgxAttestationVerifyQuote(const uint8_t* rawQuote, uint32_t quoteSize, const char *pemPckCertificate, const char* pckCrl,
                                 const char* tcbInfoJson, const char* qeIdentityJson)
{
    /// 4.1.2.4.1
    if(!rawQuote ||
       !pemPckCertificate ||
       !pckCrl ||
       !tcbInfoJson)
    {
        LOG_ERROR("rawQuote, pemPckCertificate, pckCrl, tcbInfoJson was not provided");
        return STATUS_MISSING_PARAMETERS;
    }
   
    // We totally trust user on this, it should be explicitly and clearly
    // mentioned in doc, is there any max quote len other than numeric_limit<uint32_t>::max() ?
    const std::vector<uint8_t> vecQuote(rawQuote, std::next(rawQuote, quoteSize));

    /// 4.1.2.4.2
    dcap::Quote quote;
    if(!quote.parse(vecQuote) || !quote.validate())
    {
        LOG_ERROR("Quote format verification failure");
        return Status::STATUS_UNSUPPORTED_QUOTE_FORMAT;
    }

    /// 4.1.2.4.5
    dcap::pckparser::CrlStore pckCrlStore;
    if(!pckCrlStore.parse(pckCrl))
    {
        LOG_ERROR("PCK Revocation list is invalid. pckCrl: {}", pckCrl);
        return STATUS_UNSUPPORTED_PCK_RL_FORMAT;
    }

    /// 4.1.2.4.8
    dcap::parser::json::TcbInfo tcbInfo;
    try
    {
        tcbInfo = dcap::parser::json::TcbInfo::parse(tcbInfoJson);
    }
    catch (const dcap::parser::FormatException& ex)
    {
        LOG_ERROR("TcbInfo format error: {}", ex.what());
        return STATUS_UNSUPPORTED_TCB_INFO_FORMAT;
    }
    catch (const dcap::parser::InvalidExtensionException& ex)
    {
        LOG_ERROR("TcbInfo invalid extension error: {}", ex.what());
        return STATUS_UNSUPPORTED_TCB_INFO_FORMAT;
    }

    dcap::EnclaveIdentityParser parser;
    std::unique_ptr<dcap::EnclaveIdentityV2> enclaveIdentity;
    if (qeIdentityJson != nullptr)
    {
        try {
            enclaveIdentity = parser.parse(qeIdentityJson);
        }
        catch (const dcap::ParserException& ex)
        {
            LOG_ERROR("Enclave Identity parsing error: {}", ex.what());
            return STATUS_UNSUPPORTED_QE_IDENTITY_FORMAT;
        }
    }

    try
    {
        auto pckCert = dcap::parser::x509::PckCertificate::parse(pemPckCertificate);
        return dcap::QuoteVerifier{}.verify(quote, pckCert, pckCrlStore, tcbInfo, enclaveIdentity.get(), dcap::EnclaveReportVerifier());
    }
    catch (const dcap::parser::FormatException& ex) /// 4.1.2.4.3
    {
        LOG_ERROR("PCK Certificate format error: {}", ex.what());
        return STATUS_UNSUPPORTED_PCK_CERT_FORMAT;
    }
    catch (const dcap::parser::InvalidExtensionException& ex) /// 4.1.2.4.4
    {
        LOG_ERROR("PCK Certificate invalid extension error: {}", ex.what());
        return STATUS_INVALID_PCK_CERT;
    }
}

Status sgxAttestationVerifyEnclaveReport(const uint8_t* enclaveReport, const char* enclaveIdentity)
{
    if(!enclaveReport || !enclaveIdentity)
    {
        LOG_ERROR("enclaveReport, enclaveIdentity was not provided");
        return STATUS_SGX_ENCLAVE_REPORT_UNSUPPORTED_FORMAT;
    }

    /// 4.1.2.9.1
    const std::vector<uint8_t> vecEnclaveReport(enclaveReport, enclaveReport + dcap::constants::ENCLAVE_REPORT_BYTE_LEN);
    dcap::EnclaveReport eReport{};
    auto from = vecEnclaveReport.cbegin();
    auto end = vecEnclaveReport.cend();
    if (!dcap::copyAndAdvance(eReport,
                                     from,
                                     dcap::constants::ENCLAVE_REPORT_BYTE_LEN,
                                     end))
    {
        LOG_ERROR("Enclave Report parsing as binary data representation failure");
        return STATUS_SGX_ENCLAVE_REPORT_UNSUPPORTED_FORMAT;
    }

    if(from != end)
    {
        LOG_ERROR("Enclave Report parsing as binary data representation failure. EnclaveReport could not be iterated through {} bytes", end - from);
        return STATUS_SGX_ENCLAVE_REPORT_UNSUPPORTED_FORMAT;
    }

    /// 4.1.2.9.2
    dcap::EnclaveIdentityParser parser;
    std::unique_ptr<dcap::EnclaveIdentityV2> enclaveIdentityParsed;
    try
    {
        enclaveIdentityParsed = parser.parse(enclaveIdentity);
    }
    catch(const dcap::ParserException &ex)
    {
        LOG_ERROR("Enclave identity parsing error: {}", ex.what());
        return ex.getStatus();
    }

    return dcap::EnclaveReportVerifier{}.verify(enclaveIdentityParsed.get(), eReport);
}

Status sgxAttestationGetQECertificationDataSize(
        const uint8_t *rawQuote,
        uint32_t quoteSize,
        uint32_t *qeCertificationDataSize)
{
    if(!rawQuote ||
       !qeCertificationDataSize)
    {
        LOG_ERROR("Quote or output pointer for size was not provided.");
        return STATUS_MISSING_PARAMETERS;
    }

    // We totally trust user on this, it should be explicitly and clearly
    // mentioned in doc, is there any max quote len other than numeric_limit<uint32_t>::max() ?
    const std::vector<uint8_t> vecQuote(rawQuote, std::next(rawQuote, quoteSize));

    dcap::Quote quote;
    if(!quote.parse(vecQuote) || !quote.validate())
    {
        LOG_ERROR("Can't parse or validate quote");
        return Status::STATUS_UNSUPPORTED_QUOTE_FORMAT;
    }

    *qeCertificationDataSize = static_cast<uint32_t>(quote.getCertificationData().parsedDataSize);

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
        LOG_ERROR("Quote, certifation data or certification date type was not provided");
        return STATUS_MISSING_PARAMETERS;
    }

    // We totally trust user on this, it should be explicitly and clearly
    // mentioned in doc, is there any max quote len other than numeric_limit<uint32_t>::max() ?
    const std::vector<uint8_t> vecQuote(rawQuote, std::next(rawQuote, quoteSize));

    dcap::Quote quote;

    if(!quote.parse(vecQuote) || !quote.validate())
    {
        LOG_ERROR("Can't parse or validate quote");
        return STATUS_UNSUPPORTED_QUOTE_FORMAT;
    }

    const auto& quoteCertificationData = quote.getCertificationData();

    if(qeCertificationDataSize != quoteCertificationData.parsedDataSize)
    {
        LOG_ERROR("Provided certification data size doesn't match one in quote");
        return STATUS_INVALID_QE_CERTIFICATION_DATA_SIZE;
    }

    *qeCertificationDataType = quoteCertificationData.type;

    // buffer pointed to by 'qeCertificationData' must be at least 'qeCertificationDataSize' long
    std::copy(std::begin(quoteCertificationData.data), std::end(quoteCertificationData.data), qeCertificationData);

    return STATUS_OK;
}


void sgxAttestationLoggerSetup(const char *name, const char *consoleLogLevel, const char *fileLogLevel,
                               const char *fileName, const char *pattern)
{
#ifndef SGX_LOGS
    // suppress unused variable warning when building enclave
    (void)name;
    (void)consoleLogLevel;
    (void)fileLogLevel;
    (void)fileName;
    (void)pattern;
#endif
#ifdef SGX_LOGS
    logger::init(name, consoleLogLevel, fileLogLevel, fileName, pattern);
#endif
}

void sgxAttestationLoggerSetCustomField(const char *key, const char *value)
{
#ifndef SGX_LOGS
    // suppress unused variable warning when building enclave
    (void)key;
    (void)value;
#endif
#ifdef SGX_LOGS
    logger::setCustomField(key, value);
#endif
}