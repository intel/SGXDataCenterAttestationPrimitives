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

#include "Quote.h"
#include "QuoteParsers.h"
#include "Utils/Logger.h"

#include <algorithm>
#include <iterator>

namespace intel { namespace sgx { namespace dcap {
using namespace constants;

bool Quote::parse(const std::vector<uint8_t>& rawQuote)
{
    if(rawQuote.size() < QUOTE_MIN_BYTE_LEN)
    {
        LOG_ERROR("Quote size {} is not at least {}.", rawQuote.size(), QUOTE_MIN_BYTE_LEN);
        return false;
    }

    auto from = rawQuote.cbegin();
    Header localHeader{};
    if (!copyAndAdvance(localHeader, from, HEADER_BYTE_LEN, rawQuote.cend())) {
        LOG_ERROR("Can't read header from quote. Expected size: {}", HEADER_BYTE_LEN);
        return false;
    }

    header = localHeader;

    Body localBody{};
    EnclaveReport localEnclaveReport{};
    TDReport10 localTdReport10{};
    TDReport15 localTdReport15{};

    if (localHeader.version > constants::QUOTE_VERSION_4)
    {
        if (!copyAndAdvance(localBody, from, BODY_BYTE_SIZE, rawQuote.end()))
        {
            LOG_ERROR("Can't read SGX report body from quote. Expected size: {}", BODY_BYTE_SIZE);
            return false;
        }

        switch (localBody.bodyType) {
            case BODY_SGX_ENCLAVE_REPORT_TYPE: // SGX Enclave Report
                if (localBody.size != ENCLAVE_REPORT_BYTE_LEN)
                {
                    LOG_ERROR("Unexpected SGX enclave report size. Expected size: {}", ENCLAVE_REPORT_BYTE_LEN);
                    return false;
                }
                if (!copyAndAdvance(localEnclaveReport, from, ENCLAVE_REPORT_BYTE_LEN, rawQuote.end()))
                {
                    LOG_ERROR("Can't read SGX enclave report from quote. Expected size: {}", ENCLAVE_REPORT_BYTE_LEN);
                    return false;
                }
                signedData = getDataToSignatureVerification(rawQuote, HEADER_BYTE_LEN + BODY_BYTE_SIZE + QE_REPORT_BYTE_LEN);
                break;
            case BODY_TD_REPORT10_TYPE: // TD Report for TDX 1.0
                if (localBody.size != TD_REPORT10_BYTE_LEN)
                {
                    LOG_ERROR("Unexpected TDX TD Report 1.0 size. Expected size: {}", TD_REPORT10_BYTE_LEN);
                    return false;
                }
                if (!copyAndAdvance(localTdReport10, from, TD_REPORT10_BYTE_LEN, rawQuote.end()))
                {
                    LOG_ERROR("Can't read TDX TD Report 1.0 from quote. Expected size: {}", TD_REPORT10_BYTE_LEN);
                    return false;
                }
                signedData = getDataToSignatureVerification(rawQuote, HEADER_BYTE_LEN + BODY_BYTE_SIZE + TD_REPORT10_BYTE_LEN);
                break;
            case BODY_TD_REPORT15_TYPE: // TD Report for TDX 1.5
                if (localBody.size != TD_REPORT15_BYTE_LEN)
                {
                    LOG_ERROR("Unexpected TDX TD Report 1.5 size. Expected size: {}", TD_REPORT15_BYTE_LEN);
                    return false;
                }
                if (!copyAndAdvance(localTdReport15, from, TD_REPORT15_BYTE_LEN, rawQuote.end()))
                {
                    LOG_ERROR("Can't read TDX TD Report 1.5 from quote. Expected size: {}", TD_REPORT10_BYTE_LEN);
                    return false;
                }
                signedData = getDataToSignatureVerification(rawQuote, HEADER_BYTE_LEN + BODY_BYTE_SIZE + TD_REPORT15_BYTE_LEN);
                break;
            default: // Unknown body type
                return false;
        }
    }
    else
    {
        if (localHeader.teeType == TEE_TYPE_SGX)
        {
            if (!copyAndAdvance(localEnclaveReport, from, ENCLAVE_REPORT_BYTE_LEN, rawQuote.end()))
            {
                LOG_ERROR("Can't read SGX enclave report from quote. Expected size: {}", ENCLAVE_REPORT_BYTE_LEN);
                return false;
            }
            signedData = getDataToSignatureVerification(rawQuote, HEADER_BYTE_LEN + QE_REPORT_BYTE_LEN);
        }
        else if (localHeader.teeType == TEE_TYPE_TDX)
        {
            if (!copyAndAdvance(localTdReport10, from, TD_REPORT10_BYTE_LEN, rawQuote.end()))
            {
                LOG_ERROR("Can't read TDX TD Report 1.0 from quote. Expected size: {}", TD_REPORT10_BYTE_LEN);
                return false;
            }
            signedData = getDataToSignatureVerification(rawQuote, HEADER_BYTE_LEN + TD_REPORT10_BYTE_LEN);
        }
    }

    uint32_t localAuthDataSize = 0;
    if (!copyAndAdvance(localAuthDataSize, from, rawQuote.end())) {
        LOG_ERROR("Can't read auth data size  from quote.");
        return false;
    }
    const auto remainingDistance = std::distance(from, rawQuote.end());
    if(localAuthDataSize > remainingDistance)
    {
        LOG_ERROR("Declared auth data size {} is bigger than remaining buffer size {}", localAuthDataSize, remainingDistance);
        return false;
    }

    Ecdsa256BitQuoteV3AuthData localQuoteV3Auth{};
    Ecdsa256BitQuoteV4AuthData localQuoteV4Auth{};
    if (localHeader.version == constants::QUOTE_VERSION_3)
    {
        if (!copyAndAdvance(localQuoteV3Auth, from, static_cast<size_t>(localAuthDataSize), rawQuote.end()))
        {
            LOG_ERROR("Can't read QUOTE v3 Auth data. Expected size: {}", localAuthDataSize);
            return false;
        }
        qeReportSignature = localQuoteV3Auth.qeReportSignature.signature;
        qeReport = localQuoteV3Auth.qeReport;
        attestKeyData = localQuoteV3Auth.ecdsaAttestationKey.pubKey;
        qeAuthData = localQuoteV3Auth.qeAuthData.data;
        certificationData = localQuoteV3Auth.certificationData;
        quoteSignature = localQuoteV3Auth.ecdsa256BitSignature.signature;
    }
    else if (localHeader.version > constants::QUOTE_VERSION_3)
    {
        if (!copyAndAdvance(localQuoteV4Auth, from, static_cast<size_t>(localAuthDataSize), rawQuote.end()))
        {
            LOG_ERROR("Can't read QUOTE v4 Auth data. Expected size: {}", localAuthDataSize);
            return false;
        }
        
        const auto reportBytes = localQuoteV4Auth.certificationData.data;
        auto beg = reportBytes.cbegin();
        QEReportCertificationData qeReportData;
        if (!qeReportData.insert(beg, reportBytes.cend()))
        {
            return false;
        }
        qeReportSignature = qeReportData.qeReportSignature.signature;
        qeReport = qeReportData.qeReport;
        qeAuthData = qeReportData.qeAuthData.data;
        attestKeyData = localQuoteV4Auth.ecdsaAttestationKey.pubKey;
        certificationData = qeReportData.certificationData;
        quoteSignature = localQuoteV4Auth.ecdsa256BitSignature.signature;
    }

    body = localBody;
    enclaveReport = localEnclaveReport;
    tdReport10 = localTdReport10;
    tdReport15 = localTdReport15;
    authDataSize = localAuthDataSize;
    authDataV3 = localQuoteV3Auth;
    authDataV4 = localQuoteV4Auth;

    return true;
}

bool Quote::validate() const
{
    if(std::find(ALLOWED_QUOTE_VERSIONS.begin(), ALLOWED_QUOTE_VERSIONS.end(), header.version) ==
       ALLOWED_QUOTE_VERSIONS.end())
    {
        LOG_ERROR("Quote version {} is not supported", header.version);
        return false;
    }

    if(std::find(ALLOWED_ATTESTATION_KEY_TYPES.begin(), ALLOWED_ATTESTATION_KEY_TYPES.end(), header.attestationKeyType) ==
       ALLOWED_ATTESTATION_KEY_TYPES.end())
    {
        LOG_ERROR("Attestation Key type {} is not supported", header.attestationKeyType);
        return false;
    }

    if(std::find(ALLOWED_TEE_TYPES.begin(), ALLOWED_TEE_TYPES.end(), header.teeType) == ALLOWED_TEE_TYPES.end())
    {
        LOG_ERROR("TEE Type {} is not supported", header.teeType);
        return false;
    }

    if(header.qeVendorId != INTEL_QE_VENDOR_ID) {
        LOG_ERROR("Wrong QE vendor ID. Found: {}, expected: {}", header.qeVendorId, INTEL_QE_VENDOR_ID);
        return false;
    }

    if (header.version == QUOTE_VERSION_3)
    {
        if (header.teeType != TEE_TYPE_SGX)
        {
            LOG_ERROR("Quote v3 supports only SGX tee type but found {}", header.teeType);
            return false;
        }
        if (authDataV3.certificationData.type < 1 || authDataV3.certificationData.type > 5) // QuoteV3 supports only 1-5 types
        {
            LOG_ERROR("Quote v3 supports certification data types from 1 to 5 but found {}",
                      authDataV3.certificationData.type);
            return false;
        }
    }

    if(header.version == QUOTE_VERSION_4 || header.version == QUOTE_VERSION_5)
    {
        if (authDataV4.certificationData.type != constants::PCK_ID_QE_REPORT_CERTIFICATION_DATA)
        {
            LOG_ERROR("Quote v4 supports only {} certification data type but found {}",
                      constants::PCK_ID_QE_REPORT_CERTIFICATION_DATA, authDataV4.certificationData.type);
            return false;
        }
        if (certificationData.type < 1 || certificationData.type > 5)
        {
            LOG_ERROR("Quote v4 supports QE Report Certification data types from 1 to 5 but found: {}",
                      certificationData.type);
            return false;
        }
    }

    if (header.version == QUOTE_VERSION_5)
    {
        if(std::find(ALLOWED_BODY_TYPES.begin(), ALLOWED_BODY_TYPES.end(), body.bodyType) ==
           ALLOWED_BODY_TYPES.end())
        {
            return false;
        }

        if (header.teeType == TEE_TYPE_SGX && body.bodyType != BODY_SGX_ENCLAVE_REPORT_TYPE)
        {
            return false;
        }

        if (header.teeType != TEE_TYPE_SGX && body.bodyType == BODY_SGX_ENCLAVE_REPORT_TYPE)
        {
            return false;
        }
    }

    return true;
}

const Header& Quote::getHeader() const
{
    return header;
}

const Body& Quote::getBody() const
{
    return body;
}

const EnclaveReport& Quote::getEnclaveReport() const
{
    return enclaveReport;
}

const TDReport10& Quote::getTdReport10() const
{
    return tdReport10;
}

const TDReport15& Quote::getTdReport15() const
{
    return tdReport15;
}

uint32_t Quote::getAuthDataSize() const
{
    return authDataSize;
}

const std::vector<uint8_t>& Quote::getSignedData() const
{
    return signedData;
}

const Ecdsa256BitQuoteV3AuthData& Quote::getAuthDataV3() const
{
    return authDataV3;
}

const Ecdsa256BitQuoteV4AuthData& Quote::getAuthDataV4() const {
    return authDataV4;
}

const std::array<uint8_t, constants::ECDSA_SIGNATURE_BYTE_LEN> &Quote::getQeReportSignature() const {
    return qeReportSignature;
}

const EnclaveReport &Quote::getQeReport() const {
    return qeReport;
}

const std::array<uint8_t, constants::ECDSA_PUBKEY_BYTE_LEN> &Quote::getAttestKeyData() const {
    return attestKeyData;
}

const std::vector<uint8_t> &Quote::getQeAuthData() const {
    return qeAuthData;
}

const CertificationData &Quote::getCertificationData() const {
    return certificationData;
}

const std::array<uint8_t, constants::ECDSA_SIGNATURE_BYTE_LEN> &Quote::getQuoteSignature() const {
    return quoteSignature;
}

const std::array<uint8_t, 16> &Quote::getTeeTcbSvn() const {
    if (header.version == QUOTE_VERSION_4)
    {
        return tdReport10.teeTcbSvn;
    }
    else // Quote V5 and higher
    {
        if (body.bodyType == dcap::constants::BODY_TD_REPORT10_TYPE)
        {
            return tdReport10.teeTcbSvn;
        }
        else
        {
            return tdReport15.teeTcbSvn;
        }
    }
}

const std::array<uint8_t, 48>& Quote::getMrSignerSeam() const
{
    if (header.version == QUOTE_VERSION_4)
    {
        return tdReport10.mrSignerSeam;
    }
    else // Quote V5 and higher
    {
        if (body.bodyType == dcap::constants::BODY_TD_REPORT10_TYPE)
        {
            return tdReport10.mrSignerSeam;
        }
        else
        {
            return tdReport15.mrSignerSeam;
        }
    }
}

const std::array<uint8_t, 8>& Quote::getSeamAttributes() const
{
    if (header.version == QUOTE_VERSION_4)
    {
        return tdReport10.seamAttributes;
    }
    else // Quote V5 and higher
    {
        if (body.bodyType == dcap::constants::BODY_TD_REPORT10_TYPE)
        {
            return tdReport10.seamAttributes;
        }
        else
        {
            return tdReport15.seamAttributes;
        }
    }
}

std::vector<uint8_t> Quote::getDataToSignatureVerification(const std::vector<uint8_t>& rawQuote,
                                                           const std::vector<uint8_t>::difference_type sizeToCopy) const
{
    // private method, we call it at the end of parsing, so
    // here we assume format is valid
    std::vector<uint8_t> ret(rawQuote.begin(), std::next(rawQuote.begin(), sizeToCopy));
    return ret;
}

}}} //namespace intel { namespace sgx { namespace dcap {
