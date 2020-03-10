/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
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
#include "ByteOperands.h"

#include <algorithm>
#include "QuoteConstants.h"

namespace intel { namespace sgx { namespace qvl {

namespace {
using namespace constants;

constexpr size_t HEADER_BYTE_LEN = 48;
constexpr size_t BODY_BYTE_LEN = ENCLAVE_REPORT_BYTE_LEN;
constexpr size_t AUTH_DATA_SIZE_BYTE_LEN = 4;

constexpr size_t ECDSA_SIGNATURE_BYTE_LEN = 64;
constexpr size_t ECDSA_PUBKEY_BYTE_LEN = 64;
constexpr size_t QE_REPORT_BYTE_LEN = ENCLAVE_REPORT_BYTE_LEN;
constexpr size_t QE_REPORT_SIG_BYTE_LEN = ECDSA_SIGNATURE_BYTE_LEN;
constexpr size_t QE_AUTH_DATA_SIZE_BYTE_LEN = 2;
constexpr size_t QE_CERT_DATA_TYPE_BYTE_LEN = 2;
constexpr size_t QE_CERT_DATA_SIZE_BYTE_LEN = 4;

constexpr size_t AUTH_DATA_MIN_BYTE_LEN =
                        ECDSA_SIGNATURE_BYTE_LEN +
                        ECDSA_PUBKEY_BYTE_LEN +
                        QE_REPORT_BYTE_LEN +
                        QE_REPORT_SIG_BYTE_LEN +
                        QE_AUTH_DATA_SIZE_BYTE_LEN +
                        QE_CERT_DATA_TYPE_BYTE_LEN + 
                        QE_CERT_DATA_SIZE_BYTE_LEN;

constexpr size_t QUOTE_MIN_BYTE_LEN = 
                        HEADER_BYTE_LEN +
                        BODY_BYTE_LEN + 
                        AUTH_DATA_SIZE_BYTE_LEN +
                        AUTH_DATA_MIN_BYTE_LEN;

template<typename T>
void copyAndAdvance(T& val, std::vector<uint8_t>::const_iterator& from, size_t amount, const std::vector<uint8_t>::const_iterator& totalEnd)
{
    const auto available = std::distance(from, totalEnd);
	if (available < 0 || (unsigned) available < amount)
	{
		return;
	}
    const auto end = std::next(from, static_cast<long>(amount));
    val.insert(from, end);

}

template<size_t N>
void copyAndAdvance(std::array<uint8_t, N>& arr, std::vector<uint8_t>::const_iterator& from, const std::vector<uint8_t>::const_iterator& totalEnd) 
{
	const auto capacity = std::distance(arr.cbegin(), arr.cend());
	if (std::distance(from, totalEnd) < capacity)
	{
		return;
	}
    const auto end = std::next(from, capacity);      
    std::copy(from, end, arr.begin());
    std::advance(from, capacity);
} 

void copyAndAdvance(uint16_t& val, std::vector<uint8_t>::const_iterator& from, const std::vector<uint8_t>::const_iterator& totalEnd)
{
    const auto available = std::distance(from, totalEnd);
    const auto capacity = sizeof(uint16_t);
	if (available < 0 || (unsigned) available < capacity)
	{
		return;
	}
    
    val = swapBytes(toUint16(*from, *(std::next(from))));
    std::advance(from, capacity);
} 


void copyAndAdvance(uint32_t& val, std::vector<uint8_t>::const_iterator& position, const std::vector<uint8_t>::const_iterator& totalEnd)
{
    const auto available = std::distance(position, totalEnd);
    const auto capacity = sizeof(uint32_t);
	if (available < 0 || (unsigned) available < capacity)
	{
		return;
	}
    
    val = swapBytes(toUint32(*position, *(std::next(position)), *(std::next(position, 2)), *(std::next(position, 3))));
    std::advance(position, capacity);
}

} // anonymous namespace

bool Quote::parse(const std::vector<uint8_t>& rawQuote)
{
    if(rawQuote.size() < QUOTE_MIN_BYTE_LEN)
    {
        return false;
    }

    auto from = rawQuote.cbegin();
    Header localHeader;
    copyAndAdvance(localHeader, from, HEADER_BYTE_LEN, rawQuote.cend());

    EnclaveReport localBody; 
    copyAndAdvance(localBody, from, BODY_BYTE_LEN, rawQuote.cend());  

    uint32_t localAuthDataSize;
    copyAndAdvance(localAuthDataSize, from, rawQuote.cend());
    const auto remainingDistance = std::distance(from, rawQuote.cend());
    if(localAuthDataSize != remainingDistance)
    {
        return false;
    }
	
    Ecdsa256BitQuoteAuthData localQuoteAuth;
    copyAndAdvance(localQuoteAuth, from, static_cast<size_t>(localAuthDataSize), rawQuote.cend());

    // parsing done, we should be precisely at the end of our buffer
    // if we're not it means inconsistency in internal structure
    // and it means invalid format   
    if(from != rawQuote.cend())
    {
        return false;
    }

    header = localHeader;
    body = localBody;
    authDataSize = localAuthDataSize;
    authData = localQuoteAuth;
    signedData = getDataToSignatureVerification(rawQuote);
     
    return true;
}

bool Quote::parseEnclaveReport(const std::vector<uint8_t> &enclaveReport)
{
    if(enclaveReport.size() < qvl::constants::ENCLAVE_REPORT_BYTE_LEN)
    {
        return false;
    }

    EnclaveReport localBody;
    auto from = enclaveReport.cbegin();
    auto end = enclaveReport.cend();
    copyAndAdvance(localBody, from, BODY_BYTE_LEN, end);

    if(from != end)
    {
        return false;
    }

    body = localBody;

    return true;
}

const Quote::Header& Quote::getHeader() const
{
    return header;
}

const Quote::EnclaveReport& Quote::getBody() const
{
    return body;
}

uint32_t Quote::getAuthDataSize() const
{
    return authDataSize;
}

const Quote::Ecdsa256BitQuoteAuthData& Quote::getQuoteAuthData() const
{
    return authData;
}

const std::vector<uint8_t>& Quote::getSignedData() const
{
    return signedData;
}

void Quote::Header::insert(std::vector<uint8_t>::const_iterator& from, const std::vector<uint8_t>::const_iterator& end)
{ 
    copyAndAdvance(version, from, end);
    copyAndAdvance(attestationKeyType, from, end);
    copyAndAdvance(reserved, from, end);
    copyAndAdvance(qeSvn, from, end);
    copyAndAdvance(pceSvn, from, end);
    copyAndAdvance(uuid, from, end);
    copyAndAdvance(userData, from, end);
}

void Quote::EnclaveReport::insert(std::vector<uint8_t>::const_iterator& from, const std::vector<uint8_t>::const_iterator& end)
{    
    copyAndAdvance(cpuSvn, from, end);
    copyAndAdvance(miscSelect, from, end);
    copyAndAdvance(reserved1, from, end);
    copyAndAdvance(attributes, from, end);
    copyAndAdvance(mrEnclave, from, end);
    copyAndAdvance(reserved2, from, end);
    copyAndAdvance(mrSigner, from, end);
    copyAndAdvance(reserved3, from, end);
    copyAndAdvance(isvProdID, from, end);
    copyAndAdvance(isvSvn, from, end);
    copyAndAdvance(reserved4, from, end);
    copyAndAdvance(reportData, from, end); 
}

std::array<uint8_t,384> Quote::EnclaveReport::rawBlob() const
{
    std::array<uint8_t,384> ret;
    auto to = ret.begin();
    std::copy(cpuSvn.begin(), cpuSvn.end(), to);
    std::advance(to, (unsigned) cpuSvn.size());
   
    const auto arrMiscSelect = toArray(swapBytes(miscSelect));
    std::copy(arrMiscSelect.begin(), arrMiscSelect.end(), to);
    std::advance(to, arrMiscSelect.size());

    std::copy(reserved1.begin(), reserved1.end(), to);
    std::advance(to, (unsigned) reserved1.size());

    std::copy(attributes.begin(), attributes.end(), to);
    std::advance(to, (unsigned) attributes.size());

    std::copy(mrEnclave.begin(), mrEnclave.end(), to);
    std::advance(to, (unsigned) mrEnclave.size());

    std::copy(reserved2.begin(), reserved2.end(), to);
    std::advance(to, (unsigned) reserved2.size());

    std::copy(mrSigner.begin(), mrSigner.end(), to);
    std::advance(to, (unsigned) mrSigner.size());

    std::copy(reserved3.begin(), reserved3.end(), to);
    std::advance(to, (unsigned) reserved3.size());

    const auto arrIsvProdId = toArray(swapBytes(isvProdID));
    std::copy(arrIsvProdId.begin(), arrIsvProdId.end(), to);
    std::advance(to, arrIsvProdId.size());

    const auto arrIsvSvn = toArray(swapBytes(isvSvn));
    std::copy(arrIsvSvn.begin(), arrIsvSvn.end(), to);
    std::advance(to, arrIsvSvn.size());

    std::copy(reserved4.begin(), reserved4.end(), to);
    std::advance(to, (unsigned) reserved4.size());

    std::copy(reportData.begin(), reportData.end(), to);
    std::advance(to, (unsigned) reportData.size());

    return ret;
}

void Quote::Ecdsa256BitSignature::insert(std::vector<uint8_t>::const_iterator& from, const std::vector<uint8_t>::const_iterator& end)
{ 
    copyAndAdvance(signature, from, end);
}

void Quote::Ecdsa256BitPubkey::insert(std::vector<uint8_t>::const_iterator& from, const std::vector<uint8_t>::const_iterator& end)
{
    copyAndAdvance(pubKey, from, end);
}

void Quote::QeAuthData::insert(std::vector<uint8_t>::const_iterator& from, const std::vector<uint8_t>::const_iterator& end)
{
    const size_t amount = static_cast<size_t>(std::distance(from, end));
    if(from > end || amount < QE_AUTH_DATA_SIZE_BYTE_LEN)
    {
        return;
    }
   
    this->data.clear();
    copyAndAdvance(parsedDataSize, from, end);

    if(parsedDataSize != amount - QE_AUTH_DATA_SIZE_BYTE_LEN)
    {
        // invalid format
        // moving back pointer
        from = std::prev(from, sizeof(decltype(parsedDataSize)));
        return;
    }

    if(parsedDataSize == 0)
    {
        // all good, parsed size is zero
        // data are cleared and from is moved
        return;
    }

    data.reserve(parsedDataSize);
    std::copy_n(from, parsedDataSize, std::back_inserter(data));
    std::advance(from, parsedDataSize);
}

void Quote::QeCertData::insert(std::vector<uint8_t>::const_iterator& from, const std::vector<uint8_t>::const_iterator& end)
{
    const auto minLen = QE_CERT_DATA_SIZE_BYTE_LEN + QE_CERT_DATA_TYPE_BYTE_LEN;
    const size_t amount = static_cast<size_t>(std::distance(from, end));
    if(from > end || amount < minLen)
    {
        return;
    }
 
    data.clear();
    copyAndAdvance(type, from, end);
    copyAndAdvance(parsedDataSize, from, end);
    if(parsedDataSize != amount - minLen)
    {
        // invalid format, moving back pointer
        from = std::prev(from, sizeof(decltype(type)) + sizeof(decltype(parsedDataSize)));
        return; 
    }

    if(parsedDataSize == 0)
    {
        // all good, parsed size is 0
        // data cleared and pointer moved
        return;
    }

    data.reserve(parsedDataSize);
    std::copy_n(from, parsedDataSize, std::back_inserter(data));
    std::advance(from, parsedDataSize);
}

void Quote::Ecdsa256BitQuoteAuthData::insert(std::vector<uint8_t>::const_iterator& from, const std::vector<uint8_t>::const_iterator& end)
{
    copyAndAdvance(ecdsa256BitSignature, from, ECDSA_SIGNATURE_BYTE_LEN, end);
    copyAndAdvance(ecdsaAttestationKey, from, ECDSA_PUBKEY_BYTE_LEN, end);
    copyAndAdvance(qeReport, from, ENCLAVE_REPORT_BYTE_LEN, end);
    copyAndAdvance(qeReportSignature, from, ECDSA_SIGNATURE_BYTE_LEN, end);
    
    uint16_t authSize = 0;
    copyAndAdvance(authSize, from, end);
    from = std::prev(from, sizeof(uint16_t));
    copyAndAdvance(qeAuthData, from, authSize + sizeof(uint16_t), end);

    uint32_t qeCertSize = 0;
    std::advance(from, sizeof(uint16_t)); // skip type
    copyAndAdvance(qeCertSize, from, end);
    from = std::prev(from, sizeof(uint32_t) + sizeof(uint16_t)); // go back to beg of struct data
    copyAndAdvance(qeCertData, from, qeCertSize + sizeof(uint16_t) + sizeof(uint32_t), end);
}

std::vector<uint8_t> Quote::getDataToSignatureVerification(const std::vector<uint8_t>& rawQuote) const
{
    // private method, we call it at the end of parsing, so
    // here we assume format is valid
     
    const auto sizeToCopy = HEADER_BYTE_LEN + BODY_BYTE_LEN;
    const std::vector<uint8_t> ret(rawQuote.begin(), std::next(rawQuote.begin(), sizeToCopy)); 
    return ret;
}

}}} //namespace intel { namespace sgx { namespace qvl {
