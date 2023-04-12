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

#include "QuoteV5Generator.h"
#include "QuoteUtils.h"
#include <type_traits>
#include <algorithm>

namespace intel { namespace sgx { namespace dcap { namespace test {

namespace {

class ConvertToBytesDetail
{
public:
    template<class DataType>
    static Bytes convert(const DataType& data)
    {
        return ensureIntegersAreLittleEndian<DataType>(toBytes(data));
    }

private:
    static bool isSystemLittleEndian()
    {
        uint32_t i = 0x01020304;
        return reinterpret_cast<char*>(&i)[0] == 4;
    }

    template<class DataType>
    static typename std::enable_if<!std::is_integral<DataType>::value, Bytes>::type ensureIntegersAreLittleEndian(Bytes bytes)
    {
        return bytes;
    }

    template<class DataType>
    static typename std::enable_if<std::is_integral<DataType>::value, Bytes>::type ensureIntegersAreLittleEndian(Bytes bytes)
    {
        if (!isSystemLittleEndian())
        {
            std::reverse(bytes.begin(), bytes.end());
        }
        return bytes;
    }
};

template<class DataType>
Bytes convertToBytes(DataType& data)
{
    return ConvertToBytesDetail::convert(data);
}

constexpr uint16_t DEFAULT_VERSION = 5;
constexpr uint16_t DEFAULT_BODY_TYPE = 1;
constexpr uint16_t DEFAULT_ATTESTATION_KEY_TYPE = 2;
constexpr char INTEL_QE_VENDOR_UUID[] = "939A7233F79C4CA9940A0DB3957F0607";

QuoteV5Generator::EnclaveReport defaultEnclaveReport()
{
    return {
            {}, //cpusvn
            0,  //miscselect
            {}, //reserved1
            {}, //attributes
            {}, //mrenclave
            {}, //reserved2
            {}, //mrsigner
            {}, //reserved3
            0,  //isvProdId
            0,  //isvSvn
            {}, //reserved4
            {}  //reportdata
    };
}

QuoteV5Generator::QuoteHeader defaultHeader()
{
    return {
            DEFAULT_VERSION,
            DEFAULT_ATTESTATION_KEY_TYPE,
            0,
            0,
            {{0}},
            {{0}}
    };
}

QuoteV5Generator::QuoteBody defaultBody()
{
    return {
            DEFAULT_BODY_TYPE,
            ENCLAVE_REPORT_SIZE,
    };
}

QuoteV5Generator::EcdsaSignature defaultSignature()
{
    QuoteV5Generator::EcdsaSignature ret{{{0}} };
    return ret;
}

QuoteV5Generator::EcdsaPublicKey defaultPubKey()
{
    return {
        {{0}}
    };
}

QuoteV5Generator::QEReportCertificationData defaultQEReportCertificationData()
{
    return {
            defaultEnclaveReport(),
            defaultSignature(),
            {},
            {}
    };
}

QuoteV5Generator::CertificationData defaultCertificationData()
{
    auto qEReportCertificationData = defaultQEReportCertificationData().bytes();
    return {
        6,
        static_cast<uint32_t>(qEReportCertificationData.size()),
        qEReportCertificationData
    };
}

} //anonymous namespace

QuoteV5Generator::QuoteV5Generator() :
        header(defaultHeader()),
        body(defaultBody()),
        enclaveReport(defaultEnclaveReport()),
        quoteAuthData{
                test::QUOTE_V4_AUTH_DATA_MIN_SIZE,
                defaultSignature(),
                defaultPubKey(),
                defaultCertificationData()
        }
{
    static_assert(sizeof(QuoteHeader) == QUOTE_HEADER_SIZE, "Incorrect header size");
    static_assert(sizeof(QuoteBody) == QUOTE_BODY_SIZE + 2 /* padding */, "Incorrect body size");
    static_assert(sizeof(EnclaveReport) == ENCLAVE_REPORT_SIZE, "Incorrect enclave report size");
    static_assert(sizeof(TDReport10) == TD_REPORT_10_SIZE, "Incorrect TD report 1.0 size");
    static_assert(sizeof(TDReport15) == TD_REPORT_15_SIZE, "Incorrect TD report 1.5 size");
    static_assert(sizeof(EcdsaSignature) == ENCLAVE_REPORT_SIGNATURE_SIZE, "Incorrect enclave report signature size");
    static_assert(sizeof(EcdsaPublicKey) == ECDSA_PUBLIC_KEY_SIZE, "Incorrect public key size");

    auto uuid = hexStringToBytes(INTEL_QE_VENDOR_UUID);
    std::copy(uuid.begin(), uuid.end(), header.qeVendorId.begin());
}

QuoteV5Generator& QuoteV5Generator::withHeader(const QuoteHeader& _header)
{
    this->header = _header;
    return *this;
}

QuoteV5Generator& QuoteV5Generator::withBody(const QuoteBody& _body)
{
    this->body = _body;
    return *this;
}

QuoteV5Generator& QuoteV5Generator::withEnclaveReport(const EnclaveReport& _body)
{
    this->enclaveReport = _body;
    return *this;
}

QuoteV5Generator& QuoteV5Generator::withTDReport10(const TDReport10& _body)
{
    this->tdReport10 = _body;
    return *this;
}

QuoteV5Generator& QuoteV5Generator::withTDReport15(const TDReport15& _body)
{
    this->tdReport15 = _body;
    return *this;
}

QuoteV5Generator& QuoteV5Generator::withQuoteSignature(const EcdsaSignature& signature)
{
    quoteAuthData.ecdsaSignature = signature;
    return *this; 
}

QuoteV5Generator& QuoteV5Generator::withAttestationKey(const EcdsaPublicKey& pubKey)
{
    quoteAuthData.ecdsaAttestationKey = pubKey;
    return *this;
}

QuoteV5Generator& QuoteV5Generator::withAuthDataSize(const uint32_t authDataSize)
{
    quoteAuthData.authDataSize = authDataSize;
    return *this;
}

QuoteV5Generator& QuoteV5Generator::withAuthData(const QuoteV5Generator::QuoteAuthData& authData)
{
    quoteAuthData = authData;
    return *this;
}

QuoteV5Generator& QuoteV5Generator::withCertificationData(const CertificationData& certificationData)
{
    quoteAuthData.certificationData = certificationData;
    return *this;
}

QuoteV5Generator& QuoteV5Generator::withCertificationData(uint16_t type, const Bytes& keyData)
{
    quoteAuthData.certificationData.keyDataType = type;
    quoteAuthData.certificationData.keyData = keyData;
    quoteAuthData.certificationData.size = static_cast<uint32_t>(keyData.size());
    return *this;
}

Bytes QuoteV5Generator::buildSgxQuote()
{
	return header.bytes() + body.bytes() + enclaveReport.bytes() + quoteAuthData.bytes();
}

Bytes QuoteV5Generator::buildTdx10Quote()
{
    return header.bytes() + body.bytes() + tdReport10.bytes() + quoteAuthData.bytes();
}

Bytes QuoteV5Generator::buildTdx15Quote()
{
    return header.bytes() + body.bytes() + tdReport15.bytes() + quoteAuthData.bytes();
}

Bytes QuoteV5Generator::QuoteHeader::bytes() const
{
    return
            convertToBytes(version) +
            convertToBytes(attestationKeyType) +
            convertToBytes(teeType) +
            convertToBytes(reserved) +
            convertToBytes(qeVendorId) +
            convertToBytes(userData);
}

Bytes QuoteV5Generator::QuoteBody::bytes() const
{
    return
            convertToBytes(type) +
            convertToBytes(size);
}

Bytes QuoteV5Generator::EnclaveReport::bytes() const
{
    return
        convertToBytes(cpuSvn) +
        convertToBytes(miscSelect) +
        convertToBytes(reserved1) +
        convertToBytes(attributes) +
        convertToBytes(mrEnclave) +
        convertToBytes(reserved2) +
        convertToBytes(mrSigner) +
        convertToBytes(reserved3) +
        convertToBytes(isvProdID) +
        convertToBytes(isvSvn) +
        convertToBytes(reserved4) +
        convertToBytes(reportData);
}

Bytes QuoteV5Generator::TDReport10::bytes() const
{
    return
        convertToBytes(teeTcbSvn) +
        convertToBytes(mrSeam) +
        convertToBytes(mrSignerSeam) +
        convertToBytes(seamAttributes) +
        convertToBytes(tdAttributes) +
        convertToBytes(xFAM) +
        convertToBytes(mrTd) +
        convertToBytes(mrConfigId) +
        convertToBytes(mrOwner) +
        convertToBytes(mrOwnerConfig) +
        convertToBytes(rtMr0) +
        convertToBytes(rtMr1) +
        convertToBytes(rtMr2) +
        convertToBytes(rtMr3) +
        convertToBytes(reportData);
}

Bytes QuoteV5Generator::TDReport15::bytes() const {
    return
            TDReport10::bytes() +
            convertToBytes(teeTcbSvn2) +
            convertToBytes(mrServiceTd);
}

Bytes QuoteV5Generator::QuoteAuthData::bytes() const
{
    return
        convertToBytes(authDataSize) +
        ecdsaSignature.bytes() +
        ecdsaAttestationKey.bytes() +
        certificationData.bytes();
}

Bytes QuoteV5Generator::QEReportCertificationData::bytes() const
{
    return
        qeReport.bytes() +
        qeReportSignature.bytes() +
        qeAuthData.bytes() +
        certificationData.bytes();
}

Bytes QuoteV5Generator::EcdsaSignature::bytes() const
{
    return convertToBytes(signature);
}

Bytes QuoteV5Generator::EcdsaPublicKey::bytes() const
{
    return convertToBytes(publicKey);
}

Bytes QuoteV5Generator::QeAuthData::bytes() const
{
    return convertToBytes(size) + data;
}

Bytes QuoteV5Generator::CertificationData::bytes() const
{
    return convertToBytes(keyDataType) + convertToBytes(size) + keyData;
}

}}}}
