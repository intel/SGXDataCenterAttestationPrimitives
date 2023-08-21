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
#include <QuoteVerification/Quote.h>

#include <gtest/gtest.h>
#include <gmock/gmock-matchers.h>

using namespace intel::sgx;
namespace{

bool operator==(const dcap::test::QuoteV5Generator::QuoteHeader& testHeader, const dcap::Header &header)
{
    return
        testHeader.attestationKeyType == header.attestationKeyType &&
        testHeader.version == header.version &&
        testHeader.reserved == (static_cast<uint32_t>(header.qeSvn) << 16) + static_cast<uint32_t>(header.pceSvn) &&
        testHeader.qeVendorId == header.qeVendorId &&
        testHeader.userData == header.userData;
}

bool operator==(const dcap::test::QuoteV5Generator::EnclaveReport& testReport, const dcap::EnclaveReport& report)
{
    return
        testReport.attributes == report.attributes &&
        testReport.cpuSvn == report.cpuSvn &&
        testReport.isvProdID == report.isvProdID &&
        testReport.isvSvn == report.isvSvn &&
        testReport.miscSelect == report.miscSelect&&
        testReport.mrEnclave == report.mrEnclave &&
        testReport.mrSigner == report.mrSigner &&
        testReport.reportData == report.reportData &&
        testReport.reserved1 == report.reserved1 &&
        testReport.reserved2 == report.reserved2 &&
        testReport.reserved3 == report.reserved3 &&
        testReport.reserved4 == report.reserved4;
}

bool operator==(const dcap::test::QuoteV5Generator::CertificationData& testCertificationData, const dcap::CertificationData& certificationData)
{
    return
        testCertificationData.size == certificationData.parsedDataSize
        && testCertificationData.keyDataType == certificationData.type
        && testCertificationData.keyData == certificationData.data;
}

bool operator==(const dcap::test::QuoteV5Generator::TDReport10& testTdReport, const dcap::TDReport10& tdReport)
{
    return
            testTdReport.teeTcbSvn == tdReport.teeTcbSvn
            && testTdReport.mrSeam == tdReport.mrSeam
            && testTdReport.mrSignerSeam == tdReport.mrSignerSeam
            && testTdReport.seamAttributes == tdReport.seamAttributes
            && testTdReport.xFAM == tdReport.xFAM
            && testTdReport.mrTd == tdReport.mrTd
            && testTdReport.mrConfigId == tdReport.mrConfigId
            && testTdReport.mrOwner == tdReport.mrOwner
            && testTdReport.mrOwnerConfig == tdReport.mrOwnerConfig
            && testTdReport.rtMr0 == tdReport.rtMr0
            && testTdReport.rtMr1 == tdReport.rtMr1
            && testTdReport.rtMr2 == tdReport.rtMr2
            && testTdReport.rtMr3 == tdReport.rtMr3
            && testTdReport.reportData == tdReport.reportData;
}

} // anonymous namespace

struct QuoteV5ParsingUT: public testing::Test
{
    dcap::test::QuoteV5Generator gen;
    dcap::test::QuoteV5Generator::QEReportCertificationData qeReportCertificationData;
    dcap::test::QuoteV5Generator::CertificationData certificationData;

    void SetUp() override {
        gen = {};

        qeReportCertificationData.certificationData.size = 0;
        qeReportCertificationData.certificationData.keyDataType = intel::sgx::dcap::constants::PCK_ID_PCK_CERT_CHAIN;
        qeReportCertificationData.qeReport = gen.getEnclaveReport();
        qeReportCertificationData.qeAuthData.size = 0;

        certificationData.keyDataType = intel::sgx::dcap::constants::PCK_ID_QE_REPORT_CERTIFICATION_DATA;
        certificationData.keyData = qeReportCertificationData.bytes();
        certificationData.size = static_cast<uint16_t>(certificationData.keyData.size());
        gen.withCertificationData(certificationData);
    }
};


TEST_F(QuoteV5ParsingUT, shouldNotDeserializeIfQuoteTooShort)
{
    const auto quote = dcap::test::QuoteV5Generator{}.buildSgxQuote();
    EXPECT_FALSE(dcap::Quote{}.parse(std::vector<uint8_t>(quote.cbegin(), quote.cend()-2)));
}

TEST_F(QuoteV5ParsingUT, shouldParseStubQuoteWithMinimumSize)
{
    // GIVEN
    dcap::test::QuoteV5Generator::QuoteHeader header{};
    dcap::test::QuoteV5Generator::EnclaveReport body{};

    gen.withHeader(header)
        .withEnclaveReport(body);

    // WHEN
    dcap::Quote quote;
    EXPECT_TRUE(quote.parse(gen.buildSgxQuote()));

    // THEN
    EXPECT_TRUE(header == quote.getHeader());
    EXPECT_TRUE(body == quote.getEnclaveReport());
}

TEST_F(QuoteV5ParsingUT, shouldParseEmptyHeader)
{
     // GIVEN
    const dcap::test::QuoteV5Generator::QuoteHeader testHeader{};
    const auto headerBytes = testHeader.bytes();

    // WHEN
    auto from = headerBytes.begin();
    dcap::Header header;
    header.insert(from, headerBytes.cend());

    // THEN
    ASSERT_TRUE(from == headerBytes.cend());
    EXPECT_TRUE(testHeader == header);
}

TEST_F(QuoteV5ParsingUT, shouldParseAndValidateQuoteHeader)
{
    dcap::test::QuoteV5Generator::QuoteHeader testHeader;
    testHeader.attestationKeyType = dcap::constants::ECDSA_256_WITH_P256_CURVE;
    testHeader.reserved = 0;
    testHeader.qeVendorId = dcap::constants::INTEL_QE_VENDOR_ID;
    testHeader.teeType = 0;
    testHeader.userData = {};

    gen.withHeader(testHeader);
    const auto quote = gen.buildSgxQuote();

    dcap::Quote quoteObj;

    ASSERT_TRUE(quoteObj.parse(quote));
    ASSERT_TRUE(quoteObj.validate());

    EXPECT_TRUE(testHeader == quoteObj.getHeader());
}

TEST_F(QuoteV5ParsingUT, shouldParseAndNotValidateBecauseAttestationKeyTypeNotSupported)
{
    dcap::test::QuoteV5Generator::QuoteHeader testHeader;
    testHeader.attestationKeyType = 3; // Not supported value
    testHeader.reserved = 0;
    testHeader.qeVendorId = dcap::constants::INTEL_QE_VENDOR_ID;
    testHeader.teeType = dcap::constants::TEE_TYPE_SGX;
    testHeader.userData = {};

    gen.withHeader(testHeader);
    const auto quote = gen.buildSgxQuote();

    dcap::Quote quoteObj;

    ASSERT_TRUE(quoteObj.parse(quote));
    ASSERT_FALSE(quoteObj.validate());

    EXPECT_TRUE(testHeader == quoteObj.getHeader());
}

TEST_F(QuoteV5ParsingUT, shouldParseAndNotValidateBecauseQeVendorIdNotSupported)
{
    dcap::test::QuoteV5Generator::QuoteHeader testHeader;
    testHeader.attestationKeyType = dcap::constants::ECDSA_256_WITH_P256_CURVE;
    testHeader.reserved = 0;
    testHeader.qeVendorId = {}; // Not supported
    testHeader.teeType = dcap::constants::TEE_TYPE_SGX;
    testHeader.userData = {};



    gen.withHeader(testHeader);
    const auto quote = gen.buildSgxQuote();

    dcap::Quote quoteObj;

    ASSERT_TRUE(quoteObj.parse(quote));
    ASSERT_FALSE(quoteObj.validate());

    EXPECT_TRUE(testHeader == quoteObj.getHeader());
}

TEST_F(QuoteV5ParsingUT, shouldParseButNotValidateBecauseVersionNotSupported)
{
    dcap::test::QuoteV5Generator::QuoteHeader testHeader;
    testHeader.version = 2; // Not supported
    testHeader.attestationKeyType = dcap::constants::ECDSA_256_WITH_P256_CURVE;
    testHeader.reserved = 0;
    testHeader.qeVendorId = dcap::constants::INTEL_QE_VENDOR_ID;
    testHeader.teeType = dcap::constants::TEE_TYPE_SGX;
    testHeader.userData = {};

    gen.withHeader(testHeader);
    const auto quote = gen.buildSgxQuote();

    dcap::Quote quoteObj;

    ASSERT_TRUE(quoteObj.parse(quote));

    EXPECT_TRUE(testHeader == quoteObj.getHeader());
    ASSERT_FALSE(quoteObj.validate());
}

TEST_F(QuoteV5ParsingUT, shoulNotValidateBecauseTeeTypeNotSupported)
{
    dcap::test::QuoteV5Generator::QuoteHeader testHeader;
    testHeader.attestationKeyType = dcap::constants::ECDSA_256_WITH_P256_CURVE;
    testHeader.reserved = 0;
    testHeader.qeVendorId = dcap::constants::INTEL_QE_VENDOR_ID;
    testHeader.teeType = 3; // Not supported
    testHeader.userData = {};

    gen.withHeader(testHeader);
    const auto quote = gen.buildSgxQuote();

    dcap::Quote quoteObj;
    ASSERT_TRUE(quoteObj.parse(quote));
    ASSERT_FALSE(quoteObj.validate());
}

TEST_F(QuoteV5ParsingUT, shouldNotValidateQuoteTDXHeaderWithEnclaveReport)
{
    dcap::test::QuoteV5Generator::QuoteHeader testHeader;
    testHeader.attestationKeyType = dcap::constants::ECDSA_256_WITH_P256_CURVE;
    testHeader.reserved = 0;
    testHeader.qeVendorId = dcap::constants::INTEL_QE_VENDOR_ID;
    testHeader.teeType = dcap::constants::TEE_TYPE_TDX;
    testHeader.userData = {};

    gen.withHeader(testHeader);
    const auto quote = gen.buildSgxQuote();

    dcap::Quote quoteObj;

    ASSERT_TRUE(quoteObj.parse(quote));
    ASSERT_FALSE(quoteObj.validate());
}

TEST_F(QuoteV5ParsingUT, shouldNotValdiateQuoteSGXHeaderWithTdReport)
{
    dcap::test::QuoteV5Generator::QuoteHeader testHeader;
    testHeader.attestationKeyType = dcap::constants::ECDSA_256_WITH_P256_CURVE;
    testHeader.reserved = 0;
    testHeader.qeVendorId = dcap::constants::INTEL_QE_VENDOR_ID;
    testHeader.teeType = dcap::constants::TEE_TYPE_SGX;
    testHeader.userData = {};

    gen.withBody({ dcap::constants::BODY_TD_REPORT10_TYPE, dcap::constants::TD_REPORT10_BYTE_LEN });
    gen.withHeader(testHeader);
    const auto quote = gen.buildTdx10Quote();

    dcap::Quote quoteObj;

    ASSERT_TRUE(quoteObj.parse(quote));
    ASSERT_FALSE(quoteObj.validate());
}

TEST_F(QuoteV5ParsingUT, shouldParseAndValidateQuoteSGXQuote)
{
    dcap::test::QuoteV5Generator::QuoteHeader testHeader;
    testHeader.version = 5;
    testHeader.attestationKeyType = dcap::constants::ECDSA_256_WITH_P256_CURVE;
    testHeader.reserved = 0;
    testHeader.qeVendorId = dcap::constants::INTEL_QE_VENDOR_ID;
    testHeader.teeType = dcap::constants::TEE_TYPE_SGX;
    testHeader.userData = {};

    gen.withHeader(testHeader);
    const auto quote = gen.buildSgxQuote();

    dcap::Quote quoteObj;

    ASSERT_TRUE(quoteObj.parse(quote));
    ASSERT_TRUE(quoteObj.validate());

    EXPECT_TRUE(testHeader == quoteObj.getHeader());
}

TEST_F(QuoteV5ParsingUT, shouldParseAndValidateQuoteTDX10Quote)
{
    dcap::test::QuoteV5Generator::QuoteHeader testHeader;
    testHeader.attestationKeyType = dcap::constants::ECDSA_256_WITH_P256_CURVE;
    testHeader.reserved = 0;
    testHeader.qeVendorId = dcap::constants::INTEL_QE_VENDOR_ID;
    testHeader.teeType = dcap::constants::TEE_TYPE_TDX;
    testHeader.userData = {};

    gen.withHeader(testHeader);
    gen.withBody({ dcap::constants::BODY_TD_REPORT10_TYPE,
                   dcap::constants::TD_REPORT10_BYTE_LEN });
    const auto quote = gen.buildTdx10Quote();

    dcap::Quote quoteObj;

    ASSERT_TRUE(quoteObj.parse(quote));
    ASSERT_TRUE(quoteObj.validate());

    EXPECT_TRUE(testHeader == quoteObj.getHeader());
}

TEST_F(QuoteV5ParsingUT, shouldParseAndValidateQuoteTDX15Header)
{
    dcap::test::QuoteV5Generator::QuoteHeader testHeader;
    testHeader.attestationKeyType = dcap::constants::ECDSA_256_WITH_P256_CURVE;
    testHeader.reserved = 0;
    testHeader.qeVendorId = dcap::constants::INTEL_QE_VENDOR_ID;
    testHeader.teeType = dcap::constants::TEE_TYPE_TDX;
    testHeader.userData = {};

    gen.withHeader(testHeader);
    gen.withBody({ dcap::constants::BODY_TD_REPORT15_TYPE,
                   dcap::constants::TD_REPORT15_BYTE_LEN });
    const auto quote = gen.buildTdx15Quote();

    dcap::Quote quoteObj;

    ASSERT_TRUE(quoteObj.parse(quote));
    ASSERT_TRUE(quoteObj.validate());

    EXPECT_TRUE(testHeader == quoteObj.getHeader());
}

TEST_F(QuoteV5ParsingUT, shouldNotValdiateQuoteWithUnsupportedVersion)
{
    dcap::test::QuoteV5Generator::QuoteHeader testHeader;
    testHeader.attestationKeyType = dcap::constants::ECDSA_256_WITH_P256_CURVE;
    testHeader.reserved = 0;
    testHeader.version = 100;
    testHeader.qeVendorId = dcap::constants::INTEL_QE_VENDOR_ID;
    testHeader.teeType = dcap::constants::TEE_TYPE_SGX;
    testHeader.userData = {};

    gen.withHeader(testHeader);
    const auto quote = gen.buildSgxQuote();

    dcap::Quote quoteObj;

    ASSERT_TRUE(quoteObj.parse(quote));
    ASSERT_FALSE(quoteObj.validate());
}

TEST_F(QuoteV5ParsingUT, shouldNotParseQuoteWithUnsupportedBodyType)
{
    gen.withBody({ 100, dcap::constants::ENCLAVE_REPORT_BYTE_LEN });
    const auto quote = gen.buildSgxQuote();

    dcap::Quote quoteObj;

    ASSERT_FALSE(quoteObj.parse(quote));
}

TEST_F(QuoteV5ParsingUT, shouldNotParseSgxQuoteWithInvalidBodySize)
{
    gen.withBody({ dcap::constants::BODY_SGX_ENCLAVE_REPORT_TYPE, 0});
    const auto quote = gen.buildSgxQuote();

    dcap::Quote quoteObj;

    ASSERT_FALSE(quoteObj.parse(quote));
}

TEST_F(QuoteV5ParsingUT, shouldNotParseTdx10QuoteWithInvalidBodySize)
{
    gen.withBody({ dcap::constants::BODY_TD_REPORT10_TYPE, 0});
    const auto quote = gen.buildSgxQuote();

    dcap::Quote quoteObj;

    ASSERT_FALSE(quoteObj.parse(quote));
}

TEST_F(QuoteV5ParsingUT, shouldNotParseTdx15QuoteWithInvalidBodySize)
{
    gen.withBody({ dcap::constants::BODY_TD_REPORT15_TYPE, 0});
    const auto quote = gen.buildSgxQuote();

    dcap::Quote quoteObj;

    ASSERT_FALSE(quoteObj.parse(quote));
}

TEST_F(QuoteV5ParsingUT, shouldParseEnclaveReport)
{
    const dcap::test::QuoteV5Generator::EnclaveReport testReport{};
    const auto bytes = testReport.bytes();

    auto from = bytes.begin();
    dcap::EnclaveReport report{};
    report.insert(from, bytes.cend());

    ASSERT_TRUE(from == bytes.cend());
    ASSERT_TRUE(testReport == report);
    ASSERT_THAT(report.rawBlob(), ::testing::ElementsAreArray(bytes));
}

TEST_F(QuoteV5ParsingUT, shouldParseTDReport10)
{
    const dcap::test::QuoteV5Generator::TDReport10 testReport{};
    const auto bytes = testReport.bytes();

    auto from = bytes.begin();
    dcap::TDReport10 report{};
    report.insert(from, bytes.cend());

    ASSERT_TRUE(from == bytes.cend());
    EXPECT_TRUE(testReport == report);
    ASSERT_THAT(report.rawBlob(), ::testing::ElementsAreArray(bytes));
}

TEST_F(QuoteV5ParsingUT, shouldParseTDReport15)
{
    const dcap::test::QuoteV5Generator::TDReport15 testReport{};
    const auto bytes = testReport.bytes();

    auto from = bytes.begin();
    dcap::TDReport15 report{};
    report.insert(from, bytes.cend());

    ASSERT_TRUE(from == bytes.cend());
    EXPECT_TRUE(testReport == report);
    ASSERT_THAT(report.rawBlob(), ::testing::ElementsAreArray(bytes));
}

TEST_F(QuoteV5ParsingUT, shouldParseQuoteBody)
{
    dcap::test::QuoteV5Generator::EnclaveReport testreport{};

    testreport.miscSelect = 5;
    testreport.isvSvn = 300;
    testreport.attributes = {{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}};

    gen.withEnclaveReport(testreport);

    dcap::Quote quote;

    ASSERT_TRUE(quote.parse(gen.buildSgxQuote()));
    EXPECT_TRUE(testreport == quote.getEnclaveReport());
}

TEST_F(QuoteV5ParsingUT, shouldParseQeAuthData)
{
    dcap::test::QuoteV5Generator::QeAuthData testAuth{5, {1, 2, 3, 4, 5}};
    const auto bytes = testAuth.bytes();

    auto from = bytes.begin();
    dcap::QeAuthData auth;
    auth.insert(from, bytes.cend());

    ASSERT_TRUE(from == bytes.cend());
    EXPECT_EQ(5, auth.parsedDataSize);
    EXPECT_EQ(5, auth.data.size());
    EXPECT_EQ(testAuth.data, auth.data);
}

TEST_F(QuoteV5ParsingUT, shouldParseQeAuthWithShorterDataButPointerShouldNotBeMoved)
{
    dcap::test::QuoteV5Generator::QeAuthData testAuth{5, {1, 2, 3, 4}};
    const auto bytes = testAuth.bytes();

    auto from = bytes.begin();
    dcap::QeAuthData auth;
    auth.insert(from, bytes.cend());

    ASSERT_TRUE(from == bytes.begin());
    EXPECT_EQ(5, auth.parsedDataSize);
    EXPECT_EQ(0, auth.data.size());
}

TEST_F(QuoteV5ParsingUT, shouldNotParseTooShortQuote)
{
    auto quoteBytes = dcap::test::QuoteV5Generator{}.buildSgxQuote();
    std::vector<uint8_t> tooShortQuote;
    tooShortQuote.reserve(quoteBytes.size() - 1);
    std::copy(quoteBytes.begin(), quoteBytes.end() - 1, std::back_inserter(tooShortQuote));

    dcap::Quote quote;
    EXPECT_FALSE(quote.parse(tooShortQuote));
}

TEST_F(QuoteV5ParsingUT, shouldNotParseIfAuthDataSizeBiggerThanRemaingData)
{
    ++gen.getAuthSize();

    dcap::Quote quote;
    EXPECT_FALSE(quote.parse(gen.buildSgxQuote()));
}

TEST_F(QuoteV5ParsingUT, shouldNotParseIfAuthDataSizeSmallerThanRemainingData)
{
    --gen.getAuthSize();

    dcap::Quote quote;
    EXPECT_FALSE(quote.parse(gen.buildSgxQuote()));
}

TEST_F(QuoteV5ParsingUT, shouldParseCustomQeAuth)
{
    qeReportCertificationData.qeAuthData.data = {0x00, 0xaa, 0xff};
    qeReportCertificationData.qeAuthData.size = 3;

    certificationData.keyDataType = intel::sgx::dcap::constants::PCK_ID_QE_REPORT_CERTIFICATION_DATA;
    certificationData.keyData = qeReportCertificationData.bytes();
    certificationData.size = static_cast<uint16_t>(certificationData.keyData.size());

    gen.withCertificationData(certificationData);
    gen.getAuthData().authDataSize += 3; // qeAuthData.size

    dcap::Quote quote;
    ASSERT_TRUE(quote.parse(gen.buildSgxQuote()));
    EXPECT_TRUE(certificationData == quote.getAuthDataV4().certificationData);
}

TEST_F(QuoteV5ParsingUT, shouldNotParseWhenQuoteAuthDataSizeMatchButQeAuthDataSizeDoNotMatch)
{
    qeReportCertificationData.qeAuthData.data = {0x00, 0xaa, 0xff};
    qeReportCertificationData.qeAuthData.size = 3;

    certificationData.keyDataType = intel::sgx::dcap::constants::PCK_ID_QE_REPORT_CERTIFICATION_DATA;
    certificationData.keyData = qeReportCertificationData.bytes();
    certificationData.size = static_cast<uint16_t>(certificationData.keyData.size());

    gen.withCertificationData(certificationData);
    gen.getAuthData().authDataSize += 3 + 1; // qeAuthData.size + 1

    dcap::Quote quote;
    EXPECT_FALSE(quote.parse(gen.buildSgxQuote()));
}

TEST_F(QuoteV5ParsingUT, shouldNotParseWhenQuoteAuthDataSizeMatchButQeAuthDataSizeAreTooMuch)
{
    qeReportCertificationData.qeAuthData.data = {0x00, 0xaa, 0xff};
    qeReportCertificationData.qeAuthData.size = 4; // +1 to real size

    certificationData.keyDataType = intel::sgx::dcap::constants::PCK_ID_QE_REPORT_CERTIFICATION_DATA;
    certificationData.keyData = qeReportCertificationData.bytes();
    certificationData.size = static_cast<uint16_t>(certificationData.keyData.size());

    gen.withCertificationData(certificationData);
    gen.getAuthData().authDataSize += 3; // correct qeAuthData.size

    dcap::Quote quote;
	auto builtQuote = gen.buildSgxQuote();
    EXPECT_FALSE(quote.parse(builtQuote));
}

TEST_F(QuoteV5ParsingUT, shouldParseCertificationData)
{
    qeReportCertificationData.certificationData.keyData = {0x01, 0xaa, 0xff, 0xcd};
    qeReportCertificationData.certificationData.size = 4;

    certificationData.keyData = qeReportCertificationData.bytes();
    certificationData.size = static_cast<uint16_t>(certificationData.keyData.size());
    gen.withCertificationData(certificationData);
    gen.getAuthData().authDataSize += 4; // certificationData.size

    dcap::Quote quote;
    ASSERT_TRUE(quote.parse(gen.buildSgxQuote()));
    EXPECT_EQ(qeReportCertificationData.certificationData.keyData, quote.getCertificationData().data);
    EXPECT_EQ(qeReportCertificationData.certificationData.keyDataType, quote.getCertificationData().type);
    EXPECT_EQ(qeReportCertificationData.certificationData.size, quote.getCertificationData().parsedDataSize);
}

TEST_F(QuoteV5ParsingUT, shouldNotParseWhenAuthDataSizeMatchButCertificationDataParsedSizeDoesNotMatch)
{
    qeReportCertificationData.certificationData.keyData = {0x01, 0xaa, 0xff, 0xcd};
    qeReportCertificationData.certificationData.size = 3; // bad value, should be 4, authDataSize is correct
    qeReportCertificationData.qeAuthData.data = {0x00, 0xaa, 0xff};
    qeReportCertificationData.qeAuthData.size = 3;

    certificationData.keyData = qeReportCertificationData.bytes();
    certificationData.size = static_cast<uint16_t>(certificationData.keyData.size());
    gen.withCertificationData(certificationData);
    gen.getAuthData().authDataSize += 4 + 3; // certificationData.size + qeAuthData.size

    dcap::Quote quote;
    ASSERT_FALSE(quote.parse(gen.buildSgxQuote()));
}

TEST_F(QuoteV5ParsingUT, shouldNotParseWhenAuthDataSizeMatchButCertificationDataParsedSizeIsTooMuch)
{
    qeReportCertificationData.certificationData.keyData = {0x01, 0xaa, 0xff, 0xcd};
    qeReportCertificationData.certificationData.size = 5; // +1 to real size
    qeReportCertificationData.qeAuthData.data = {0x00, 0xaa, 0xff};
    qeReportCertificationData.qeAuthData.size = 3;

    certificationData.keyData = qeReportCertificationData.bytes();
    certificationData.size = static_cast<uint16_t>(certificationData.keyData.size());
    gen.withCertificationData(certificationData);
    gen.getAuthData().authDataSize += 5 + 3; // certificationData.size + qeAuthData.size

    dcap::Quote quote;
    ASSERT_FALSE(quote.parse(gen.buildSgxQuote()));
}

TEST_F(QuoteV5ParsingUT, shouldNotParseWhenAuthDataSizeMatchButQeAuthDataParsedSizeIsTooMuch)
{
    qeReportCertificationData.certificationData.keyData = {0x01, 0xaa, 0xff, 0xcd};
    qeReportCertificationData.certificationData.size = 4;
    qeReportCertificationData.qeAuthData.data = {0x00, 0xaa, 0xff};
    qeReportCertificationData.qeAuthData.size = 4; // +1 to real size

    certificationData.keyData = qeReportCertificationData.bytes();
    certificationData.size = static_cast<uint16_t>(certificationData.keyData.size());
    gen.withCertificationData(certificationData);
    gen.getAuthData().authDataSize += 4 + 3; // certificationData.size + qeAuthData.size

    dcap::Quote quote;
    ASSERT_FALSE(quote.parse(gen.buildSgxQuote()));
}

TEST_F(QuoteV5ParsingUT, shouldParseQeAuthAndQeCert)
{
    qeReportCertificationData.certificationData.keyData = {0x01, 0xaa, 0xff, 0xcd};
    qeReportCertificationData.certificationData.size = 4;
    qeReportCertificationData.qeAuthData.data = {0x00, 0xaa, 0xff};
    qeReportCertificationData.qeAuthData.size = 3;

    certificationData.keyData = qeReportCertificationData.bytes();
    certificationData.size = static_cast<uint16_t>(certificationData.keyData.size());
    gen.withCertificationData(certificationData);
    gen.getAuthData().authDataSize += 4 + 3; // certificationData.size + qeAuthData.size

    dcap::Quote quote;
    ASSERT_TRUE(quote.parse(gen.buildSgxQuote()));
}

TEST_F(QuoteV5ParsingUT, shouldNotValidateQeAuthAndQeCertWithUnsupportedType)
{
    qeReportCertificationData.certificationData.keyDataType = 6; // 6 is invalid, should be 5

    certificationData.keyData = qeReportCertificationData.bytes();
    certificationData.size = static_cast<uint16_t>(certificationData.keyData.size());
    gen.withCertificationData(certificationData);

    dcap::Quote quote;
    ASSERT_TRUE(quote.parse(gen.buildSgxQuote()));
    ASSERT_FALSE(quote.validate());
}

TEST_F(QuoteV5ParsingUT, shouldNotParseCertificationDataWithUnsupportedType)
{
    certificationData.keyDataType = 5; // 5 is invalid, should be 6
    gen.withCertificationData(certificationData);

    dcap::Quote quote;
    ASSERT_TRUE(quote.parse(gen.buildSgxQuote()));
    ASSERT_FALSE(quote.validate());
}