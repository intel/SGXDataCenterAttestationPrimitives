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


#include "QuoteGenerator.h"
#include <QuoteVerification/Quote.h>

#include <gtest/gtest.h>

using namespace intel::sgx;
namespace{

bool operator==(const dcap::test::QuoteGenerator::QuoteHeader& testHeader, const dcap::Quote::Header &header)
{
    return
        (testHeader.attestationKeyType) == header.attestationKeyType &&
        (testHeader.version) == header.version &&
        (testHeader.qeSvn) == header.qeSvn &&
        (testHeader.pceSvn) == header.pceSvn &&
        testHeader.uuid == header.uuid &&
        testHeader.userData == header.userData;
}

bool operator==(const dcap::test::QuoteGenerator::EnclaveReport& testReport, const dcap::Quote::EnclaveReport& report)
{
    return
        testReport.attributes == report.attributes &&
        testReport.cpuSvn == report.cpuSvn &&
        (testReport.isvProdID) == report.isvProdID &&
        (testReport.isvSvn) == report.isvSvn &&
        (testReport.miscSelect) == report.miscSelect&&
        testReport.mrEnclave == report.mrEnclave &&
        testReport.mrSigner == report.mrSigner &&
        testReport.reportData == report.reportData &&
        testReport.reserved1 == report.reserved1 &&
        testReport.reserved2 == report.reserved2 &&
        testReport.reserved3 == report.reserved3 &&
        testReport.reserved4 == report.reserved4;
}

bool operator==(const dcap::test::QuoteGenerator::EcdsaSignature& testSig, const dcap::Quote::Ecdsa256BitSignature& sig)
{
    return testSig.signature == sig.signature;
}

bool operator==(const dcap::test::QuoteGenerator::EcdsaPublicKey& testKey, const dcap::Quote::Ecdsa256BitPubkey& key)
{
    return testKey.publicKey == key.pubKey;
}

bool operator==(const dcap::test::QuoteGenerator::QeAuthData& testQeAuthData, const dcap::Quote::QeAuthData& qeAuth)
{
    return
        testQeAuthData.size == qeAuth.parsedDataSize
        && testQeAuthData.data == qeAuth.data;
}

bool operator==(const dcap::test::QuoteGenerator::QeCertData& testQeCertData, const dcap::Quote::QeCertData& qeCertData)
{
    return
        testQeCertData.size == qeCertData.parsedDataSize
        && testQeCertData.keyDataType == qeCertData.type
        && testQeCertData.keyData == qeCertData.data;
}

bool operator==(const dcap::test::QuoteGenerator::QuoteAuthData& testAuth, const dcap::Quote::Ecdsa256BitQuoteAuthData& auth)
{
    return
        testAuth.ecdsaSignature == auth.ecdsa256BitSignature
        && testAuth.ecdsaAttestationKey == auth.ecdsaAttestationKey
        && testAuth.ecdsaAttestationKey == auth.ecdsaAttestationKey
        && testAuth.qeReport == auth.qeReport
        && testAuth.qeReportSignature == auth.qeReportSignature
        && testAuth.qeAuthData == auth.qeAuthData
        && testAuth.qeCertData == auth.qeCertData;
}

} // anonymous namespace


TEST(quoteParsing, shouldNotDeserializeIfQuoteTooShort)
{
    const auto quote = dcap::test::QuoteGenerator{}.buildQuote();
    EXPECT_FALSE(dcap::Quote{}.parse(std::vector<uint8_t>(quote.cbegin(), quote.cend()-2)));
}

TEST(quote, shouldParseStubQuoteWithMinimumSize)
{
    // GIVEN
    dcap::test::QuoteGenerator::QuoteHeader header{};
    dcap::test::QuoteGenerator::EnclaveReport body{};
    dcap::test::QuoteGenerator::QuoteAuthData auth{};
    auth.authDataSize = dcap::test::QUOTE_AUTH_DATA_MIN_SIZE;
    
    dcap::test::QuoteGenerator gen{};
    gen.withHeader(header)
        .withBody(body)
        .withAuthData(auth);

    // WHEN
    dcap::Quote quote;
    EXPECT_TRUE(quote.parse(gen.buildQuote()));

    // THEN
    EXPECT_TRUE(header == quote.getHeader());
    EXPECT_TRUE(body == quote.getBody());
    EXPECT_TRUE(auth == quote.getQuoteAuthData());
}

TEST(quoteParsing, shouldParseEmptyHeader)
{
     // GIVEN
    const dcap::test::QuoteGenerator::QuoteHeader testHeader{};
    const auto headerBytes = testHeader.bytes();

    // WHEN
    auto from = headerBytes.begin();
    dcap::Quote::Header header;
    header.insert(from, headerBytes.cend());

    // THEN
    ASSERT_TRUE(from == headerBytes.cend());
    EXPECT_TRUE(testHeader == header);
}

TEST(quoteParsing, shouldParseQuoteHeader)
{
    dcap::test::QuoteGenerator::QuoteHeader testHeader;
    testHeader.version = 3;
    testHeader.attestationKeyType = 0xffaa;
    testHeader.pceSvn = 0;
    testHeader.qeSvn = 0;
    testHeader.uuid = {};
    testHeader.reserved = {};
    testHeader.userData = {};

    dcap::test::QuoteGenerator generator;

    generator.withHeader(testHeader);
    const auto quote = generator.buildQuote();

    dcap::Quote quoteObj;

    ASSERT_TRUE(quoteObj.parse(quote));

    EXPECT_TRUE(testHeader == quoteObj.getHeader()); 
}

TEST(quoteParsing, shouldParseEnclaveReport)
{
    const dcap::test::QuoteGenerator::EnclaveReport testreport{};
    const auto bytes = testreport.bytes();

    auto from = bytes.begin();
    dcap::Quote::EnclaveReport report;
    report.insert(from, bytes.cend());

    ASSERT_TRUE(from == bytes.cend());
    EXPECT_TRUE(testreport == report);
}

TEST(quoteParsing, shouldParseQuoteBody)
{
    dcap::test::QuoteGenerator::EnclaveReport testreport{};

    testreport.miscSelect = 5;
    testreport.isvSvn = 300;
    testreport.attributes = {{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}};

    dcap::test::QuoteGenerator gen{};
    gen.withBody(testreport);

    dcap::Quote quote;

    ASSERT_TRUE(quote.parse(gen.buildQuote()));
    EXPECT_TRUE(testreport == quote.getBody());
}

TEST(quoteParsing, shouldParseQeAuthData)
{
    dcap::test::QuoteGenerator::QeAuthData testAuth{5, {1,2,3,4,5}};
    const auto bytes = testAuth.bytes();

    auto from = bytes.begin();
    dcap::Quote::QeAuthData auth;
    auth.insert(from, bytes.cend());

    ASSERT_TRUE(from == bytes.cend());
    EXPECT_EQ(5, auth.parsedDataSize);
    EXPECT_EQ(5, auth.data.size());
    EXPECT_EQ(testAuth.data, auth.data);
}

TEST(quoteParsing, shouldParseQeAuthWithShorterDataButPointerShouldNotBeMoved)
{
    dcap::test::QuoteGenerator::QeAuthData testAuth{5, {1,2,3,4}};
    const auto bytes = testAuth.bytes();

    auto from = bytes.begin();
    dcap::Quote::QeAuthData auth;
    auth.insert(from, bytes.cend());

    ASSERT_TRUE(from == bytes.begin());
    EXPECT_EQ(5, auth.parsedDataSize);
    EXPECT_EQ(0, auth.data.size());
}

TEST(quoteParsing, shouldNotParseTooShortQuote)
{
    auto quoteBytes = dcap::test::QuoteGenerator{}.buildQuote();
    std::vector<uint8_t> tooShortQuote;
    tooShortQuote.reserve(quoteBytes.size() - 1);
    std::copy(quoteBytes.begin(), quoteBytes.end() - 1, std::back_inserter(tooShortQuote));

    dcap::Quote quote;
    EXPECT_FALSE(quote.parse(tooShortQuote));
}

TEST(quoteParsing, shouldNotParseIfAuthDataSizeBiggerThanRemaingData)
{
    dcap::test::QuoteGenerator gen;
    ++gen.getAuthSize();

    dcap::Quote quote;
    EXPECT_FALSE(quote.parse(gen.buildQuote()));
}

TEST(quoteParsing, shouldNotParseIfAuthDataSizeSmallerThanRemaingData)
{
    dcap::test::QuoteGenerator gen;
    --gen.getAuthSize();

    dcap::Quote quote;
    EXPECT_FALSE(quote.parse(gen.buildQuote()));
}

TEST(quoteParsing, shouldParseCustomQeAuth)
{
    dcap::test::QuoteGenerator gen;

    dcap::test::QuoteGenerator::QeAuthData qeAuthData;
    qeAuthData.data = {0x00, 0xaa, 0xff};
    qeAuthData.size = 3;

    gen.withQeAuthData(qeAuthData);
    gen.getAuthSize() +=  3; //QeAuthData::size byte len is const and already taken into account when creating default gen object

    dcap::Quote quote;
    ASSERT_TRUE(quote.parse(gen.buildQuote()));
    EXPECT_TRUE(qeAuthData == quote.getQuoteAuthData().qeAuthData);
}

TEST(quoteParsing, shouldNotParseWhenQuoteAuthDataSizeMatchButQeAuthDataSizeDoNotMatch)
{
    dcap::test::QuoteGenerator gen;

    dcap::test::QuoteGenerator::QeAuthData qeAuthData;
    qeAuthData.data = {0x00, 0xaa, 0xff};
    qeAuthData.size = 2;

    gen.withQeAuthData(qeAuthData);
    gen.getAuthSize() += 3;

    dcap::Quote quote;
    EXPECT_FALSE(quote.parse(gen.buildQuote()));
}

TEST(quoteParsing, shouldNotParseWhenQuoteAuthDataSizeMatchButQeAuthDataSizeAreTooMuch)
{
    dcap::test::QuoteGenerator gen;

    dcap::test::QuoteGenerator::QeAuthData qeAuthData;
    qeAuthData.data = {0x00, 0xaa, 0xff};
    qeAuthData.size = 4;

    gen.withQeAuthData(qeAuthData);
    gen.getAuthSize() += 3;

    dcap::Quote quote;
	auto builtQuote = gen.buildQuote();
    EXPECT_FALSE(quote.parse(builtQuote));
}

TEST(quoteParsing, shouldParseQeCertData)
{
    dcap::test::QuoteGenerator gen;

    dcap::test::QuoteGenerator::QeCertData qeCert;
    qeCert.keyData = {0x01, 0xaa, 0xff, 0xcd};
    qeCert.size = 4;
    qeCert.keyDataType = 5;
    
    gen.withQeCertData(qeCert);
    gen.getAuthSize() += 4;

    dcap::Quote quote;
    ASSERT_TRUE(quote.parse(gen.buildQuote()));
    EXPECT_EQ(qeCert.keyData, quote.getQuoteAuthData().qeCertData.data);
    EXPECT_EQ(qeCert.size, quote.getQuoteAuthData().qeCertData.parsedDataSize);
    EXPECT_EQ(qeCert.keyDataType, quote.getQuoteAuthData().qeCertData.type);
}

TEST(quoteParsing, shouldNotParseWhenAuthDataSizeMatchButQeCertDataParsedSizeDoesNotMatch)
{
    dcap::test::QuoteGenerator gen;

    dcap::test::QuoteGenerator::QeCertData qeCert;
    qeCert.keyData = {0x01, 0xaa, 0xff, 0xcd};
    qeCert.size = 3;
    qeCert.keyDataType = 5;
    
    gen.withQeCertData(qeCert);
    gen.getAuthSize() += 4;

    dcap::Quote quote;
    ASSERT_FALSE(quote.parse(gen.buildQuote())); 
}

TEST(quoteParsing, shouldNotParseWhenAuthDataSizeMatchButQeCertDataParsedSizeIsTooMuch)
{
    dcap::test::QuoteGenerator gen;

    dcap::test::QuoteGenerator::QeCertData qeCert;
    qeCert.keyData = {0x01, 0xaa, 0xff, 0xcd};
    qeCert.size = 5;
    qeCert.keyDataType = 5;
    
    gen.withQeCertData(qeCert);
    gen.getAuthSize() += 4;

    dcap::Quote quote;
    ASSERT_FALSE(quote.parse(gen.buildQuote())); 
}

TEST(quoteParsing, shouldParseQeAuthAndQeCert)
{
    dcap::test::QuoteGenerator gen;

    dcap::test::QuoteGenerator::QeCertData qeCert;
    qeCert.keyData = {0x01, 0xaa, 0xff, 0xcd};
    qeCert.size = 4;
    qeCert.keyDataType = 5;
    
    gen.withQeCertData(qeCert);
    gen.getAuthSize() += 4;

    dcap::test::QuoteGenerator::QeAuthData qeAuthData;
    qeAuthData.data = {0x00, 0xaa, 0xff};
    qeAuthData.size = 3;
    gen.withQeAuthData(qeAuthData);
    gen.getAuthSize() += 3;

    dcap::Quote quote;
    ASSERT_TRUE(quote.parse(gen.buildQuote())); 
}
