/*
* Copyright (c) 2017-2018, Intel Corporation
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


#include <Verifiers/QuoteVerifier.h>
#include <PckParser/FormatException.h>

#include "Mocks/CertCrlStoresMocks.h"
#include "Mocks/QEIdentityJsonVerifierMock.h"
#include "Mocks/EnclaveReportVerifierMock.h"
#include "Mocks/TCBInfoJsonVerifierMock.h"
#include "DigestUtils.h"
#include "QuoteGenerator.h"
#include "KeyHelpers.h"
#include "Constants/QuoteTestConstants.h"
#include "EcdsaSignatureGenerator.h"


using namespace intel::sgx;
using namespace ::testing;

namespace{

uint16_t toUint16(uint8_t leftMostByte, uint8_t rightMostByte)
{
    uint16_t ret = 0;
    ret |= static_cast<uint16_t>(rightMostByte);
    ret |= (static_cast<uint16_t>(leftMostByte) << 8) & 0xff00;
    return ret;
}

std::array<uint8_t,64> signAndGetRaw(const std::vector<uint8_t>& data, EVP_PKEY& key)
{
    auto signature = qvl::DigestUtils::signMessageSha256(data, key);
    return EcdsaSignatureGenerator::convertECDSASignatureToRawArray(signature);
}

qvl::pckparser::SgxExtension sgxExtension(qvl::pckparser::SgxExtension::Type type,
                                          const std::vector<uint8_t>& data,
                                          const ASN1_TYPE& asn1Data = ASN1_TYPE{},
                                          const std::vector<qvl::pckparser::SgxExtension>& subsequence = {},
                                          const std::string& oidStr = "")
{
    return qvl::pckparser::SgxExtension(type, data, asn1Data, subsequence, oidStr);
}

std::vector<qvl::pckparser::Extension> standardPCKExtensions()
{
    using namespace intel::sgx::qvl::test::constants;
    std::vector<qvl::pckparser::Extension> ret(PCK_REQUIRED_EXTENSIONS.size());
    std::transform(PCK_REQUIRED_EXTENSIONS.begin(), PCK_REQUIRED_EXTENSIONS.end(), ret.begin(), [](int nid){
                return qvl::pckparser::Extension{nid, "", {}};
    });

    return ret;
}

std::vector<uint8_t> concat(const std::vector<uint8_t>& rhs, const std::vector<uint8_t>& lhs)
{
    std::vector<uint8_t> ret = rhs;
    std::copy(lhs.begin(), lhs.end(), std::back_inserter(ret));
    return ret;
}

template<size_t N>
std::vector<uint8_t> concat(const std::array<uint8_t,N>& rhs, const std::vector<uint8_t>& lhs)
{
    std::vector<uint8_t> ret(std::begin(rhs), std::end(rhs));
    std::copy(lhs.begin(), lhs.end(), std::back_inserter(ret));
    return ret;
}

std::array<uint8_t,64> assingFirst32(const std::array<uint8_t,32>& in)
{
    std::array<uint8_t,64> ret{};
    std::copy_n(in.begin(), 32, ret.begin());
    return ret;
}

std::array<uint8_t,64> signEnclaveReport(const qvl::test::QuoteGenerator::EnclaveReport& report, EVP_PKEY& key)
{
    return signAndGetRaw(report.bytes(), key);
}
}//anonymous namespace

// helper struct to clear asn1 integers memory on tests exit
struct ASN1IntegerMemory final
{
    ASN1IntegerMemory() = default;
    ~ASN1IntegerMemory()
    {
        for(auto value : values)
        {
            ASN1_INTEGER_free(value);
        }
    }

    ASN1_TYPE createUint(uint8_t input)
    {
        auto asnInt = ASN1_INTEGER_new();
        ASN1_INTEGER_set_uint64(asnInt, input);
        values.push_back(asnInt);

        auto retVal = ASN1_TYPE{V_ASN1_INTEGER};
        retVal.value.integer = asnInt;
        return retVal;
    }

    ASN1_TYPE createUint(uint16_t input)
    {
        auto asnInt = ASN1_INTEGER_new();
        ASN1_INTEGER_set_uint64(asnInt, input);
        values.push_back(asnInt);

        auto retVal = ASN1_TYPE{V_ASN1_INTEGER};
        retVal.value.integer = asnInt;
        return retVal;
    }

private:
    std::vector<ASN1_INTEGER*> values;
};

class EnclaveReportVerifierMock;

struct QuoteVerifierUT: public testing::Test
{
    QuoteVerifierUT()
       : ppid(16, 0xaa), cpusvn(16, 0x40), fmspc(6, 0xde), pcesvn{0xaa, 0xbb}
    {

    }
    const qvl::crypto::EVP_PKEY_uptr privKey = qvl::test::toEvp(*qvl::test::priv(qvl::test::PEM_PRV));
    const qvl::crypto::EC_KEY_uptr pckPubKey = qvl::test::pub(qvl::test::PEM_PUB);
    const std::vector<uint8_t> emptyVector{};
    const std::vector<uint8_t> ppid;
    const std::vector<uint8_t> cpusvn;
    const std::vector<uint8_t> fmspc;
    const std::vector<uint8_t> pcesvn;
    ASN1IntegerMemory asn1Integers;
    const std::vector<qvl::pckparser::Extension> standardExtensions = standardPCKExtensions();
    const std::vector<qvl::pckparser::SgxExtension> tcbSequence {
            sgxExtension(qvl::pckparser::SgxExtension::Type::SGX_TCB_COMP01_SVN, std::vector<uint8_t>{cpusvn[0]}, asn1Integers.createUint(cpusvn[0])),
            sgxExtension(qvl::pckparser::SgxExtension::Type::SGX_TCB_COMP02_SVN, std::vector<uint8_t>{cpusvn[1]}, asn1Integers.createUint(cpusvn[1])),
            sgxExtension(qvl::pckparser::SgxExtension::Type::SGX_TCB_COMP03_SVN, std::vector<uint8_t>{cpusvn[2]}, asn1Integers.createUint(cpusvn[2])),
            sgxExtension(qvl::pckparser::SgxExtension::Type::SGX_TCB_COMP04_SVN, std::vector<uint8_t>{cpusvn[3]}, asn1Integers.createUint(cpusvn[3])),
            sgxExtension(qvl::pckparser::SgxExtension::Type::SGX_TCB_COMP05_SVN, std::vector<uint8_t>{cpusvn[4]}, asn1Integers.createUint(cpusvn[4])),
            sgxExtension(qvl::pckparser::SgxExtension::Type::SGX_TCB_COMP06_SVN, std::vector<uint8_t>{cpusvn[5]}, asn1Integers.createUint(cpusvn[5])),
            sgxExtension(qvl::pckparser::SgxExtension::Type::SGX_TCB_COMP07_SVN, std::vector<uint8_t>{cpusvn[6]}, asn1Integers.createUint(cpusvn[6])),
            sgxExtension(qvl::pckparser::SgxExtension::Type::SGX_TCB_COMP08_SVN, std::vector<uint8_t>{cpusvn[7]}, asn1Integers.createUint(cpusvn[7])),
            sgxExtension(qvl::pckparser::SgxExtension::Type::SGX_TCB_COMP09_SVN, std::vector<uint8_t>{cpusvn[8]}, asn1Integers.createUint(cpusvn[8])),
            sgxExtension(qvl::pckparser::SgxExtension::Type::SGX_TCB_COMP10_SVN, std::vector<uint8_t>{cpusvn[9]}, asn1Integers.createUint(cpusvn[9])),
            sgxExtension(qvl::pckparser::SgxExtension::Type::SGX_TCB_COMP11_SVN, std::vector<uint8_t>{cpusvn[10]}, asn1Integers.createUint(cpusvn[10])),
            sgxExtension(qvl::pckparser::SgxExtension::Type::SGX_TCB_COMP12_SVN, std::vector<uint8_t>{cpusvn[11]}, asn1Integers.createUint(cpusvn[11])),
            sgxExtension(qvl::pckparser::SgxExtension::Type::SGX_TCB_COMP13_SVN, std::vector<uint8_t>{cpusvn[12]}, asn1Integers.createUint(cpusvn[12])),
            sgxExtension(qvl::pckparser::SgxExtension::Type::SGX_TCB_COMP14_SVN, std::vector<uint8_t>{cpusvn[13]}, asn1Integers.createUint(cpusvn[13])),
            sgxExtension(qvl::pckparser::SgxExtension::Type::SGX_TCB_COMP15_SVN, std::vector<uint8_t>{cpusvn[14]}, asn1Integers.createUint(cpusvn[14])),
            sgxExtension(qvl::pckparser::SgxExtension::Type::SGX_TCB_COMP16_SVN, std::vector<uint8_t>{cpusvn[15]}, asn1Integers.createUint(cpusvn[15])),
            sgxExtension(qvl::pckparser::SgxExtension::Type::CPUSVN, cpusvn),
            sgxExtension(qvl::pckparser::SgxExtension::Type::PCESVN, pcesvn, asn1Integers.createUint(toUint16(pcesvn[1], pcesvn[0])))
    };
    std::vector<qvl::pckparser::SgxExtension> sgxExtensions{
        sgxExtension(qvl::pckparser::SgxExtension::Type::PPID, ppid),
        sgxExtension(qvl::pckparser::SgxExtension::Type::TCB, {}, {}, tcbSequence),
        sgxExtension(qvl::pckparser::SgxExtension::Type::FMSPC, fmspc),
        sgxExtension(qvl::pckparser::SgxExtension::Type::PCEID, std::vector<uint8_t>(2)),
        sgxExtension(qvl::pckparser::SgxExtension::Type::SGX_TYPE, std::vector<uint8_t>(1)),
        sgxExtension(qvl::pckparser::SgxExtension::Type::DYNAMIC_PLATFORM, std::vector<uint8_t>(1)),
        sgxExtension(qvl::pckparser::SgxExtension::Type::CACHED_KEYS, std::vector<uint8_t>(1)),
    };
    const std::vector<qvl::pckparser::Revoked> emptyRevoked{};
    std::set<TCBInfoJsonVerifier::TcbLevel, std::greater<>> tcbs{};

    NiceMock<qvl::test::CertStoreMock> pck;
    NiceMock<qvl::test::CrlStoreMock> crl;
    NiceMock<qvl::test::TCBInfoJsonVerifierMock> tcbInfoJson;
    NiceMock<qvl::test::QEIdentityJsonVerifierMock> qeIdentityJson;
    NiceMock<qvl::test::EnclaveReportVerifierMock> enclaveReportVerifier;
    qvl::test::QuoteGenerator gen;

    /*
     * SetUp represent minimal, positive quote verification data preparation
     */
    void SetUp() override
    {
        ON_CALL(pck, getSGXExtensions()).WillByDefault(testing::ReturnRef(sgxExtensions));
        ON_CALL(pck, expired()).WillByDefault(testing::Return(false));
        ON_CALL(pck, getSubject()).WillByDefault(testing::ReturnRef(qvl::test::constants::PCK_SUBJECT));
        ON_CALL(pck, getIssuer()).WillByDefault(testing::ReturnRef(qvl::test::constants::PCK_PLATFORM_CRL_ISSUER));
        ON_CALL(pck, getExtensions()).WillByDefault(testing::ReturnRef(standardExtensions));
        ON_CALL(pck, getPubKey()).WillByDefault(testing::ReturnRef(*pckPubKey));

        ON_CALL(crl, expired()).WillByDefault(testing::Return(false));
        ON_CALL(crl, getExtensions()).WillByDefault(testing::ReturnRef(standardExtensions));
        ON_CALL(crl, getIssuer()).WillByDefault(testing::ReturnRef(qvl::test::constants::PCK_PLATFORM_CRL_ISSUER));
        ON_CALL(crl, getRevoked()).WillByDefault(testing::ReturnRef(emptyRevoked));

        ON_CALL(tcbInfoJson, getFmspc()).WillByDefault(testing::ReturnRef(fmspc));
        ON_CALL(tcbInfoJson, getTcbLevels()).WillByDefault(testing::ReturnRef(tcbs));

        ON_CALL(qeIdentityJson, getStatus()).WillByDefault(Return(STATUS_OK));
        ON_CALL(enclaveReportVerifier, verify(_, _)).WillByDefault(Return(STATUS_OK));

        qvl::test::QuoteGenerator::QeCertData qeCertData;
        qeCertData.keyDataType = qvl::test::constants::PCK_ID_PLAIN_PPID;
        qeCertData.keyData = concat(ppid, concat(cpusvn, pcesvn));
        qeCertData.size = static_cast<uint16_t>(qeCertData.keyData.size());
        gen.withQeCertData(qeCertData);
        gen.getAuthSize() += qeCertData.keyData.size();
        gen.getQuoteAuthData().ecdsaAttestationKey.publicKey = qvl::test::getRawPub(*pckPubKey);

        gen.getQuoteAuthData().qeReport.reportData = assingFirst32(
            qvl::DigestUtils::sha256DigestArray(concat(gen.getQuoteAuthData().ecdsaAttestationKey.publicKey, gen.getQuoteAuthData().qeAuthData.data)));


        gen.getQuoteAuthData().qeReportSignature.signature = signEnclaveReport(gen.getQuoteAuthData().qeReport, *privKey);


        gen.getQuoteAuthData().ecdsaSignature.signature =
            signAndGetRaw(concat(gen.getHeader().bytes(), gen.getBody().bytes()), *privKey);
    }
};

TEST_F(QuoteVerifierUT, shouldReturnStatusTcbInfoMismatch)
{
    qvl::Quote quote;
    std::vector<uint8_t> emptyVector{};

    EXPECT_CALL(tcbInfoJson, getFmspc()).WillRepeatedly(testing::ReturnRef(emptyVector));

    EXPECT_EQ(STATUS_TCB_INFO_MISMATCH, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}

TEST_F(QuoteVerifierUT, shouldReturnUnsuportedTcbInfoFormatWhenRevokedCpusvnHasIncorrectSize)
{
    const auto quoteBin = gen.buildQuote();
    qvl::Quote quote;
    std::vector<uint8_t> tooManyElements(17, 128);

    tcbs.insert(tcbs.begin(), TCBInfoJsonVerifier::TcbLevel{tooManyElements, toUint16(pcesvn[1], pcesvn[0]), "Revoked"});
    EXPECT_CALL(tcbInfoJson, getTcbLevels()).WillOnce(testing::ReturnRef(tcbs));

    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_UNSUPPORTED_TCB_INFO_FORMAT, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}

TEST_F(QuoteVerifierUT, shouldReturnUnsuportedTcbInfoFormatWhenLastestCpusvnHasIncorrectSize)
{
    const auto quoteBin = gen.buildQuote();
    qvl::Quote quote;
    std::vector<uint8_t> tooManyElements(17, 128);

    tcbs.insert(tcbs.begin(), TCBInfoJsonVerifier::TcbLevel{tooManyElements, toUint16(pcesvn[1], pcesvn[0]), "UpToDate"});
    EXPECT_CALL(tcbInfoJson, getTcbLevels()).WillOnce(testing::ReturnRef(tcbs));

    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_UNSUPPORTED_TCB_INFO_FORMAT, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}

TEST_F(QuoteVerifierUT, shouldReturnUnsuportedTcbInfoFormatWhenConfigurationNeededCpusvnHasIncorrectSize)
{
    const auto quoteBin = gen.buildQuote();
    qvl::Quote quote;
    std::vector<uint8_t> tooManyElements(17, 128);

    tcbs.insert(tcbs.begin(), TCBInfoJsonVerifier::TcbLevel{tooManyElements, toUint16(pcesvn[1], pcesvn[0]), "ConfigurationNeeded"});
    EXPECT_CALL(tcbInfoJson, getTcbLevels()).WillOnce(testing::ReturnRef(tcbs));

    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_UNSUPPORTED_TCB_INFO_FORMAT, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}

TEST_F(QuoteVerifierUT, shouldReturnStatusInvalidPckCrlWhenPeriodAndIssuerIsInvalid)
{
    const auto quoteBin = gen.buildQuote();
    qvl::Quote quote;

    EXPECT_CALL(crl, getIssuer()).WillRepeatedly(testing::ReturnRef(qvl::test::constants::ROOT_CA_CRL_ISSUER));


    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_INVALID_PCK_CRL, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}

TEST_F(QuoteVerifierUT, shouldReturnStatusInvalidPckCrlWhenCrlIssuerIsDifferentThanPck)
{
    const auto quoteBin = gen.buildQuote();
    qvl::Quote quote;

    EXPECT_CALL(crl, getIssuer()).WillRepeatedly(testing::ReturnRef(qvl::test::constants::PCK_PLATFORM_CRL_ISSUER));
    EXPECT_CALL(pck, getIssuer()).WillRepeatedly(testing::ReturnRef(qvl::test::constants::ROOT_CA_CRL_ISSUER));

    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_INVALID_PCK_CRL, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}

TEST_F(QuoteVerifierUT, shouldReturnStatusPckRevoked)
{
    const auto quoteBin = gen.buildQuote();
    qvl::Quote quote;

    EXPECT_CALL(crl, isRevoked(testing::_)).WillOnce(testing::Return(true));


    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_PCK_REVOKED, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}

TEST_F(QuoteVerifierUT, shouldReturnStatusInvalidQeFormat)
{
    qvl::Quote quote;
    gen.getQuoteAuthData().ecdsaAttestationKey.publicKey = std::array<uint8_t, 64>{};
    const auto quoteBin = gen.buildQuote();

    tcbs.insert(tcbs.begin(), TCBInfoJsonVerifier::TcbLevel{cpusvn, toUint16(pcesvn[1], pcesvn[0]), "UpToDate"});
    EXPECT_CALL(tcbInfoJson, getTcbLevels()).WillOnce(testing::ReturnRef(tcbs));

    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_INVALID_QE_REPORT_DATA, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}

TEST_F(QuoteVerifierUT, shouldReturnUnsupportedQuoteFormatWhenParsedDatraSizeIsDifferentThanDataSize)
{
    class QuoteMock : public qvl::Quote
    {
    public:
        void setEcdsa256BitQuoteAuthData(qvl::Quote::Ecdsa256BitQuoteAuthData authData){
            qvl::Quote::authData = authData;
        }
    };

    qvl::Quote::Ecdsa256BitQuoteAuthData authData;
    authData.qeCertData.type = 1;
    authData.qeCertData.parsedDataSize = 5;
    authData.qeCertData.data = concat(ppid, concat(cpusvn, pcesvn));
    QuoteMock quote;
    const auto quoteBin = gen.buildQuote();

    tcbs.insert(tcbs.begin(), TCBInfoJsonVerifier::TcbLevel{cpusvn, toUint16(pcesvn[1], pcesvn[0]), "UpToDate"});
    EXPECT_CALL(tcbInfoJson, getTcbLevels()).WillOnce(testing::ReturnRef(tcbs));

    ASSERT_TRUE(quote.parse(quoteBin));
    quote.setEcdsa256BitQuoteAuthData(authData);
    EXPECT_EQ(STATUS_UNSUPPORTED_QUOTE_FORMAT, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}

TEST_F(QuoteVerifierUT, shouldVerifyCorrectly)
{
    const auto quoteBin = gen.buildQuote();

    tcbs.insert(tcbs.begin(), TCBInfoJsonVerifier::TcbLevel{cpusvn, toUint16(pcesvn[1], pcesvn[0]), "UpToDate"});
    EXPECT_CALL(tcbInfoJson, getTcbLevels()).WillOnce(testing::ReturnRef(tcbs));

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_OK, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}

TEST_F(QuoteVerifierUT, shouldReturnInvalidPCKCert)
{
    const qvl::pckparser::Subject emptySubject{};
    ON_CALL(pck, getSubject()).WillByDefault(testing::ReturnRef(emptySubject));
    const auto quoteBin = gen.buildQuote();

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_INVALID_PCK_CERT, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}

TEST_F(QuoteVerifierUT, shouldReturnInvalidPCKCertWhenTcbExtensionIsEmpty)
{
    sgxExtensions[1] = sgxExtension(qvl::pckparser::SgxExtension::Type::TCB, {}, {}, std::vector<qvl::pckparser::SgxExtension>{});
    const auto quoteBin = gen.buildQuote();

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_INVALID_PCK_CERT, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}

TEST_F(QuoteVerifierUT, shouldReturnInvalidPCKCertWhenSgxExtensionsAreMissing)
{
    sgxExtensions.clear();
    const auto quoteBin = gen.buildQuote();

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_INVALID_PCK_CERT, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}

struct QuoteVerifierUTPckTypesParametrized : public QuoteVerifierUT,
                                             public testing::WithParamInterface<uint16_t>
{};

TEST_P(QuoteVerifierUTPckTypesParametrized, shouldReturnStatusOkEvenWhenPpidIsNotMatching)
{
    const std::vector<uint8_t> notMatchingPpid(16, 0x00);
    const auto sgxExtensionsWithNoMatchingPpid = [&]() -> std::vector<qvl::pckparser::SgxExtension>
    {
        std::vector<qvl::pckparser::SgxExtension> ret = sgxExtensions;
        ret[0] = sgxExtension(qvl::pckparser::SgxExtension::Type::PPID, notMatchingPpid);
        return ret;
    }();
    ON_CALL(pck, getSGXExtensions()).WillByDefault(testing::ReturnRef(sgxExtensionsWithNoMatchingPpid));

    qvl::test::QuoteGenerator::QeCertData qeCertData;
    qeCertData.keyDataType = GetParam();
    qeCertData.keyData = concat(ppid, concat(cpusvn, pcesvn));
    qeCertData.size = static_cast<uint16_t>(qeCertData.keyData.size());

    const auto quoteBin = gen.withQeCertData(qeCertData).buildQuote();

    tcbs.insert(tcbs.begin(), TCBInfoJsonVerifier::TcbLevel{cpusvn, toUint16(pcesvn[1], pcesvn[0]), "UpToDate"});
    EXPECT_CALL(tcbInfoJson, getTcbLevels()).WillOnce(testing::ReturnRef(tcbs));

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_OK, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}

INSTANTIATE_TEST_CASE_P(PckIdTypesThatDoNotValidateQeCertData,
                        QuoteVerifierUTPckTypesParametrized,
                        testing::Values(
                          qvl::test::constants::PCK_ID_ENCRYPTED_PPID_2048,
                          qvl::test::constants::PCK_ID_ENCRYPTED_PPID_3072,
                          qvl::test::constants::PCK_ID_PCK_CERTIFICATE,
                          qvl::test::constants::PCK_ID_PCK_CERT_CHAIN));

TEST_F(QuoteVerifierUT, shouldReturnQuoteInvalidSignature)
{
    gen.getQuoteAuthData().ecdsaSignature.signature[0] = ~gen.getQuoteAuthData().ecdsaSignature.signature[0];
    const auto quoteBin = gen.buildQuote();

    tcbs.insert(tcbs.begin(), TCBInfoJsonVerifier::TcbLevel{cpusvn, toUint16(pcesvn[1], pcesvn[0]), "UpToDate"});
    EXPECT_CALL(tcbInfoJson, getTcbLevels()).WillOnce(testing::ReturnRef(tcbs));

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_INVALID_QUOTE_SIGNATURE, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}

TEST_F(QuoteVerifierUT, shouldReturnInvalidQeReportSignature)
{
    gen.getQuoteAuthData().qeReportSignature.signature[0] = ~gen.getQuoteAuthData().qeReportSignature.signature[0];
    const auto quoteBin = gen.buildQuote();

    tcbs.insert(tcbs.begin(), TCBInfoJsonVerifier::TcbLevel{cpusvn, toUint16(pcesvn[1], pcesvn[0]), "UpToDate"});
    EXPECT_CALL(tcbInfoJson, getTcbLevels()).WillOnce(testing::ReturnRef(tcbs));

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_INVALID_QE_REPORT_SIGNATURE, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}

TEST_F(QuoteVerifierUT, shouldReturnTcbRevokedOnLatestRevokedEqualPckTCB)
{
    const auto quoteBin = gen.buildQuote();

    tcbs.insert(tcbs.begin(), TCBInfoJsonVerifier::TcbLevel{cpusvn, toUint16(pcesvn[1], pcesvn[0]), "Revoked"});
    EXPECT_CALL(tcbInfoJson, getTcbLevels()).WillOnce(testing::ReturnRef(tcbs));

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_TCB_REVOKED, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}

TEST_F(QuoteVerifierUT, shouldMatchToLowerTCBWhenBothSVNsAreLowerAndReturnConfigurationNeeded)
{
    const auto quoteBin = gen.buildQuote();

    std::vector<uint8_t> higherCpusvn = { 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x3F, 0x3F, 0x41, 0x3F, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40 };
    std::vector<uint8_t> lowerCpusvn = { 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x3F, 0x3F, 0x40, 0x3F, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40 };

    const std::vector<uint8_t> higherPcesvn = {0xff, 0xff};
    const std::vector<uint8_t> lowerPcesvn = {0x00, 0x00};

    tcbs.insert(TCBInfoJsonVerifier::TcbLevel{lowerCpusvn, toUint16(lowerPcesvn[1], lowerPcesvn[0]), "ConfigurationNeeded"});
    tcbs.insert(TCBInfoJsonVerifier::TcbLevel{higherCpusvn, toUint16(higherPcesvn[1], higherPcesvn[0]), "Revoked"});
    EXPECT_CALL(tcbInfoJson, getTcbLevels()).WillOnce(testing::ReturnRef(tcbs));

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_TCB_CONFIGURATION_NEEDED, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}

TEST_F(QuoteVerifierUT, shouldMatchToLowerTCBAndReturnConfigurationNeeded)
{
    const auto quoteBin = gen.buildQuote();

    std::vector<uint8_t> higherCpusvn = { 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x3F, 0x3F, 0x41, 0x3F, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40 };
    std::vector<uint8_t> lowerCpusvn = { 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x3F, 0x3F, 0x40, 0x3F, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40 };

    auto higherTcb = TCBInfoJsonVerifier::TcbLevel{higherCpusvn, toUint16(pcesvn[1], pcesvn[0]), "Revoked"};
    auto lowerTcb = TCBInfoJsonVerifier::TcbLevel{lowerCpusvn, toUint16(pcesvn[1], pcesvn[0]), "ConfigurationNeeded"};
    tcbs.insert(lowerTcb);
    tcbs.insert(higherTcb);
    EXPECT_EQ(tcbs.size(), 2);
    EXPECT_EQ(tcbs.begin()->cpusvn, higherTcb.cpusvn); // make sure that TCB levels has been inserted and sorted correctly
    EXPECT_CALL(tcbInfoJson, getTcbLevels()).WillOnce(testing::ReturnRef(tcbs));

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_TCB_CONFIGURATION_NEEDED, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}

TEST_F(QuoteVerifierUT, shouldReturnTcbNotSupportedWhenOnlyPceSvnIsHigher)
{
    const auto quoteBin = gen.buildQuote();

    const std::vector<uint8_t> higherPcesvn = {0xff, 0xff};

    tcbs.insert(tcbs.begin(), TCBInfoJsonVerifier::TcbLevel{cpusvn, toUint16(higherPcesvn[1], higherPcesvn[0]), "Revoked"});
    EXPECT_CALL(tcbInfoJson, getTcbLevels()).WillOnce(testing::ReturnRef(tcbs));

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_TCB_NOT_SUPPORTED, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}

TEST_F(QuoteVerifierUT, shouldReturnTcbRevokedWhenOnlyCpuSvnIsLower)
{
    const auto quoteBin = gen.buildQuote();

    std::vector<uint8_t> lowerCpusvn = cpusvn;
    lowerCpusvn[8]--;

    tcbs.insert(tcbs.begin(), TCBInfoJsonVerifier::TcbLevel{lowerCpusvn, toUint16(pcesvn[1], pcesvn[0]), "Revoked"});
    EXPECT_CALL(tcbInfoJson, getTcbLevels()).WillOnce(testing::ReturnRef(tcbs));

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_TCB_REVOKED, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}

TEST_F(QuoteVerifierUT, shouldReturnTcbRevokedWhenOnlyPcesvnIsLower)
{
    const auto quoteBin = gen.buildQuote();

    const std::vector<uint8_t> lowerPcesvn = {0x21, 0x12};

    tcbs.insert(tcbs.begin(), TCBInfoJsonVerifier::TcbLevel{cpusvn, toUint16(lowerPcesvn[1], lowerPcesvn[0]), "Revoked"});
    EXPECT_CALL(tcbInfoJson, getTcbLevels()).WillOnce(testing::ReturnRef(tcbs));

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_TCB_REVOKED, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}

TEST_F(QuoteVerifierUT, shouldNOTReturnTcbRevokedWhenRevokedPcesvnAndCpusvnAreLower)
{
    const auto quoteBin = gen.buildQuote();

    std::vector<uint8_t> lowerCpusvn = cpusvn;
    lowerCpusvn[8]--;
    std::vector<uint8_t> lowerPcesvn = pcesvn;
    lowerPcesvn[0]--;

    tcbs.insert(TCBInfoJsonVerifier::TcbLevel{cpusvn, toUint16(pcesvn[1], pcesvn[0]), "UpToDate"});
    tcbs.insert(TCBInfoJsonVerifier::TcbLevel{lowerCpusvn, toUint16(lowerPcesvn[1], lowerPcesvn[0]), "Revoked"});
    EXPECT_CALL(tcbInfoJson, getTcbLevels()).WillOnce(testing::ReturnRef(tcbs));

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_OK, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}

TEST_F(QuoteVerifierUT, shouldReturnUnsupportedQeCertification)
{
    qvl::test::QuoteGenerator::QeCertData qeCertData;
    qeCertData.keyDataType = qvl::test::constants::UNSUPPORTED_PCK_ID;
    qeCertData.keyData = concat(ppid, concat(cpusvn, pcesvn));
    qeCertData.size = static_cast<uint16_t>(qeCertData.keyData.size());
    gen.withQeCertData(qeCertData);
    const auto quoteBin = gen.buildQuote();

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    tcbs.insert(tcbs.begin(), TCBInfoJsonVerifier::TcbLevel{cpusvn, toUint16(pcesvn[1], pcesvn[0]), "UpToDate"});
    EXPECT_CALL(tcbInfoJson, getTcbLevels()).WillOnce(testing::ReturnRef(tcbs));
    EXPECT_EQ(STATUS_UNSUPPORTED_QE_CERTIFICATION, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}

struct QeIdentityStatuses {
    Status enclaveVerifierStatus;
    Status expectedStatus;
};

struct QuoteVerifierUTQeIdentityStatusParametrized : public QuoteVerifierUT,
                                                     public testing::WithParamInterface<QeIdentityStatuses>
{};

TEST_P(QuoteVerifierUTQeIdentityStatusParametrized, testAllStatuses)
{
    auto params = GetParam();
    const auto quoteBin = gen.buildQuote();
    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    tcbs.insert(tcbs.begin(), TCBInfoJsonVerifier::TcbLevel{cpusvn, toUint16(pcesvn[1], pcesvn[0]), "UpToDate"});
    EXPECT_CALL(tcbInfoJson, getTcbLevels()).WillOnce(testing::ReturnRef(tcbs));
    EXPECT_CALL(enclaveReportVerifier, verify(_, _)).WillOnce(Return(params.enclaveVerifierStatus));
    EXPECT_CALL(qeIdentityJson, getStatus()).WillOnce(Return(STATUS_OK));
    EXPECT_EQ(params.expectedStatus, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}

INSTANTIATE_TEST_CASE_P(AllStatutes,
                        QuoteVerifierUTQeIdentityStatusParametrized,
                        testing::Values(
                            QeIdentityStatuses{STATUS_OK, STATUS_OK},
                            QeIdentityStatuses{STATUS_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE, STATUS_QE_IDENTITY_OUT_OF_DATE},
                            QeIdentityStatuses{STATUS_SGX_ENCLAVE_REPORT_MISCSELECT_MISMATCH, STATUS_QE_IDENTITY_MISMATCH},
                            QeIdentityStatuses{STATUS_SGX_ENCLAVE_REPORT_ATTRIBUTES_MISMATCH, STATUS_QE_IDENTITY_MISMATCH},
                            QeIdentityStatuses{STATUS_SGX_ENCLAVE_REPORT_MRENCLAVE_MISMATCH, STATUS_QE_IDENTITY_MISMATCH},
                            QeIdentityStatuses{STATUS_SGX_ENCLAVE_REPORT_MRSIGNER_MISMATCH, STATUS_QE_IDENTITY_MISMATCH},
                            QeIdentityStatuses{STATUS_SGX_ENCLAVE_REPORT_ISVPRODID_MISMATCH, STATUS_QE_IDENTITY_MISMATCH},
                            QeIdentityStatuses{STATUS_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE, STATUS_QE_IDENTITY_MISMATCH}
                        ));

TEST_F(QuoteVerifierUT, shouldNotVerifyQeidIfJsonStatusIsNotOk)
{
    const auto quoteBin = gen.buildQuote();
    tcbs.insert(tcbs.begin(), TCBInfoJsonVerifier::TcbLevel{cpusvn, toUint16(pcesvn[1], pcesvn[0]), "UpToDate"});
    EXPECT_CALL(tcbInfoJson, getTcbLevels()).WillOnce(testing::ReturnRef(tcbs));
    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_CALL(enclaveReportVerifier, verify(_, _)).Times(0);
    EXPECT_CALL(qeIdentityJson, getStatus()).WillOnce(Return(STATUS_SGX_QE_IDENTITY_INVALID));
    EXPECT_EQ(STATUS_OK, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson, qeIdentityJson, enclaveReportVerifier));
}
