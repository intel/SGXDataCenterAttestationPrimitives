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
#include "Mocks/TCBInfoJsonVerifierMock.h"
#include "TestUtils/DigestUtils.h"
#include "TestUtils/QuoteGenerator.h"
#include "TestUtils/KeyHelpers.h"
#include "Constants/QuoteTestConstants.h"


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

std::array<uint8_t,64> getRawSig(const std::vector<uint8_t>& derSig)
{
    const long COMP_SIZE = 32;
    auto ecdsaSig = qvl::crypto::make_unique(ECDSA_SIG_new());
    auto sigPtr = ecdsaSig.get();
    auto it = derSig.data();

    d2i_ECDSA_SIG(&sigPtr, &it, static_cast<long>(derSig.size()));

    // internal pointers
    const BIGNUM *r,*s;
    ECDSA_SIG_get0(ecdsaSig.get(), &r, &s);

    auto bn2Vec = [&](const BIGNUM* bn) -> std::vector<uint8_t>{
        const int bnLen = BN_num_bytes(bn);
        if(bnLen <= 0)
        {
            return {};
        }
        std::vector<uint8_t> ret(static_cast<size_t>(bnLen));
        BN_bn2bin(bn, ret.data());
        return ret;
    };

    const auto rVec = bn2Vec(r);
    const auto sVec = bn2Vec(s);

    std::array<uint8_t, 64> ret{};
    std::fill(ret.begin(), ret.end(), 0x00);
    const auto rOffset = static_cast<long>(COMP_SIZE - rVec.size());
    const auto sOffset = static_cast<long>(COMP_SIZE - sVec.size());

    std::copy_n(rVec.begin(), COMP_SIZE - rOffset, std::next(ret.begin(), rOffset));
    std::copy_n(sVec.begin(), COMP_SIZE - sOffset, std::next(ret.begin(), COMP_SIZE + sOffset));

    return ret;
}

std::array<uint8_t,64> signAndGetRaw(const std::vector<uint8_t>& data, EVP_PKEY& key)
{
    return getRawSig(qvl::DigestUtils::signMessageSha256(data, key));
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

struct QuoteVerifierUT: public testing::Test
{
    QuoteVerifierUT()
       : ppid(16, 0xaa), cpusvn(16, 0x80), fmspc(6, 0xde), pcesvn{0xaa, 0xbb}
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

    NiceMock<qvl::test::CertStoreMock> pck;
    NiceMock<qvl::test::CrlStoreMock> crl;
    NiceMock<qvl::test::TCBInfoJsonVerifierMock> tcbInfoJson;
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
        ON_CALL(tcbInfoJson, getLatestCpusvn()).WillByDefault(testing::ReturnRef(cpusvn));
        ON_CALL(tcbInfoJson, getLatestPcesvn()).WillByDefault(testing::Return(toUint16(pcesvn[1], pcesvn[0])));
        ON_CALL(tcbInfoJson, getRevokedCpusvn()).WillByDefault(testing::ReturnRef(emptyVector));
        ON_CALL(tcbInfoJson, getRevokedPcesvn()).WillByDefault(testing::Return(0));

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

    EXPECT_EQ(STATUS_TCB_INFO_MISMATCH, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
}

TEST_F(QuoteVerifierUT, shouldThrowFormatException)
{
    const auto quoteBin = gen.buildQuote();
    qvl::Quote quote;
    std::vector<uint8_t> tooManyElements(17, 128);

    EXPECT_CALL(tcbInfoJson, getRevokedCpusvn()).WillOnce(testing::ReturnRef(emptyVector));
    EXPECT_CALL(tcbInfoJson, getLatestCpusvn()).WillOnce(testing::ReturnRef(cpusvn)).WillOnce(testing::ReturnRef(tooManyElements));

    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_THROW(qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson), qvl::pckparser::FormatException);
}

TEST_F(QuoteVerifierUT, shouldReturnUnsuportedTcbInfoFormatWhenRevokedCpusvnHasIncorrectSize)
{
    const auto quoteBin = gen.buildQuote();
    qvl::Quote quote;
    std::vector<uint8_t> tooManyElements(17, 128);

    EXPECT_CALL(tcbInfoJson, getRevokedCpusvn()).WillOnce(testing::ReturnRef(cpusvn)).WillOnce(testing::ReturnRef(tooManyElements));

    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_UNSUPPORTED_TCB_INFO_FORMAT, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
}

TEST_F(QuoteVerifierUT, shouldReturnUnsuportedTcbInfoFormatWhenLastestCpusvnHasIncorrectSize)
{
    const auto quoteBin = gen.buildQuote();
    qvl::Quote quote;
    std::vector<uint8_t> tooManyElements(17, 128);

    EXPECT_CALL(tcbInfoJson, getLatestCpusvn()).WillOnce(testing::ReturnRef(tooManyElements));

    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_UNSUPPORTED_TCB_INFO_FORMAT, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
}


TEST_F(QuoteVerifierUT, shouldReturnStatusOutOfdDateWhenPcesvnIsToobig)
{
    const auto quoteBin = gen.buildQuote();
    qvl::Quote quote;
    int largest = 999999999;

    EXPECT_CALL(tcbInfoJson, getLatestPcesvn()).WillOnce(testing::Return(largest));

    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_TCB_OUT_OF_DATE, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
}

TEST_F(QuoteVerifierUT, shouldReturnStatusOutOfdDateWhenLastestCpusvnIsTooBig)
{
    const auto quoteBin = gen.buildQuote();
    qvl::Quote quote;
    std::vector<uint8_t> largestCpusvnValue(16, 255);

    EXPECT_CALL(tcbInfoJson, getLatestCpusvn()).WillRepeatedly(testing::ReturnRef(largestCpusvnValue));

    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_TCB_OUT_OF_DATE, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
}

TEST_F(QuoteVerifierUT, shouldReturnStatusInvalidPckCrlWhenPeriodAndIssuerIsInvalid)
{
    const auto quoteBin = gen.buildQuote();
    qvl::Quote quote;

    EXPECT_CALL(crl, getIssuer()).WillRepeatedly(testing::ReturnRef(qvl::test::constants::ROOT_CA_CRL_ISSUER));


    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_INVALID_PCK_CRL, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
}

TEST_F(QuoteVerifierUT, shouldReturnStatusInvalidPckCrlWhenCrlIssuerIsDifferentThanPck)
{
    const auto quoteBin = gen.buildQuote();
    qvl::Quote quote;

    EXPECT_CALL(crl, getIssuer()).WillRepeatedly(testing::ReturnRef(qvl::test::constants::PCK_PLATFORM_CRL_ISSUER));
    EXPECT_CALL(pck, getIssuer()).WillRepeatedly(testing::ReturnRef(qvl::test::constants::ROOT_CA_CRL_ISSUER));

    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_INVALID_PCK_CRL, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
}

TEST_F(QuoteVerifierUT, shouldReturnStatusPckRevoked)
{
    const auto quoteBin = gen.buildQuote();
    qvl::Quote quote;

    EXPECT_CALL(crl, isRevoked(testing::_)).WillOnce(testing::Return(true));


    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_PCK_REVOKED, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
}

TEST_F(QuoteVerifierUT, shouldReturnStatusInvalidQeFormat)
{
    qvl::Quote quote;
    gen.getQuoteAuthData().ecdsaAttestationKey.publicKey = std::array<uint8_t, 64>{};
    const auto quoteBin = gen.buildQuote();

    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_INVALID_QE_REPORT_DATA, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
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

    ASSERT_TRUE(quote.parse(quoteBin));
    quote.setEcdsa256BitQuoteAuthData(authData);
    EXPECT_EQ(STATUS_UNSUPPORTED_QUOTE_FORMAT, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
}

TEST_F(QuoteVerifierUT, shouldVerifyCorrectly)
{
    const auto quoteBin = gen.buildQuote();

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_OK, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
}

TEST_F(QuoteVerifierUT, shouldReturnInvalidPCKCert)
{
    const qvl::pckparser::Subject emptySubject{};
    ON_CALL(pck, getSubject()).WillByDefault(testing::ReturnRef(emptySubject));
    const auto quoteBin = gen.buildQuote();

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_INVALID_PCK_CERT, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
}

TEST_F(QuoteVerifierUT, shouldReturnInvalidPCKCertWhenTcbExtensionIsEmpty)
{
    sgxExtensions[1] = sgxExtension(qvl::pckparser::SgxExtension::Type::TCB, {}, {}, std::vector<qvl::pckparser::SgxExtension>{});
    const auto quoteBin = gen.buildQuote();

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_INVALID_PCK_CERT, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
}

TEST_F(QuoteVerifierUT, shouldReturnInvalidPCKCertWhenSgxExtensionsAreMissing)
{
    sgxExtensions.clear();
    const auto quoteBin = gen.buildQuote();

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_INVALID_PCK_CERT, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
}

struct QuoteVerifierUTPckTypesParametrized : public QuoteVerifierUT,
    public testing::WithParamInterface<uint16_t>
{};

TEST_P(QuoteVerifierUTPckTypesParametrized, shouldReturnStatusOkEvenWhenPpidIsNotMatching)
{
    const std::vector<uint8_t> notMatchingPpid(16, 0x00);
    const auto sgxExtensionsWihtNoMatchingPpid = [&]() -> std::vector<qvl::pckparser::SgxExtension>
    {
        std::vector<qvl::pckparser::SgxExtension> ret = sgxExtensions;
        ret[0] = sgxExtension(qvl::pckparser::SgxExtension::Type::PPID, notMatchingPpid);
        return ret;
    }();
    ON_CALL(pck, getSGXExtensions()).WillByDefault(testing::ReturnRef(sgxExtensionsWihtNoMatchingPpid));

    qvl::test::QuoteGenerator::QeCertData qeCertData;
    qeCertData.keyDataType = GetParam();
    qeCertData.keyData = concat(ppid, concat(cpusvn, pcesvn));
    qeCertData.size = static_cast<uint16_t>(qeCertData.keyData.size());

    const auto quoteBin = gen.withQeCertData(qeCertData).buildQuote();

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_OK, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
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

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_INVALID_QUOTE_SIGNATURE, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
}

TEST_F(QuoteVerifierUT, shouldReturnInvalidQeReportSignature)
{
    gen.getQuoteAuthData().qeReportSignature.signature[0] = ~gen.getQuoteAuthData().qeReportSignature.signature[0];
    const auto quoteBin = gen.buildQuote();

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_INVALID_QE_REPORT_SIGNATURE, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
}

TEST_F(QuoteVerifierUT, shouldReturnTcbRevokedOnLatestRevokedEqualPckTCB)
{
    const auto quoteBin = gen.buildQuote();

    ON_CALL(tcbInfoJson, getRevokedCpusvn()).WillByDefault(testing::ReturnRef(cpusvn));
    ON_CALL(tcbInfoJson, getRevokedPcesvn()).WillByDefault(testing::Return(toUint16(pcesvn[1], pcesvn[0])));

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_TCB_REVOKED, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
}

TEST_F(QuoteVerifierUT, shouldReturnTcbRevokedOnLatestRevokedCpuSvnAndPceSvnGreaterThanPckCpuSvn)
{
    const auto quoteBin = gen.buildQuote();

    std::vector<uint8_t> higherCpusvn = cpusvn;
    higherCpusvn[8]++;
    const std::vector<uint8_t> higherPcesvn = {0xff, 0xff};

    ON_CALL(tcbInfoJson, getRevokedCpusvn()).WillByDefault(testing::ReturnRef(higherCpusvn));
    ON_CALL(tcbInfoJson, getRevokedPcesvn()).WillByDefault(testing::Return(toUint16(higherPcesvn[1], higherPcesvn[0])));

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_TCB_REVOKED, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
}

TEST_F(QuoteVerifierUT, shouldReturnTcbRevokedWhenOnlyOneRevokedTcbComponentIsHigher)
{
    const auto quoteBin = gen.buildQuote();

    std::vector<uint8_t> higherCpusvn = cpusvn;
    higherCpusvn[8]++;

    ON_CALL(tcbInfoJson, getRevokedCpusvn()).WillByDefault(testing::ReturnRef(higherCpusvn));
    ON_CALL(tcbInfoJson, getRevokedPcesvn()).WillByDefault(testing::Return(toUint16(pcesvn[1], pcesvn[0])));

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_TCB_REVOKED, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
}

TEST_F(QuoteVerifierUT, shouldNOTReturnTcbRevokedWhenOnlyOneRevokedTcbComponentIsLower)
{
    const auto quoteBin = gen.buildQuote();

    std::vector<uint8_t> lowerCpusvn = cpusvn;
    lowerCpusvn[8]--;
    const std::vector<uint8_t> higherPcesvn = {0xff, 0xff};

    ON_CALL(tcbInfoJson, getRevokedCpusvn()).WillByDefault(testing::ReturnRef(lowerCpusvn));
    ON_CALL(tcbInfoJson, getRevokedPcesvn()).WillByDefault(testing::Return(toUint16(higherPcesvn[1], higherPcesvn[0])));

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_OK, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
}

TEST_F(QuoteVerifierUT, shouldNOTReturnTcbRevokedWhenOnlyCpusvnIsRevoked)
{
    const auto quoteBin = gen.buildQuote();

    std::vector<uint8_t> lowerPcesvn = pcesvn;
    lowerPcesvn[0]--;

    ON_CALL(tcbInfoJson, getRevokedCpusvn()).WillByDefault(testing::ReturnRef(cpusvn));
    ON_CALL(tcbInfoJson, getRevokedPcesvn()).WillByDefault(testing::Return(toUint16(lowerPcesvn[1], lowerPcesvn[0])));

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_OK, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
}

TEST_F(QuoteVerifierUT, shouldNOTReturnTcbRevokedWhenOnlyPcesvnIsRevoked)
{
    const auto quoteBin = gen.buildQuote();

    std::vector<uint8_t> lowerCpusvn = cpusvn;
    lowerCpusvn[8]--;

    ON_CALL(tcbInfoJson, getRevokedCpusvn()).WillByDefault(testing::ReturnRef(lowerCpusvn));
    ON_CALL(tcbInfoJson, getRevokedPcesvn()).WillByDefault(testing::Return(toUint16(pcesvn[1], pcesvn[0])));

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_OK, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
}

TEST_F(QuoteVerifierUT, shouldNOTReturnTcbRevokedWhenRevokedPcesvnAndCpusvnAreLower)
{
    const auto quoteBin = gen.buildQuote();

    std::vector<uint8_t> lowerCpusvn = cpusvn;
    lowerCpusvn[8]--;
    std::vector<uint8_t> lowerPcesvn = pcesvn;
    lowerPcesvn[0]--;

    ON_CALL(tcbInfoJson, getRevokedCpusvn()).WillByDefault(testing::ReturnRef(lowerCpusvn));
    ON_CALL(tcbInfoJson, getRevokedPcesvn()).WillByDefault(testing::Return(toUint16(lowerPcesvn[1], lowerPcesvn[0])));

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_OK, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
}

TEST_F(QuoteVerifierUT, shouldNOTReturnTcbRevokedWhenRevokedCpusvnIsHigherAndPcesvnIsLower)
{
    const auto quoteBin = gen.buildQuote();

    std::vector<uint8_t> higherCpusvn = cpusvn;
    higherCpusvn[4]++;
    std::vector<uint8_t> lowerPcesvn = pcesvn;
    lowerPcesvn[0]--;

    ON_CALL(tcbInfoJson, getRevokedCpusvn()).WillByDefault(testing::ReturnRef(higherCpusvn));
    ON_CALL(tcbInfoJson, getRevokedPcesvn()).WillByDefault(testing::Return(toUint16(lowerPcesvn[1], lowerPcesvn[0])));

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_OK, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
}

TEST_F(QuoteVerifierUT, shouldReturnTcbRevokedWhenRevokedCpusvnIsEqualAndPcesvnIsHigher)
{
    const auto quoteBin = gen.buildQuote();

    std::vector<uint8_t> higherPcesvn = pcesvn;
    higherPcesvn[0]++;

    ON_CALL(tcbInfoJson, getRevokedCpusvn()).WillByDefault(testing::ReturnRef(cpusvn));
    ON_CALL(tcbInfoJson, getRevokedPcesvn()).WillByDefault(testing::Return(toUint16(higherPcesvn[1], higherPcesvn[0])));

    qvl::Quote quote;
    ASSERT_TRUE(quote.parse(quoteBin));
    EXPECT_EQ(STATUS_TCB_REVOKED, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
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
    EXPECT_EQ(STATUS_UNSUPPORTED_QE_CERTIFICATION, qvl::QuoteVerifier{}.verify(quote, pck, crl, tcbInfoJson));
}


