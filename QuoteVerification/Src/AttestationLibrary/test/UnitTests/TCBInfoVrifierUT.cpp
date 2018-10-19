/*
* Copyright (c) 2018, Intel Corporation
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
*    * Redistributions of source code must retain the above copyright notice,
*      this list of conditions and the following disclaimer.
*    * Redistributions in binary form must reproduce the above copyright
*      notice, this list of conditions and the following disclaimer in the
*      documentation and/or other materials provided with the distribution.
*    * Neither the name of Intel Corporation nor the names of its contributors
*      may be used to endorse or promote products derived from this software
*      without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <SgxEcdsaAttestation/QuoteVerification.h>
#include <Verifiers/TCBInfoVerifier.h>
#include <Verifiers/TCBSigningChain.h>
#include <Verifiers/TCBInfoJsonVerifier.h>
#include <Mocks/CertCrlStoresMocks.h>
#include <Mocks/TcbSigningChainMock.h>
#include <Mocks/CommonVerifierMock.h>
#include <Mocks/PckCrlVerifierMock.h>
#include <CertVerification/X509Constants.h>
#include <PckParser/PckParser.h>

using namespace testing;
using namespace intel::sgx::qvl;

struct TCBInfoVerifierUT : public Test
{
    std::vector<pckparser::Extension> extensions;
    pckparser::Signature signature;
    TCBInfoJsonVerifier tcbInfoJsonVerifier;
    crypto::EC_KEY_uptr pubKey = crypto::make_unique(EC_KEY_new());
};

TEST_F(TCBInfoVerifierUT, shouldReturnedStatusOkWhenVerifyPassPositive)
{
    // GIVEN
    auto commonVerifierMock = std::make_unique<StrictMock<test::CommonVerifierMock>>();
    auto pckCrlVerifierMock = std::make_unique<StrictMock<test::PckCrlVerifierMock>>();
    auto tcbSigningChainMock = std::make_unique<StrictMock<test::TcbSigningChainMock>>();
    StrictMock<test::CertificateChainMock> certificateChainMock;
    StrictMock<test::CertStoreMock> certStoreMock;
    StrictMock<test::CrlStoreMock> crlStoreMock;
    auto certStoreMockPtr = std::make_shared<StrictMock<test::CertStoreMock>>();

    EXPECT_CALL(*commonVerifierMock, checkSha256EcdsaSignature(_, _, _)).WillOnce(Return(true));

    EXPECT_CALL(*tcbSigningChainMock, verify(_, _, _)).WillOnce(Return(STATUS_OK));

    EXPECT_CALL(certificateChainMock, get(_)).WillRepeatedly(Return(certStoreMockPtr));

    EXPECT_CALL(*certStoreMockPtr, getPubKey()).WillOnce(ReturnRef(*pubKey));

    TCBInfoVerifier tcbInfoVerifier(std::move(commonVerifierMock), std::move(tcbSigningChainMock));

    // WHEN
    auto result = tcbInfoVerifier.verify(tcbInfoJsonVerifier, certificateChainMock, crlStoreMock, certStoreMock);

    // THEN
    EXPECT_EQ(STATUS_OK, result);
}

TEST_F(TCBInfoVerifierUT, shouldReturnedRootCaMissingWhenTcbSigningChainVerifyFail)
{
    // GIVEN
    auto commonVerifierMock = std::make_unique<StrictMock<test::CommonVerifierMock>>();
    auto pckCrlVerifierMock = std::make_unique<StrictMock<test::PckCrlVerifierMock>>();
    auto tcbSigningChainMock = std::make_unique<StrictMock<test::TcbSigningChainMock>>();
    StrictMock<test::CertificateChainMock> certificateChainMock;
    StrictMock<test::CertStoreMock> certStoreMock;
    StrictMock<test::CrlStoreMock> crlStoreMock;
    auto certStoreMockPtr = std::make_shared<StrictMock<test::CertStoreMock>>();

    EXPECT_CALL(*tcbSigningChainMock, verify(_, _, _)).WillOnce(Return(STATUS_SGX_ROOT_CA_MISSING));

    TCBInfoVerifier tcbInfoVerifier(std::move(commonVerifierMock), std::move(tcbSigningChainMock));

    // WHEN
    auto result = tcbInfoVerifier.verify(tcbInfoJsonVerifier, certificateChainMock, crlStoreMock, certStoreMock);

    // THEN
    EXPECT_EQ(STATUS_SGX_ROOT_CA_MISSING, result);
}

TEST_F(TCBInfoVerifierUT, shouldReturnedInfoInvalidSignatureWhenCheckSha256EcdsaSignatureFail)
{
    // GIVEN
    auto commonVerifierMock = std::make_unique<StrictMock<test::CommonVerifierMock>>();
    auto pckCrlVerifierMock = std::make_unique<StrictMock<test::PckCrlVerifierMock>>();
    auto tcbSigningChainMock = std::make_unique<StrictMock<test::TcbSigningChainMock>>();
    StrictMock<test::CertificateChainMock> certificateChainMock;
    StrictMock<test::CertStoreMock> certStoreMock;
    StrictMock<test::CrlStoreMock> crlStoreMock;
    auto certStoreMockPtr = std::make_shared<StrictMock<test::CertStoreMock>>();

    EXPECT_CALL(*commonVerifierMock, checkSha256EcdsaSignature(_, _, _)).WillOnce(Return(false));

    EXPECT_CALL(*tcbSigningChainMock, verify(_, _, _)).WillOnce(Return(STATUS_OK));

    EXPECT_CALL(certificateChainMock, get(_)).WillRepeatedly(Return(certStoreMockPtr));

    EXPECT_CALL(*certStoreMockPtr, getPubKey()).WillOnce(ReturnRef(*pubKey));

    TCBInfoVerifier tcbInfoVerifier(std::move(commonVerifierMock), std::move(tcbSigningChainMock));

    // WHEN
    auto result = tcbInfoVerifier.verify(tcbInfoJsonVerifier, certificateChainMock, crlStoreMock, certStoreMock);

    // THEN
    EXPECT_EQ(STATUS_TCB_INFO_INVALID_SIGNATURE, result);
}
