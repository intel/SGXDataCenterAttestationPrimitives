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
#include <Verifiers/PckCertVerifier.h>
#include <Mocks/CertCrlStoresMocks.h>
#include <Mocks/CommonVerifierMock.h>
#include <Mocks/PckCrlVerifierMock.h>
#include <CertVerification/X509Constants.h>
#include <PckParser/PckParser.h>

using namespace testing;
using namespace intel::sgx::qvl;


struct VerifyPckCertUT : public Test
{
    std::vector<pckparser::Extension> extensions;
    std::vector<pckparser::SgxExtension> sgxExtensions;
    pckparser::Signature signature;
};

TEST_F(VerifyPckCertUT, shouldReturnedStatusOkWhenVerifyPassPositive)
{
    // GIVEN
    auto commonVerifierMock = std::make_unique<StrictMock<test::CommonVerifierMock>>();
    auto pckCrlVerifierMock = std::make_unique<StrictMock<test::PckCrlVerifierMock>>();
    StrictMock<test::CertificateChainMock> certificateChainMock;
    StrictMock<test::CertStoreMock> trustedRootMock;
    StrictMock<test::CrlStoreMock> crlStoreMock;
    auto rootCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto intermediateCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto pckCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();

    EXPECT_CALL(*commonVerifierMock, verifyRootCACert(_)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(*commonVerifierMock, verifyIntermediate(_, _)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(*commonVerifierMock, checkStandardExtensions(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*commonVerifierMock, checkSGXExtensions(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*commonVerifierMock, checkSignature(
            An<const pckparser::CertStore&>(), An<const pckparser::CertStore&>())).WillOnce(Return(true));

    EXPECT_CALL(*pckCrlVerifierMock, verify(_, _)).WillRepeatedly(Return(STATUS_OK));

    EXPECT_CALL(certificateChainMock, getRootCert()).WillRepeatedly(Return(rootCertMock));
    EXPECT_CALL(certificateChainMock, getIntermediateCert()).WillRepeatedly(Return(intermediateCertMock));
    EXPECT_CALL(certificateChainMock, getTopmostCert()).WillRepeatedly(Return(pckCertMock));

    EXPECT_CALL(*rootCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::ROOT_CA_SUBJECT));
    EXPECT_CALL(*rootCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(*rootCertMock, getSignature()).WillOnce(ReturnRef(signature));

    EXPECT_CALL(*intermediateCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PLATFORM_CA_SUBJECT));
    EXPECT_CALL(*intermediateCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(*pckCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PCK_SUBJECT));
    EXPECT_CALL(*pckCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::PCK_PLATFORM_CRL_ISSUER));

    EXPECT_CALL(crlStoreMock, isRevoked(_)).WillRepeatedly(Return(false));

    EXPECT_CALL(trustedRootMock, getSubject()).WillOnce(ReturnRef(constants::ROOT_CA_SUBJECT));
    EXPECT_CALL(trustedRootMock, getIssuer()).WillOnce(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(trustedRootMock, getSignature()).WillOnce(ReturnRef(signature));

    EXPECT_CALL(*pckCertMock, expired()).WillOnce(Return(false));

    EXPECT_CALL(*pckCertMock, getExtensions()).WillOnce(ReturnRef(extensions));
    EXPECT_CALL(*pckCertMock, getSGXExtensions()).WillOnce(ReturnRef(sgxExtensions));

    PckCertVerifier pckCertVerifier(std::move(commonVerifierMock), std::move(pckCrlVerifierMock));

    // WHEN
    auto result = pckCertVerifier.verify(certificateChainMock, crlStoreMock, crlStoreMock, trustedRootMock);

    // THEN
    EXPECT_EQ(STATUS_OK, result);
}

TEST_F(VerifyPckCertUT, sholuldReturnPckRevokedWhenCrlIsRevoked)
{
    // GIVEN
    auto commonVerifierMock = std::make_unique<StrictMock<test::CommonVerifierMock>>();
    auto pckCrlVerifierMock = std::make_unique<StrictMock<test::PckCrlVerifierMock>>();
    StrictMock<test::CertificateChainMock> certificateChainMock;
    StrictMock<test::CertStoreMock> trustedRootMock;
    StrictMock<test::CrlStoreMock> crlStoreMock;
    auto rootCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto intermediateCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto pckCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();

    EXPECT_CALL(*commonVerifierMock, verifyRootCACert(_)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(*commonVerifierMock, verifyIntermediate(_, _)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(*commonVerifierMock, checkStandardExtensions(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*commonVerifierMock, checkSGXExtensions(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*commonVerifierMock, checkSignature(
            An<const pckparser::CertStore&>(), An<const pckparser::CertStore&>())).WillOnce(Return(true));

    EXPECT_CALL(*pckCrlVerifierMock, verify(_, _)).WillRepeatedly(Return(STATUS_OK));

    EXPECT_CALL(certificateChainMock, getRootCert()).WillRepeatedly(Return(rootCertMock));
    EXPECT_CALL(certificateChainMock, getIntermediateCert()).WillRepeatedly(Return(intermediateCertMock));
    EXPECT_CALL(certificateChainMock, getTopmostCert()).WillRepeatedly(Return(pckCertMock));

    EXPECT_CALL(*rootCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::ROOT_CA_SUBJECT));
    EXPECT_CALL(*rootCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(*rootCertMock, getSignature()).WillOnce(ReturnRef(signature));

    EXPECT_CALL(*intermediateCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PLATFORM_CA_SUBJECT));
    EXPECT_CALL(*intermediateCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(*pckCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PCK_SUBJECT));
    EXPECT_CALL(*pckCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::PCK_PLATFORM_CRL_ISSUER));

    EXPECT_CALL(crlStoreMock, isRevoked(_))
            .WillOnce(Return(false))
            .WillOnce(Return(true));

    EXPECT_CALL(trustedRootMock, getSubject()).WillOnce(ReturnRef(constants::ROOT_CA_SUBJECT));
    EXPECT_CALL(trustedRootMock, getIssuer()).WillOnce(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(trustedRootMock, getSignature()).WillOnce(ReturnRef(signature));

    EXPECT_CALL(*pckCertMock, expired()).WillOnce(Return(false));

    EXPECT_CALL(*pckCertMock, getExtensions()).WillOnce(ReturnRef(extensions));
    EXPECT_CALL(*pckCertMock, getSGXExtensions()).WillOnce(ReturnRef(sgxExtensions));

    PckCertVerifier pckCertVerifier(std::move(commonVerifierMock), std::move(pckCrlVerifierMock));

    // WHEN
    auto result = pckCertVerifier.verify(certificateChainMock, crlStoreMock, crlStoreMock, trustedRootMock);

    // THEN
    EXPECT_EQ(STATUS_SGX_PCK_REVOKED, result);
}

TEST_F(VerifyPckCertUT, sholuldReturnIntermiediateCaRevokedWhenCrlIsRevoked)
{
    // GIVEN
    auto commonVerifierMock = std::make_unique<StrictMock<test::CommonVerifierMock>>();
    auto pckCrlVerifierMock = std::make_unique<StrictMock<test::PckCrlVerifierMock>>();
    StrictMock<test::CertificateChainMock> certificateChainMock;
    StrictMock<test::CertStoreMock> trustedRootMock;
    StrictMock<test::CrlStoreMock> crlStoreMock;
    auto rootCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto intermediateCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto pckCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();

    EXPECT_CALL(*commonVerifierMock, verifyRootCACert(_)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(*commonVerifierMock, verifyIntermediate(_, _)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(*commonVerifierMock, checkStandardExtensions(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*commonVerifierMock, checkSGXExtensions(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*commonVerifierMock, checkSignature(
            An<const pckparser::CertStore&>(), An<const pckparser::CertStore&>())).WillOnce(Return(true));

    EXPECT_CALL(*pckCrlVerifierMock, verify(_, _)).WillRepeatedly(Return(STATUS_OK));

    EXPECT_CALL(certificateChainMock, getRootCert()).WillRepeatedly(Return(rootCertMock));
    EXPECT_CALL(certificateChainMock, getIntermediateCert()).WillRepeatedly(Return(intermediateCertMock));
    EXPECT_CALL(certificateChainMock, getTopmostCert()).WillRepeatedly(Return(pckCertMock));

    EXPECT_CALL(*rootCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::ROOT_CA_SUBJECT));
    EXPECT_CALL(*rootCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(*rootCertMock, getSignature()).WillOnce(ReturnRef(signature));

    EXPECT_CALL(*intermediateCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PLATFORM_CA_SUBJECT));
    EXPECT_CALL(*intermediateCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(*pckCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PCK_SUBJECT));
    EXPECT_CALL(*pckCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::PCK_PLATFORM_CRL_ISSUER));

    EXPECT_CALL(crlStoreMock, isRevoked(_)).WillRepeatedly(Return(true));

    EXPECT_CALL(trustedRootMock, getSubject()).WillOnce(ReturnRef(constants::ROOT_CA_SUBJECT));
    EXPECT_CALL(trustedRootMock, getIssuer()).WillOnce(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(trustedRootMock, getSignature()).WillOnce(ReturnRef(signature));

    EXPECT_CALL(*pckCertMock, expired()).WillOnce(Return(false));

    EXPECT_CALL(*pckCertMock, getExtensions()).WillOnce(ReturnRef(extensions));
    EXPECT_CALL(*pckCertMock, getSGXExtensions()).WillOnce(ReturnRef(sgxExtensions));

    PckCertVerifier pckCertVerifier(std::move(commonVerifierMock), std::move(pckCrlVerifierMock));

    // WHEN
    auto result = pckCertVerifier.verify(certificateChainMock, crlStoreMock, crlStoreMock, trustedRootMock);

    // THEN
    EXPECT_EQ(STATUS_SGX_INTERMEDIATE_CA_REVOKED, result);
}

TEST_F(VerifyPckCertUT, sholuldReturnCrlInvalidWhenCrlIntermediateVerifierFail)
{
    // GIVEN
    auto commonVerifierMock = std::make_unique<StrictMock<test::CommonVerifierMock>>();
    auto pckCrlVerifierMock = std::make_unique<StrictMock<test::PckCrlVerifierMock>>();
    StrictMock<test::CertificateChainMock> certificateChainMock;
    StrictMock<test::CertStoreMock> trustedRootMock;
    StrictMock<test::CrlStoreMock> crlStoreMock;
    auto rootCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto intermediateCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto pckCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();

    EXPECT_CALL(*commonVerifierMock, verifyRootCACert(_)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(*commonVerifierMock, verifyIntermediate(_, _)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(*commonVerifierMock, checkStandardExtensions(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*commonVerifierMock, checkSGXExtensions(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*commonVerifierMock, checkSignature(
            An<const pckparser::CertStore&>(), An<const pckparser::CertStore&>())).WillOnce(Return(true));

    EXPECT_CALL(*pckCrlVerifierMock, verify(_, _))
            .WillOnce(Return(STATUS_OK))
            .WillOnce(Return(STATUS_SGX_CRL_INVALID));

    EXPECT_CALL(certificateChainMock, getRootCert()).WillRepeatedly(Return(rootCertMock));
    EXPECT_CALL(certificateChainMock, getIntermediateCert()).WillRepeatedly(Return(intermediateCertMock));
    EXPECT_CALL(certificateChainMock, getTopmostCert()).WillRepeatedly(Return(pckCertMock));

    EXPECT_CALL(*rootCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::ROOT_CA_SUBJECT));
    EXPECT_CALL(*rootCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(*rootCertMock, getSignature()).WillOnce(ReturnRef(signature));

    EXPECT_CALL(*intermediateCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PLATFORM_CA_SUBJECT));
    EXPECT_CALL(*intermediateCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(*pckCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PCK_SUBJECT));
    EXPECT_CALL(*pckCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::PCK_PLATFORM_CRL_ISSUER));

    EXPECT_CALL(crlStoreMock, isRevoked(_)).WillRepeatedly(Return(false));

    EXPECT_CALL(trustedRootMock, getSubject()).WillOnce(ReturnRef(constants::ROOT_CA_SUBJECT));
    EXPECT_CALL(trustedRootMock, getIssuer()).WillOnce(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(trustedRootMock, getSignature()).WillOnce(ReturnRef(signature));

    EXPECT_CALL(*pckCertMock, expired()).WillOnce(Return(false));

    EXPECT_CALL(*pckCertMock, getExtensions()).WillOnce(ReturnRef(extensions));
    EXPECT_CALL(*pckCertMock, getSGXExtensions()).WillOnce(ReturnRef(sgxExtensions));

    PckCertVerifier pckCertVerifier(std::move(commonVerifierMock), std::move(pckCrlVerifierMock));

    // WHEN
    auto result = pckCertVerifier.verify(certificateChainMock, crlStoreMock, crlStoreMock, trustedRootMock);

    // THEN
    EXPECT_EQ(STATUS_SGX_CRL_INVALID, result);
}

TEST_F(VerifyPckCertUT, sholuldReturnCrlInvalidWhenCrlRootVerifierFail)
{
    // GIVEN
    auto commonVerifierMock = std::make_unique<StrictMock<test::CommonVerifierMock>>();
    auto pckCrlVerifierMock = std::make_unique<StrictMock<test::PckCrlVerifierMock>>();
    StrictMock<test::CertificateChainMock> certificateChainMock;
    StrictMock<test::CertStoreMock> trustedRootMock;
    StrictMock<test::CrlStoreMock> crlStoreMock;
    auto rootCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto intermediateCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto pckCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();

    EXPECT_CALL(*commonVerifierMock, verifyRootCACert(_)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(*commonVerifierMock, verifyIntermediate(_, _)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(*commonVerifierMock, checkStandardExtensions(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*commonVerifierMock, checkSGXExtensions(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*commonVerifierMock, checkSignature(
            An<const pckparser::CertStore&>(), An<const pckparser::CertStore&>())).WillOnce(Return(true));

    EXPECT_CALL(*pckCrlVerifierMock, verify(_, _))
            .WillOnce(Return(STATUS_SGX_CRL_INVALID));

    EXPECT_CALL(certificateChainMock, getRootCert()).WillRepeatedly(Return(rootCertMock));
    EXPECT_CALL(certificateChainMock, getIntermediateCert()).WillRepeatedly(Return(intermediateCertMock));
    EXPECT_CALL(certificateChainMock, getTopmostCert()).WillRepeatedly(Return(pckCertMock));

    EXPECT_CALL(*rootCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::ROOT_CA_SUBJECT));
    EXPECT_CALL(*rootCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(*rootCertMock, getSignature()).WillOnce(ReturnRef(signature));

    EXPECT_CALL(*intermediateCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PLATFORM_CA_SUBJECT));
    EXPECT_CALL(*intermediateCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(*pckCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PCK_SUBJECT));
    EXPECT_CALL(*pckCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::PCK_PLATFORM_CRL_ISSUER));

    EXPECT_CALL(crlStoreMock, isRevoked(_)).WillRepeatedly(Return(false));

    EXPECT_CALL(trustedRootMock, getSubject()).WillOnce(ReturnRef(constants::ROOT_CA_SUBJECT));
    EXPECT_CALL(trustedRootMock, getIssuer()).WillOnce(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(trustedRootMock, getSignature()).WillOnce(ReturnRef(signature));

    EXPECT_CALL(*pckCertMock, expired()).WillOnce(Return(false));

    EXPECT_CALL(*pckCertMock, getExtensions()).WillOnce(ReturnRef(extensions));
    EXPECT_CALL(*pckCertMock, getSGXExtensions()).WillOnce(ReturnRef(sgxExtensions));

    PckCertVerifier pckCertVerifier(std::move(commonVerifierMock), std::move(pckCrlVerifierMock));

    // WHEN
    auto result = pckCertVerifier.verify(certificateChainMock, crlStoreMock, crlStoreMock, trustedRootMock);

    // THEN
    EXPECT_EQ(STATUS_SGX_CRL_INVALID, result);
}

TEST_F(VerifyPckCertUT, sholuldReturnPckCertUnTrustedWhenSigantureIsWrong)
{
    // GIVEN
    pckparser::Signature wrongSignature;
    wrongSignature.rawDer.push_back(1);
    auto commonVerifierMock = std::make_unique<StrictMock<test::CommonVerifierMock>>();
    auto pckCrlVerifierMock = std::make_unique<StrictMock<test::PckCrlVerifierMock>>();
    StrictMock<test::CertificateChainMock> certificateChainMock;
    StrictMock<test::CertStoreMock> trustedRootMock;
    StrictMock<test::CrlStoreMock> crlStoreMock;
    auto rootCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto intermediateCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto pckCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();

    EXPECT_CALL(*commonVerifierMock, verifyRootCACert(_)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(*commonVerifierMock, verifyIntermediate(_, _)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(*commonVerifierMock, checkStandardExtensions(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*commonVerifierMock, checkSGXExtensions(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*commonVerifierMock, checkSignature(
            An<const pckparser::CertStore&>(), An<const pckparser::CertStore&>())).WillOnce(Return(true));

    EXPECT_CALL(*pckCrlVerifierMock, verify(_, _)).WillRepeatedly(Return(STATUS_OK));

    EXPECT_CALL(certificateChainMock, getRootCert()).WillRepeatedly(Return(rootCertMock));
    EXPECT_CALL(certificateChainMock, getIntermediateCert()).WillRepeatedly(Return(intermediateCertMock));
    EXPECT_CALL(certificateChainMock, getTopmostCert()).WillRepeatedly(Return(pckCertMock));

    EXPECT_CALL(*rootCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::ROOT_CA_SUBJECT));
    EXPECT_CALL(*rootCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(*rootCertMock, getSignature()).WillOnce(ReturnRef(wrongSignature));

    EXPECT_CALL(*intermediateCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PLATFORM_CA_SUBJECT));
    EXPECT_CALL(*intermediateCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(*pckCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PCK_SUBJECT));
    EXPECT_CALL(*pckCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::PCK_PLATFORM_CRL_ISSUER));

    EXPECT_CALL(crlStoreMock, isRevoked(_)).WillRepeatedly(Return(false));

    EXPECT_CALL(trustedRootMock, getSubject()).WillOnce(ReturnRef(constants::ROOT_CA_SUBJECT));
    EXPECT_CALL(trustedRootMock, getIssuer()).WillOnce(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(trustedRootMock, getSignature()).WillOnce(ReturnRef(signature));

    EXPECT_CALL(*pckCertMock, expired()).WillOnce(Return(false));

    EXPECT_CALL(*pckCertMock, getExtensions()).WillOnce(ReturnRef(extensions));
    EXPECT_CALL(*pckCertMock, getSGXExtensions()).WillOnce(ReturnRef(sgxExtensions));

    PckCertVerifier pckCertVerifier(std::move(commonVerifierMock), std::move(pckCrlVerifierMock));

    // WHEN
    auto result = pckCertVerifier.verify(certificateChainMock, crlStoreMock, crlStoreMock, trustedRootMock);

    // THEN
    EXPECT_EQ(STATUS_SGX_PCK_CERT_CHAIN_UNTRUSTED, result);
}

TEST_F(VerifyPckCertUT, sholuldReturnTrustedRootCaInvalidWhenSubjectIsWrong)
{
    // GIVEN
    auto commonVerifierMock = std::make_unique<StrictMock<test::CommonVerifierMock>>();
    auto pckCrlVerifierMock = std::make_unique<StrictMock<test::PckCrlVerifierMock>>();
    StrictMock<test::CertificateChainMock> certificateChainMock;
    StrictMock<test::CertStoreMock> trustedRootMock;
    StrictMock<test::CrlStoreMock> crlStoreMock;
    auto rootCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto intermediateCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto pckCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();

    EXPECT_CALL(*commonVerifierMock, verifyRootCACert(_)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(*commonVerifierMock, verifyIntermediate(_, _)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(*commonVerifierMock, checkStandardExtensions(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*commonVerifierMock, checkSGXExtensions(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*commonVerifierMock, checkSignature(
            An<const pckparser::CertStore&>(), An<const pckparser::CertStore&>())).WillOnce(Return(true));

    EXPECT_CALL(*pckCrlVerifierMock, verify(_, _)).WillRepeatedly(Return(STATUS_OK));

    EXPECT_CALL(certificateChainMock, getRootCert()).WillRepeatedly(Return(rootCertMock));
    EXPECT_CALL(certificateChainMock, getIntermediateCert()).WillRepeatedly(Return(intermediateCertMock));
    EXPECT_CALL(certificateChainMock, getTopmostCert()).WillRepeatedly(Return(pckCertMock));

    EXPECT_CALL(*rootCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::ROOT_CA_SUBJECT));
    EXPECT_CALL(*rootCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));

    EXPECT_CALL(*intermediateCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PLATFORM_CA_SUBJECT));
    EXPECT_CALL(*intermediateCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(*pckCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PCK_SUBJECT));
    EXPECT_CALL(*pckCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::PCK_PLATFORM_CRL_ISSUER));

    EXPECT_CALL(crlStoreMock, isRevoked(_)).WillRepeatedly(Return(false));

    EXPECT_CALL(trustedRootMock, getSubject()).WillOnce(ReturnRef(constants::PCK_SUBJECT));
    EXPECT_CALL(trustedRootMock, getIssuer()).WillOnce(ReturnRef(constants::ROOT_CA_CRL_ISSUER));

    EXPECT_CALL(*pckCertMock, expired()).WillOnce(Return(false));

    EXPECT_CALL(*pckCertMock, getExtensions()).WillOnce(ReturnRef(extensions));
    EXPECT_CALL(*pckCertMock, getSGXExtensions()).WillOnce(ReturnRef(sgxExtensions));

    PckCertVerifier pckCertVerifier(std::move(commonVerifierMock), std::move(pckCrlVerifierMock));

    // WHEN
    auto result = pckCertVerifier.verify(certificateChainMock, crlStoreMock, crlStoreMock, trustedRootMock);

    // THEN
    EXPECT_EQ(STATUS_TRUSTED_ROOT_CA_INVALID, result);
}

TEST_F(VerifyPckCertUT, sholuldReturnPckInvalidExtensionsWhenSgxExtensionsIsWrong)
{
    // GIVEN
    auto commonVerifierMock = std::make_unique<StrictMock<test::CommonVerifierMock>>();
    auto pckCrlVerifierMock = std::make_unique<StrictMock<test::PckCrlVerifierMock>>();
    StrictMock<test::CertificateChainMock> certificateChainMock;
    StrictMock<test::CertStoreMock> trustedRootMock;
    StrictMock<test::CrlStoreMock> crlStoreMock;
    auto rootCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto intermediateCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto pckCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();

    EXPECT_CALL(*commonVerifierMock, verifyRootCACert(_)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(*commonVerifierMock, verifyIntermediate(_, _)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(*commonVerifierMock, checkStandardExtensions(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*commonVerifierMock, checkSGXExtensions(_, _)).WillOnce(Return(false));

    EXPECT_CALL(*pckCrlVerifierMock, verify(_, _)).WillRepeatedly(Return(STATUS_OK));

    EXPECT_CALL(certificateChainMock, getRootCert()).WillRepeatedly(Return(rootCertMock));
    EXPECT_CALL(certificateChainMock, getIntermediateCert()).WillRepeatedly(Return(intermediateCertMock));
    EXPECT_CALL(certificateChainMock, getTopmostCert()).WillRepeatedly(Return(pckCertMock));

    EXPECT_CALL(*rootCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::ROOT_CA_SUBJECT));
    EXPECT_CALL(*rootCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));

    EXPECT_CALL(*intermediateCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PLATFORM_CA_SUBJECT));
    EXPECT_CALL(*intermediateCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(*pckCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PCK_SUBJECT));
    EXPECT_CALL(*pckCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::PCK_PLATFORM_CRL_ISSUER));

    EXPECT_CALL(crlStoreMock, isRevoked(_)).WillRepeatedly(Return(false));

    EXPECT_CALL(*pckCertMock, expired()).WillOnce(Return(false));

    EXPECT_CALL(*pckCertMock, getExtensions()).WillOnce(ReturnRef(extensions));
    EXPECT_CALL(*pckCertMock, getSGXExtensions()).WillOnce(ReturnRef(sgxExtensions));

    PckCertVerifier pckCertVerifier(std::move(commonVerifierMock), std::move(pckCrlVerifierMock));

    // WHEN
    auto result = pckCertVerifier.verify(certificateChainMock, crlStoreMock, crlStoreMock, trustedRootMock);

    // THEN
    EXPECT_EQ(STATUS_SGX_PCK_INVALID_EXTENSIONS, result);
}

TEST_F(VerifyPckCertUT, sholuldReturnPckInvalidExtensionsWhenStandardExtensionsIsWrong)
{
    // GIVEN
    auto commonVerifierMock = std::make_unique<StrictMock<test::CommonVerifierMock>>();
    auto pckCrlVerifierMock = std::make_unique<StrictMock<test::PckCrlVerifierMock>>();
    StrictMock<test::CertificateChainMock> certificateChainMock;
    StrictMock<test::CertStoreMock> trustedRootMock;
    StrictMock<test::CrlStoreMock> crlStoreMock;
    auto rootCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto intermediateCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto pckCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();

    EXPECT_CALL(*commonVerifierMock, verifyRootCACert(_)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(*commonVerifierMock, verifyIntermediate(_, _)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(*commonVerifierMock, checkStandardExtensions(_, _)).WillOnce(Return(false));

    EXPECT_CALL(*pckCrlVerifierMock, verify(_, _)).WillRepeatedly(Return(STATUS_OK));

    EXPECT_CALL(certificateChainMock, getRootCert()).WillRepeatedly(Return(rootCertMock));
    EXPECT_CALL(certificateChainMock, getIntermediateCert()).WillRepeatedly(Return(intermediateCertMock));
    EXPECT_CALL(certificateChainMock, getTopmostCert()).WillRepeatedly(Return(pckCertMock));

    EXPECT_CALL(*rootCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::ROOT_CA_SUBJECT));
    EXPECT_CALL(*rootCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));

    EXPECT_CALL(*intermediateCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PLATFORM_CA_SUBJECT));
    EXPECT_CALL(*intermediateCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(*pckCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PCK_SUBJECT));
    EXPECT_CALL(*pckCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::PCK_PLATFORM_CRL_ISSUER));

    EXPECT_CALL(crlStoreMock, isRevoked(_)).WillRepeatedly(Return(false));

    EXPECT_CALL(*pckCertMock, expired()).WillOnce(Return(false));

    EXPECT_CALL(*pckCertMock, getExtensions()).WillOnce(ReturnRef(extensions));

    PckCertVerifier pckCertVerifier(std::move(commonVerifierMock), std::move(pckCrlVerifierMock));

    // WHEN
    auto result = pckCertVerifier.verify(certificateChainMock, crlStoreMock, crlStoreMock, trustedRootMock);

    // THEN
    EXPECT_EQ(STATUS_SGX_PCK_INVALID_EXTENSIONS, result);
}

TEST_F(VerifyPckCertUT, sholuldReturnPckInvalidWhenCertExpired)
{
    // GIVEN
    auto commonVerifierMock = std::make_unique<StrictMock<test::CommonVerifierMock>>();
    auto pckCrlVerifierMock = std::make_unique<StrictMock<test::PckCrlVerifierMock>>();
    StrictMock<test::CertificateChainMock> certificateChainMock;
    StrictMock<test::CertStoreMock> trustedRootMock;
    StrictMock<test::CrlStoreMock> crlStoreMock;
    auto rootCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto intermediateCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto pckCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();

    EXPECT_CALL(*commonVerifierMock, verifyRootCACert(_)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(*commonVerifierMock, verifyIntermediate(_, _)).WillOnce(Return(STATUS_OK));

    EXPECT_CALL(*pckCrlVerifierMock, verify(_, _)).WillRepeatedly(Return(STATUS_OK));

    EXPECT_CALL(certificateChainMock, getRootCert()).WillRepeatedly(Return(rootCertMock));
    EXPECT_CALL(certificateChainMock, getIntermediateCert()).WillRepeatedly(Return(intermediateCertMock));
    EXPECT_CALL(certificateChainMock, getTopmostCert()).WillRepeatedly(Return(pckCertMock));

    EXPECT_CALL(*rootCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::ROOT_CA_SUBJECT));
    EXPECT_CALL(*rootCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));

    EXPECT_CALL(*intermediateCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PLATFORM_CA_SUBJECT));
    EXPECT_CALL(*intermediateCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(*pckCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PCK_SUBJECT));
    EXPECT_CALL(*pckCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::PCK_PLATFORM_CRL_ISSUER));

    EXPECT_CALL(crlStoreMock, isRevoked(_)).WillRepeatedly(Return(false));

    EXPECT_CALL(*pckCertMock, expired()).WillOnce(Return(true));

    PckCertVerifier pckCertVerifier(std::move(commonVerifierMock), std::move(pckCrlVerifierMock));

    // WHEN
    auto result = pckCertVerifier.verify(certificateChainMock, crlStoreMock, crlStoreMock, trustedRootMock);

    // THEN
    EXPECT_EQ(STATUS_SGX_PCK_INVALID, result);
}

TEST_F(VerifyPckCertUT, sholuldReturnPckMissingWhenSubjectIsWrong)
{

    auto wrongSubject = constants::PCK_SUBJECT;
    wrongSubject.commonName = "test common name";
    // GIVEN
    auto commonVerifierMock = std::make_unique<StrictMock<test::CommonVerifierMock>>();
    auto pckCrlVerifierMock = std::make_unique<StrictMock<test::PckCrlVerifierMock>>();
    StrictMock<test::CertificateChainMock> certificateChainMock;
    StrictMock<test::CertStoreMock> trustedRootMock;
    StrictMock<test::CrlStoreMock> crlStoreMock;
    auto rootCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto intermediateCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto pckCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();

    EXPECT_CALL(*pckCrlVerifierMock, verify(_, _)).WillRepeatedly(Return(STATUS_OK));

    EXPECT_CALL(certificateChainMock, getRootCert()).WillRepeatedly(Return(rootCertMock));
    EXPECT_CALL(certificateChainMock, getIntermediateCert()).WillRepeatedly(Return(intermediateCertMock));
    EXPECT_CALL(certificateChainMock, getTopmostCert()).WillRepeatedly(Return(pckCertMock));

    EXPECT_CALL(*rootCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::ROOT_CA_SUBJECT));
    EXPECT_CALL(*rootCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));

    EXPECT_CALL(*intermediateCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PLATFORM_CA_SUBJECT));
    EXPECT_CALL(*intermediateCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(*pckCertMock, getSubject()).WillRepeatedly(ReturnRef(wrongSubject));
    EXPECT_CALL(*pckCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::PCK_PLATFORM_CRL_ISSUER));

    EXPECT_CALL(crlStoreMock, isRevoked(_)).WillRepeatedly(Return(false));

    PckCertVerifier pckCertVerifier(std::move(commonVerifierMock), std::move(pckCrlVerifierMock));

    // WHEN
    auto result = pckCertVerifier.verify(certificateChainMock, crlStoreMock, crlStoreMock, trustedRootMock);

    // THEN
    EXPECT_EQ(STATUS_SGX_PCK_MISSING, result);
}

TEST_F(VerifyPckCertUT, sholuldReturnInvalidIssuerWhenIssuerIsWrong)
{

    auto wrongIssuer = constants::PCK_PROCESSOR_CRL_ISSUER;
    wrongIssuer.commonName = "test common name";
    // GIVEN
    auto commonVerifierMock = std::make_unique<StrictMock<test::CommonVerifierMock>>();
    auto pckCrlVerifierMock = std::make_unique<StrictMock<test::PckCrlVerifierMock>>();
    StrictMock<test::CertificateChainMock> certificateChainMock;
    StrictMock<test::CertStoreMock> trustedRootMock;
    StrictMock<test::CrlStoreMock> crlStoreMock;
    auto rootCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto intermediateCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto pckCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();

    EXPECT_CALL(*commonVerifierMock, verifyRootCACert(_)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(*commonVerifierMock, verifyIntermediate(_, _)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(*commonVerifierMock, checkStandardExtensions(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*commonVerifierMock, checkSGXExtensions(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*pckCrlVerifierMock, verify(_, _)).WillRepeatedly(Return(STATUS_OK));

    EXPECT_CALL(certificateChainMock, getRootCert()).WillRepeatedly(Return(rootCertMock));
    EXPECT_CALL(certificateChainMock, getIntermediateCert()).WillRepeatedly(Return(intermediateCertMock));
    EXPECT_CALL(certificateChainMock, getTopmostCert()).WillRepeatedly(Return(pckCertMock));

    EXPECT_CALL(*rootCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::ROOT_CA_SUBJECT));
    EXPECT_CALL(*rootCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(*intermediateCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PLATFORM_CA_SUBJECT));
    EXPECT_CALL(*intermediateCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(*pckCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PCK_SUBJECT));
    EXPECT_CALL(*pckCertMock, getIssuer()).WillRepeatedly(ReturnRef(wrongIssuer));

    EXPECT_CALL(crlStoreMock, isRevoked(_)).WillRepeatedly(Return(false));

    EXPECT_CALL(*pckCertMock, expired()).WillOnce(Return(false));

    EXPECT_CALL(*pckCertMock, getExtensions()).WillOnce(ReturnRef(extensions));
    EXPECT_CALL(*pckCertMock, getSGXExtensions()).WillOnce(ReturnRef(sgxExtensions));

    PckCertVerifier pckCertVerifier(std::move(commonVerifierMock), std::move(pckCrlVerifierMock));

    // WHEN
    auto result = pckCertVerifier.verify(certificateChainMock, crlStoreMock, crlStoreMock, trustedRootMock);

    // THEN
    EXPECT_EQ(STATUS_SGX_PCK_INVALID_ISSUER, result);
}

TEST_F(VerifyPckCertUT, sholuldReturnInvalidIssuerWhenSignatureIsWrong)
{
    // GIVEN
    auto commonVerifierMock = std::make_unique<StrictMock<test::CommonVerifierMock>>();
    auto pckCrlVerifierMock = std::make_unique<StrictMock<test::PckCrlVerifierMock>>();
    StrictMock<test::CertificateChainMock> certificateChainMock;
    StrictMock<test::CertStoreMock> trustedRootMock;
    StrictMock<test::CrlStoreMock> crlStoreMock;
    auto rootCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto intermediateCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto pckCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();

    EXPECT_CALL(*commonVerifierMock, verifyRootCACert(_)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(*commonVerifierMock, verifyIntermediate(_, _)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(*commonVerifierMock, checkStandardExtensions(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*commonVerifierMock, checkSGXExtensions(_, _)).WillOnce(Return(true));
    EXPECT_CALL(*commonVerifierMock, checkSignature(
            An<const pckparser::CertStore&>(), An<const pckparser::CertStore&>())).WillOnce(Return(false));

    EXPECT_CALL(*pckCrlVerifierMock, verify(_, _)).WillRepeatedly(Return(STATUS_OK));

    EXPECT_CALL(certificateChainMock, getRootCert()).WillRepeatedly(Return(rootCertMock));
    EXPECT_CALL(certificateChainMock, getIntermediateCert()).WillRepeatedly(Return(intermediateCertMock));
    EXPECT_CALL(certificateChainMock, getTopmostCert()).WillRepeatedly(Return(pckCertMock));

    EXPECT_CALL(*rootCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::ROOT_CA_SUBJECT));
    EXPECT_CALL(*rootCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));

    EXPECT_CALL(*intermediateCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PLATFORM_CA_SUBJECT));
    EXPECT_CALL(*intermediateCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(*pckCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PCK_SUBJECT));
    EXPECT_CALL(*pckCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::PCK_PLATFORM_CRL_ISSUER));

    EXPECT_CALL(crlStoreMock, isRevoked(_)).WillRepeatedly(Return(false));

    EXPECT_CALL(*pckCertMock, expired()).WillOnce(Return(false));

    EXPECT_CALL(*pckCertMock, getExtensions()).WillOnce(ReturnRef(extensions));
    EXPECT_CALL(*pckCertMock, getSGXExtensions()).WillOnce(ReturnRef(sgxExtensions));

    PckCertVerifier pckCertVerifier(std::move(commonVerifierMock), std::move(pckCrlVerifierMock));

    // WHEN
    auto result = pckCertVerifier.verify(certificateChainMock, crlStoreMock, crlStoreMock, trustedRootMock);

    // THEN
    EXPECT_EQ(STATUS_SGX_PCK_INVALID_ISSUER, result);
}

TEST_F(VerifyPckCertUT, sholuldReturnIntermediateMissingWhenVerifyIntermediateFail)
{
    // GIVEN
    auto commonVerifierMock = std::make_unique<StrictMock<test::CommonVerifierMock>>();
    auto pckCrlVerifierMock = std::make_unique<StrictMock<test::PckCrlVerifierMock>>();
    StrictMock<test::CertificateChainMock> certificateChainMock;
    StrictMock<test::CertStoreMock> trustedRootMock;
    StrictMock<test::CrlStoreMock> crlStoreMock;
    auto rootCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto intermediateCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto pckCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();

    EXPECT_CALL(*commonVerifierMock, verifyRootCACert(_)).WillOnce(Return(STATUS_OK));
    EXPECT_CALL(*commonVerifierMock, verifyIntermediate(_, _)).WillOnce(Return(STATUS_SGX_INTERMEDIATE_CA_MISSING));

    EXPECT_CALL(*pckCrlVerifierMock, verify(_, _)).WillRepeatedly(Return(STATUS_OK));

    EXPECT_CALL(certificateChainMock, getRootCert()).WillRepeatedly(Return(rootCertMock));
    EXPECT_CALL(certificateChainMock, getIntermediateCert()).WillRepeatedly(Return(intermediateCertMock));
    EXPECT_CALL(certificateChainMock, getTopmostCert()).WillRepeatedly(Return(pckCertMock));

    EXPECT_CALL(*rootCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::ROOT_CA_SUBJECT));
    EXPECT_CALL(*rootCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));

    EXPECT_CALL(*intermediateCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PLATFORM_CA_SUBJECT));
    EXPECT_CALL(*intermediateCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(*pckCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PCK_SUBJECT));
    EXPECT_CALL(*pckCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::PCK_PLATFORM_CRL_ISSUER));

    EXPECT_CALL(crlStoreMock, isRevoked(_)).WillRepeatedly(Return(false));

    PckCertVerifier pckCertVerifier(std::move(commonVerifierMock), std::move(pckCrlVerifierMock));

    // WHEN
    auto result = pckCertVerifier.verify(certificateChainMock, crlStoreMock, crlStoreMock, trustedRootMock);

    // THEN
    EXPECT_EQ(STATUS_SGX_INTERMEDIATE_CA_MISSING, result);
}

TEST_F(VerifyPckCertUT, sholuldReturnRootCaMissingWhenVerifyRootCaFail)
{
    // GIVEN
    auto commonVerifierMock = std::make_unique<StrictMock<test::CommonVerifierMock>>();
    auto pckCrlVerifierMock = std::make_unique<StrictMock<test::PckCrlVerifierMock>>();
    StrictMock<test::CertificateChainMock> certificateChainMock;
    StrictMock<test::CertStoreMock> trustedRootMock;
    StrictMock<test::CrlStoreMock> crlStoreMock;
    auto rootCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto intermediateCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto pckCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();

    EXPECT_CALL(*commonVerifierMock, verifyRootCACert(_)).WillOnce(Return(STATUS_SGX_ROOT_CA_MISSING));

    EXPECT_CALL(*pckCrlVerifierMock, verify(_, _)).WillRepeatedly(Return(STATUS_OK));

    EXPECT_CALL(certificateChainMock, getRootCert()).WillRepeatedly(Return(rootCertMock));
    EXPECT_CALL(certificateChainMock, getIntermediateCert()).WillRepeatedly(Return(intermediateCertMock));
    EXPECT_CALL(certificateChainMock, getTopmostCert()).WillRepeatedly(Return(pckCertMock));

    EXPECT_CALL(*rootCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::ROOT_CA_SUBJECT));
    EXPECT_CALL(*rootCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));

    EXPECT_CALL(*intermediateCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PLATFORM_CA_SUBJECT));
    EXPECT_CALL(*intermediateCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));
    EXPECT_CALL(*pckCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PCK_SUBJECT));
    EXPECT_CALL(*pckCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::PCK_PLATFORM_CRL_ISSUER));
    EXPECT_CALL(crlStoreMock, isRevoked(_)).WillRepeatedly(Return(false));

    PckCertVerifier pckCertVerifier(std::move(commonVerifierMock), std::move(pckCrlVerifierMock));

    // WHEN
    auto result = pckCertVerifier.verify(certificateChainMock, crlStoreMock, crlStoreMock, trustedRootMock);

    // THEN
    EXPECT_EQ(STATUS_SGX_ROOT_CA_MISSING, result);
}

TEST_F(VerifyPckCertUT, sholuldReturnPckMissingWhenPckCertIsNotPresent)
{
    // GIVEN
    auto commonVerifierMock = std::make_unique<StrictMock<test::CommonVerifierMock>>();
    auto pckCrlVerifierMock = std::make_unique<StrictMock<test::PckCrlVerifierMock>>();
    StrictMock<test::CertificateChainMock> certificateChainMock;
    StrictMock<test::CertStoreMock> trustedRootMock;
    StrictMock<test::CrlStoreMock> crlStoreMock;
    auto rootCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto intermediateCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto pckCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();

    EXPECT_CALL(*pckCrlVerifierMock, verify(_, _)).WillRepeatedly(Return(STATUS_OK));

    EXPECT_CALL(certificateChainMock, getRootCert()).WillRepeatedly(Return(rootCertMock));
    EXPECT_CALL(certificateChainMock, getIntermediateCert()).WillRepeatedly(Return(intermediateCertMock));
    EXPECT_CALL(certificateChainMock, getTopmostCert()).WillRepeatedly(Return(nullptr));

    EXPECT_CALL(*rootCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::ROOT_CA_SUBJECT));
    EXPECT_CALL(*rootCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));

    EXPECT_CALL(*intermediateCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::PLATFORM_CA_SUBJECT));
    EXPECT_CALL(*intermediateCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));

    PckCertVerifier pckCertVerifier(std::move(commonVerifierMock), std::move(pckCrlVerifierMock));

    // WHEN
    auto result = pckCertVerifier.verify(certificateChainMock, crlStoreMock, crlStoreMock, trustedRootMock);

    // THEN
    EXPECT_EQ(STATUS_SGX_PCK_MISSING, result);
}

TEST_F(VerifyPckCertUT, sholuldReturnIntermediateMissingWhenIntermediateCertIsNotPresent)
{
    // GIVEN
    auto commonVerifierMock = std::make_unique<StrictMock<test::CommonVerifierMock>>();
    auto pckCrlVerifierMock = std::make_unique<StrictMock<test::PckCrlVerifierMock>>();
    StrictMock<test::CertificateChainMock> certificateChainMock;
    StrictMock<test::CertStoreMock> trustedRootMock;
    StrictMock<test::CrlStoreMock> crlStoreMock;
    auto rootCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();
    auto intermediateCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();

    EXPECT_CALL(*pckCrlVerifierMock, verify(_, _)).WillRepeatedly(Return(STATUS_OK));

    EXPECT_CALL(certificateChainMock, getRootCert()).WillRepeatedly(Return(rootCertMock));
    EXPECT_CALL(certificateChainMock, getIntermediateCert()).WillRepeatedly(Return(nullptr));

    EXPECT_CALL(*rootCertMock, getSubject()).WillRepeatedly(ReturnRef(constants::ROOT_CA_SUBJECT));
    EXPECT_CALL(*rootCertMock, getIssuer()).WillRepeatedly(ReturnRef(constants::ROOT_CA_CRL_ISSUER));

    PckCertVerifier pckCertVerifier(std::move(commonVerifierMock), std::move(pckCrlVerifierMock));

    // WHEN
    auto result = pckCertVerifier.verify(certificateChainMock, crlStoreMock, crlStoreMock, trustedRootMock);

    // THEN
    EXPECT_EQ(STATUS_SGX_INTERMEDIATE_CA_MISSING, result);
}

TEST_F(VerifyPckCertUT, sholuldReturnRootCaMissingWhenRootCaCertIsNotPresent)
{
    // GIVEN
    auto commonVerifierMock = std::make_unique<StrictMock<test::CommonVerifierMock>>();
    auto pckCrlVerifierMock = std::make_unique<StrictMock<test::PckCrlVerifierMock>>();
    StrictMock<test::CertificateChainMock> certificateChainMock;
    StrictMock<test::CertStoreMock> trustedRootMock;
    StrictMock<test::CrlStoreMock> crlStoreMock;

    auto rootCertMock = std::make_shared<StrictMock<test::CertStoreMock>>();

    EXPECT_CALL(certificateChainMock, getRootCert()).WillRepeatedly(Return(nullptr));

    PckCertVerifier pckCertVerifier(std::move(commonVerifierMock), std::move(pckCrlVerifierMock));

    // WHEN
    auto result = pckCertVerifier.verify(certificateChainMock, crlStoreMock, crlStoreMock, trustedRootMock);

    // THEN
    EXPECT_EQ(STATUS_SGX_ROOT_CA_MISSING, result);
}