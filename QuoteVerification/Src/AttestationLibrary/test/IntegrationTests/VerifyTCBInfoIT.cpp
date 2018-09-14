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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <SgxEcdsaAttestation/QuoteVerification.h>
#include <TcbInfoGenerator.h>
#include "ReadFile.h"

using namespace testing;

struct TCBInfoVerificationTests : public Test
{
    const char placeholder[8] = "1234567";

    std::string tcbSigning;
    std::string pemRootCrl;
    std::string pemRoot;

    void readNonEmptyTextFile(std::string &destination, const std::string &path) const
    {
        destination = readTextFile(path);
        ASSERT_FALSE(destination.empty()) << "File at path: " << path << " is either empty or inaccessible";
    }
};

TEST_F(TCBInfoVerificationTests, nullptrArgumentsShouldReturnUnsupportedCertStatus)
{
    ASSERT_EQ(STATUS_UNSUPPORTED_CERT_FORMAT, sgxAttestationVerifyTCBInfo(nullptr, nullptr, nullptr, nullptr));
}

TEST_F(TCBInfoVerificationTests, nullptrTCBInfoShoudReturnUnsupportedCertStatus)
{
    ASSERT_EQ(STATUS_UNSUPPORTED_CERT_FORMAT, sgxAttestationVerifyTCBInfo(nullptr, placeholder, placeholder, placeholder));
}

TEST_F(TCBInfoVerificationTests, nullptrCertChainShoudReturnUnsupportedCertStatus)
{
    ASSERT_EQ(STATUS_UNSUPPORTED_CERT_FORMAT, sgxAttestationVerifyTCBInfo(placeholder, nullptr, placeholder, placeholder));
}

TEST_F(TCBInfoVerificationTests, nullptrRootCrlShoudReturnUnsupportedCertStatus)
{
    ASSERT_EQ(STATUS_UNSUPPORTED_CERT_FORMAT, sgxAttestationVerifyTCBInfo(placeholder, placeholder, nullptr, placeholder));
}

TEST_F(TCBInfoVerificationTests, nullptrRootCertShoudReturnUnsupportedCertStatus)
{
    ASSERT_EQ(STATUS_UNSUPPORTED_CERT_FORMAT, sgxAttestationVerifyTCBInfo(placeholder, placeholder, placeholder, nullptr));
}

TEST_F(TCBInfoVerificationTests, nonJsonStringAsTCBInfoShouldReturnUnsupportedFormatStatus)
{
    const char invalidTcbInfo[] = "Just a plain string.";
    ASSERT_EQ(STATUS_SGX_TCB_INFO_UNSUPPORTED_FORMAT, sgxAttestationVerifyTCBInfo(invalidTcbInfo, placeholder, placeholder, placeholder));
}

TEST_F(TCBInfoVerificationTests, positive)
{
    // GIVEN
    readNonEmptyTextFile(tcbSigning, "VerifyTCBInfo/valid_tcb.pem");
    readNonEmptyTextFile(pemRootCrl, "VerifyTCBInfo/valid_root_crl.pem");
    readNonEmptyTextFile(pemRoot, "VerifyTCBInfo/valid_root.pem");
    const char tcbInfoSignatureTemplate[] = R"json("signature": "62f2eb97227d906c158e8500964c8d10029e1a318e0e95054fbc1b9636913555d7147ceefe07c4cb7ac1ac700093e2ee3fd4f7d00c7caf135dc5243be51e1def")json";
    auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, generateTcbLevel(), tcbInfoSignatureTemplate);

    // WHEN
    const auto verificationResult = sgxAttestationVerifyTCBInfo(tcbInfoJson.data(), tcbSigning.c_str(), pemRootCrl.c_str(), pemRoot.c_str());

    // THEN
    EXPECT_EQ(STATUS_OK, verificationResult);
}

TEST_F(TCBInfoVerificationTests, shouldFailWhenTCBInfoIsNotAValidJson)
{
    // GIVEN
    readNonEmptyTextFile(tcbSigning, "VerifyTCBInfo/valid_tcb.pem");
    readNonEmptyTextFile(pemRootCrl, "VerifyTCBInfo/valid_root_crl.pem");
    readNonEmptyTextFile(pemRoot, "VerifyTCBInfo/valid_root.pem");
    const char invalidTcbInfo[] = R"json(tcbInfo: {"issueDate": "2017-10-04T11:10:45Z"}")json";

    // WHEN
    const auto verificationResult = sgxAttestationVerifyTCBInfo(invalidTcbInfo, tcbSigning.c_str(), pemRootCrl.c_str(), pemRoot.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_TCB_INFO_UNSUPPORTED_FORMAT, verificationResult);
}

TEST_F(TCBInfoVerificationTests, shouldFailWhenTCBInfoHasIncorrectSignature)
{
    // GIVEN
    readNonEmptyTextFile(tcbSigning, "VerifyTCBInfo/valid_tcb.pem");
    readNonEmptyTextFile(pemRootCrl, "VerifyTCBInfo/valid_root_crl.pem");
    readNonEmptyTextFile(pemRoot, "VerifyTCBInfo/valid_root.pem");
    const char tcbInfoSignatureTemplate[] = R"json("signature": "0000000000000000000000000000000000000000074c282930032dca36cdb5a771eb18156a31426e9b7f8e0cf5b62958feb24cb61557c26e666a1620cc4d7d9a")json";
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, generateTcbLevel(), tcbInfoSignatureTemplate);

    // WHEN
    const auto verificationResult = sgxAttestationVerifyTCBInfo(tcbInfoJson.data(), tcbSigning.c_str(), pemRootCrl.c_str(), pemRoot.c_str());

    // THEN
    EXPECT_EQ(STATUS_TCB_INFO_INVALID_SIGNATURE, verificationResult);
}

TEST_F(TCBInfoVerificationTests, shouldFailWhenTCBSigningCertChainIsTooLong)
{
    // GIVEN
    readNonEmptyTextFile(tcbSigning, "VerifyTCBInfo/TCBSigningCertChainTooLong/tcb.pem");
    readNonEmptyTextFile(pemRootCrl, "VerifyTCBInfo/TCBSigningCertChainTooLong/root_crl.pem");
    readNonEmptyTextFile(pemRoot, "VerifyTCBInfo/TCBSigningCertChainTooLong/root.pem");
    const auto tcbInfoJson = generateTcbInfo();

    // WHEN
    const auto verificationResult = sgxAttestationVerifyTCBInfo(tcbInfoJson.data(), tcbSigning.c_str(), pemRootCrl.c_str(), pemRoot.c_str());

    // THEN
    EXPECT_EQ(STATUS_UNSUPPORTED_CERT_FORMAT, verificationResult);
}

TEST_F(TCBInfoVerificationTests, shouldFailWhenTCBSigningCertIsCorrupted)
{
    // GIVEN
    readNonEmptyTextFile(tcbSigning, "VerifyTCBInfo/TCBSigningCertCorrupted/tcb.pem");
    readNonEmptyTextFile(pemRootCrl, "VerifyTCBInfo/TCBSigningCertCorrupted/root_crl.pem");
    readNonEmptyTextFile(pemRoot, "VerifyTCBInfo/TCBSigningCertCorrupted/root.pem");
    const auto tcbInfoJson = generateTcbInfo();

    // WHEN
    const auto verificationResult = sgxAttestationVerifyTCBInfo(tcbInfoJson.data(), tcbSigning.c_str(), pemRootCrl.c_str(), pemRoot.c_str());

    // THEN
    EXPECT_EQ(STATUS_UNSUPPORTED_CERT_FORMAT, verificationResult);
}

TEST_F(TCBInfoVerificationTests, shouldFailWhenTCBSigningCertSubjectIsInvalid)
{
    // GIVEN
    readNonEmptyTextFile(tcbSigning, "VerifyTCBInfo/TCBSigningCertInvalidSubject/tcb.pem");
    readNonEmptyTextFile(pemRootCrl, "VerifyTCBInfo/TCBSigningCertInvalidSubject/root_crl.pem");
    readNonEmptyTextFile(pemRoot, "VerifyTCBInfo/TCBSigningCertInvalidSubject/root.pem");
    const auto tcbInfoJson = generateTcbInfo();

    // WHEN
    const auto verificationResult = sgxAttestationVerifyTCBInfo(tcbInfoJson.data(), tcbSigning.c_str(), pemRootCrl.c_str(), pemRoot.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_TCB_SIGNING_CERT_MISSING, verificationResult);
}

TEST_F(TCBInfoVerificationTests, shouldFailWhenTCBSigningCertIsExpired)
{
    // GIVEN
    readNonEmptyTextFile(tcbSigning, "VerifyTCBInfo/TCBSigningExpired/tcb.pem");
    readNonEmptyTextFile(pemRootCrl, "VerifyTCBInfo/TCBSigningExpired/root_crl.pem");
    readNonEmptyTextFile(pemRoot, "VerifyTCBInfo/TCBSigningExpired/root.pem");
    const auto tcbInfoJson = generateTcbInfo();

    // WHEN
    const auto verificationResult = sgxAttestationVerifyTCBInfo(tcbInfoJson.data(), tcbSigning.c_str(), pemRootCrl.c_str(), pemRoot.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_TCB_SIGNING_CERT_INVALID, verificationResult);
}

TEST_F(TCBInfoVerificationTests, shouldFailWhenTCBSigningCertIsMissingRequiredExtensions)
{
    // GIVEN
    readNonEmptyTextFile(tcbSigning, "VerifyTCBInfo/TCBSigningCertWithoutRequiredExtensions/tcb.pem");
    readNonEmptyTextFile(pemRootCrl, "VerifyTCBInfo/TCBSigningCertWithoutRequiredExtensions/root_crl.pem");
    readNonEmptyTextFile(pemRoot, "VerifyTCBInfo/TCBSigningCertWithoutRequiredExtensions/root.pem");
    const auto tcbInfoJson = generateTcbInfo();

    // WHEN
    const auto verificationResult = sgxAttestationVerifyTCBInfo(tcbInfoJson.data(), tcbSigning.c_str(), pemRootCrl.c_str(), pemRoot.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_TCB_SIGNING_CERT_INVALID_EXTENSIONS, verificationResult);
}

TEST_F(TCBInfoVerificationTests, shouldFailWhenTCBSigningCertIssuerNameIsIncorrect)
{
    // GIVEN
    readNonEmptyTextFile(tcbSigning, "VerifyTCBInfo/TCBSigningCertIncorrectIssuer/tcb.pem");
    readNonEmptyTextFile(pemRootCrl, "VerifyTCBInfo/TCBSigningCertIncorrectIssuer/root_crl.pem");
    readNonEmptyTextFile(pemRoot, "VerifyTCBInfo/TCBSigningCertIncorrectIssuer/root.pem");
    const auto tcbInfoJson = generateTcbInfo();

    // WHEN
    const auto verificationResult = sgxAttestationVerifyTCBInfo(tcbInfoJson.data(), tcbSigning.c_str(), pemRootCrl.c_str(), pemRoot.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_TCB_SIGNING_CERT_INVALID_ISSUER, verificationResult);
}

TEST_F(TCBInfoVerificationTests, shouldFailWhenTCBSigningCertHasIncorrectSignature)
{
    // GIVEN
    readNonEmptyTextFile(tcbSigning, "VerifyTCBInfo/TCBSigningCertIncorrectSignature/tcb.pem");
    readNonEmptyTextFile(pemRootCrl, "VerifyTCBInfo/TCBSigningCertIncorrectSignature/root_crl.pem");
    readNonEmptyTextFile(pemRoot, "VerifyTCBInfo/TCBSigningCertIncorrectSignature/root.pem");
    const auto tcbInfoJson = generateTcbInfo();

    // WHEN
    const auto verificationResult = sgxAttestationVerifyTCBInfo(tcbInfoJson.data(), tcbSigning.c_str(), pemRootCrl.c_str(), pemRoot.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_TCB_SIGNING_CERT_INVALID_ISSUER, verificationResult);
}

TEST_F(TCBInfoVerificationTests, shouldFailWhenTCBSigningCertChainRootCertIsDifferentThanTrustedCert)
{
    // GIVEN
    readNonEmptyTextFile(tcbSigning, "VerifyTCBInfo/TCBSigningCertChainUntrusted/tcb.pem");
    readNonEmptyTextFile(pemRootCrl, "VerifyTCBInfo/TCBSigningCertChainUntrusted/root_crl.pem");
    readNonEmptyTextFile(pemRoot, "VerifyTCBInfo/TCBSigningCertChainUntrusted/root.pem");
    const char tcbInfoSignatureTemplate[] = R"json("signature": "62f2eb97227d906c158e8500964c8d10029e1a318e0e95054fbc1b9636913555d7147ceefe07c4cb7ac1ac700093e2ee3fd4f7d00c7caf135dc5243be51e1def")json";
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, generateTcbLevel(), tcbInfoSignatureTemplate);

    // WHEN
    const auto verificationResult = sgxAttestationVerifyTCBInfo(tcbInfoJson.data(), tcbSigning.c_str(), pemRootCrl.c_str(), pemRoot.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_TCB_SIGNING_CERT_CHAIN_UNTRUSTED, verificationResult);
}

TEST_F(TCBInfoVerificationTests, shouldFailWhenTCBSigningCertChainRootCertHasInvalidFormat)
{
    // GIVEN
    readNonEmptyTextFile(tcbSigning, "VerifyTCBInfo/TrustedRootCertInvalidFormat/tcb.pem");
    readNonEmptyTextFile(pemRootCrl, "VerifyTCBInfo/TrustedRootCertInvalidFormat/root_crl.pem");
    readNonEmptyTextFile(pemRoot, "VerifyTCBInfo/TrustedRootCertInvalidFormat/root.pem");
    const auto tcbInfoJson = generateTcbInfo();

    // WHEN
    const auto verificationResult = sgxAttestationVerifyTCBInfo(tcbInfoJson.data(), tcbSigning.c_str(), pemRootCrl.c_str(), pemRoot.c_str());

    // THEN
    EXPECT_EQ(STATUS_UNSUPPORTED_CERT_FORMAT, verificationResult);
}

TEST_F(TCBInfoVerificationTests, shouldFailWhenTCBSigningCertChainRootCertHasInvalidSubject)
{
    // GIVEN
    readNonEmptyTextFile(tcbSigning, "VerifyTCBInfo/TrustedRootCertInvalidSubject/tcb.pem");
    readNonEmptyTextFile(pemRootCrl, "VerifyTCBInfo/TrustedRootCertInvalidSubject/root_crl.pem");
    readNonEmptyTextFile(pemRoot, "VerifyTCBInfo/TrustedRootCertInvalidSubject/root.pem");
    const auto tcbInfoJson = generateTcbInfo();

    // WHEN
    const auto verificationResult = sgxAttestationVerifyTCBInfo(tcbInfoJson.data(), tcbSigning.c_str(), pemRootCrl.c_str(), pemRoot.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_ROOT_CA_MISSING, verificationResult);
}

TEST_F(TCBInfoVerificationTests, shouldFailWhenRootCrlHasInvalidFormat)
{
    // GIVEN
    readNonEmptyTextFile(tcbSigning, "VerifyTCBInfo/TrustedRootCrlCorrupted/tcb.pem");
    readNonEmptyTextFile(pemRootCrl, "VerifyTCBInfo/TrustedRootCrlCorrupted/root_crl.pem");
    readNonEmptyTextFile(pemRoot, "VerifyTCBInfo/TrustedRootCrlCorrupted/root.pem");
    const auto tcbInfoJson = generateTcbInfo();

    // WHEN
    const auto verificationResult = sgxAttestationVerifyTCBInfo(tcbInfoJson.data(), tcbSigning.c_str(), pemRootCrl.c_str(), pemRoot.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_CRL_UNSUPPORTED_FORMAT, verificationResult);
}

TEST_F(TCBInfoVerificationTests, shouldFailWhenRootCrlHasIssuerDifferentThanRootCertSubject)
{
    // GIVEN
    readNonEmptyTextFile(tcbSigning, "VerifyTCBInfo/TrustedRootCrlIncorrectIssuer/tcb.pem");
    readNonEmptyTextFile(pemRootCrl, "VerifyTCBInfo/TrustedRootCrlIncorrectIssuer/root_crl.pem");
    readNonEmptyTextFile(pemRoot, "VerifyTCBInfo/TrustedRootCrlIncorrectIssuer/root.pem");
    const auto tcbInfoJson = generateTcbInfo();

    // WHEN
    const auto verificationResult = sgxAttestationVerifyTCBInfo(tcbInfoJson.data(), tcbSigning.c_str(), pemRootCrl.c_str(), pemRoot.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_CRL_UNKNOWN_ISSUER, verificationResult);
}

TEST_F(TCBInfoVerificationTests, shouldFailWhenRootCrlHasInvalidSignature)
{
    // GIVEN
    readNonEmptyTextFile(tcbSigning, "VerifyTCBInfo/TrustedRootCrlIncorrectSignature/tcb.pem");
    readNonEmptyTextFile(pemRootCrl, "VerifyTCBInfo/TrustedRootCrlIncorrectSignature/root_crl.pem");
    readNonEmptyTextFile(pemRoot, "VerifyTCBInfo/TrustedRootCrlIncorrectSignature/root.pem");
    const auto tcbInfoJson = generateTcbInfo();

    // WHEN
    const auto verificationResult = sgxAttestationVerifyTCBInfo(tcbInfoJson.data(), tcbSigning.c_str(), pemRootCrl.c_str(), pemRoot.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_CRL_INVALID_SIGNATURE, verificationResult);
}

TEST_F(TCBInfoVerificationTests, shouldFailWhenRootCrlHasExpired)
{
    // GIVEN
    readNonEmptyTextFile(tcbSigning, "VerifyTCBInfo/TrustedRootCrlExpired/tcb.pem");
    readNonEmptyTextFile(pemRootCrl, "VerifyTCBInfo/TrustedRootCrlExpired/root_crl.pem");
    readNonEmptyTextFile(pemRoot, "VerifyTCBInfo/TrustedRootCrlExpired/root.pem");
    const auto tcbInfoJson = generateTcbInfo();

    // WHEN
    const auto verificationResult = sgxAttestationVerifyTCBInfo(tcbInfoJson.data(), tcbSigning.c_str(), pemRootCrl.c_str(), pemRoot.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_CRL_INVALID, verificationResult);
}

TEST_F(TCBInfoVerificationTests, shouldFailWhenRootCrlHasNoNecessaryExtensions)
{
    // GIVEN
    readNonEmptyTextFile(tcbSigning, "VerifyTCBInfo/TrustedRootCrlWithoutRequiredExtensions/tcb.pem");
    readNonEmptyTextFile(pemRootCrl, "VerifyTCBInfo/TrustedRootCrlWithoutRequiredExtensions/root_crl.pem");
    readNonEmptyTextFile(pemRoot, "VerifyTCBInfo/TrustedRootCrlWithoutRequiredExtensions/root.pem");
    const auto tcbInfoJson = generateTcbInfo();

    // WHEN
    const auto verificationResult = sgxAttestationVerifyTCBInfo(tcbInfoJson.data(), tcbSigning.c_str(), pemRootCrl.c_str(), pemRoot.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_CRL_INVALID_EXTENSIONS, verificationResult);
}

TEST_F(TCBInfoVerificationTests, shouldFailWhenRootCrlHasRevokedTcbSigningCertificate)
{
    // GIVEN
    readNonEmptyTextFile(tcbSigning, "VerifyTCBInfo/TrustedRootCrlRevokedTCBSigningCert/tcb.pem");
    readNonEmptyTextFile(pemRootCrl, "VerifyTCBInfo/TrustedRootCrlRevokedTCBSigningCert/root_crl.pem");
    readNonEmptyTextFile(pemRoot, "VerifyTCBInfo/TrustedRootCrlRevokedTCBSigningCert/root.pem");
    const auto tcbInfoJson = generateTcbInfo();

    // WHEN
    const auto verificationResult = sgxAttestationVerifyTCBInfo(tcbInfoJson.data(), tcbSigning.c_str(), pemRootCrl.c_str(), pemRoot.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_TCB_SIGNING_CERT_REVOKED, verificationResult);
}

TEST_F(TCBInfoVerificationTests, shouldSucceedWhenRootCrlHasUnrelatedRevokedEntries)
{
    // GIVEN
    readNonEmptyTextFile(tcbSigning, "VerifyTCBInfo/TrustedRootCrlUnrelatedRevokedCerts/tcb.pem");
    readNonEmptyTextFile(pemRootCrl, "VerifyTCBInfo/TrustedRootCrlUnrelatedRevokedCerts/root_crl.pem");
    readNonEmptyTextFile(pemRoot, "VerifyTCBInfo/TrustedRootCrlUnrelatedRevokedCerts/root.pem");
    const char tcbInfoSignatureTemplate[] = R"json("signature": "62f2eb97227d906c158e8500964c8d10029e1a318e0e95054fbc1b9636913555d7147ceefe07c4cb7ac1ac700093e2ee3fd4f7d00c7caf135dc5243be51e1def")json";
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, generateTcbLevel(), tcbInfoSignatureTemplate);

    // WHEN
    const auto verificationResult = sgxAttestationVerifyTCBInfo(tcbInfoJson.data(), tcbSigning.c_str(), pemRootCrl.c_str(), pemRoot.c_str());

    // THEN
    EXPECT_EQ(STATUS_OK, verificationResult);
}
