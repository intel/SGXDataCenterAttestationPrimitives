/*
* Copyright (c) 2017, Intel Corporation
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

#include "ReadFile.h"

namespace{
struct InputData{
    std::array<const char*,2> crls;
    std::string rootCaCrl;
    std::string intermediateCaCrl;
    std::string trustedRootCert ;
    std::string certChain;
};

InputData readTestInput(const std::string& directory)
{
    InputData data{};
    data.rootCaCrl = readTextFile("VerifyChainTestData/" + directory + "/rootCaCrl.pem");
    data.intermediateCaCrl = readTextFile("VerifyChainTestData/" + directory + "/intermediateCaCrl.pem");
    data.trustedRootCert = readTextFile("VerifyChainTestData/" + directory + "/IntelSGXRootCACertificate.pem");
    data.certChain = readTextFile("VerifyChainTestData/" + directory + "/IntelSGXCertificateChain.pem");
    if(data.rootCaCrl.empty() || data.intermediateCaCrl.empty() || data.trustedRootCert.empty() || data.certChain.empty())
    {
        throw std::logic_error("Invalid input");
    }
    data.crls = {{data.rootCaCrl.data(), data.intermediateCaCrl.data()}};
    return data;
}
}//anonymous namespace

TEST(sgxAttestationVerifyPCKCertificate, correctChainVerificationPlatformCA)
{
    // GIVEN
    const auto input = readTestInput("Positive_PlatformAsIntermediate");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_OK, actual);
}

TEST(sgxAttestationVerifyPCKCertificate, correctChainVerificationProcessorCA)
{
    // GIVEN
    const auto input = readTestInput("Positive_ProcessorAsIntermediate");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_OK, actual);
}

TEST(sgxAttestationVerifyPCKCertificate, unsuportedChainFormat)
{
    // GIVEN
    auto input = readTestInput("Positive_ProcessorAsIntermediate");
    input.certChain = "notavalidformat";
    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_UNSUPPORTED_CERT_FORMAT, actual);
}

TEST(sgxAttestationVerifyPCKCertificate, unsuportedRootCaFormat)
{
    // GIVEN
    auto input = readTestInput("Positive_PlatformAsIntermediate");
    input.trustedRootCert = "notavalidformat";

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_TRUSTED_ROOT_CA_UNSUPPORTED_FORMAT, actual);
}

TEST(sgxAttestationVerifyPCKCertificate, unsuportedRootCaCrlFormat)
{
    // GIVEN
    auto input = readTestInput("Positive_PlatformAsIntermediate");
    input.rootCaCrl = "notavalidformat";

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_CRL_UNSUPPORTED_FORMAT, actual);
}

TEST(sgxAttestationVerifyPCKCertificate, unsuportedIntermediateCaCrlFormat)
{
    // GIVEN
    auto input = readTestInput("Positive_ProcessorAsIntermediate");
    input.intermediateCaCrl = "notavalidformat";

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_CRL_UNSUPPORTED_FORMAT, actual);
}

TEST(sgxAttestationVerifyPCKCertificate, shouldReturnPCKRevoked)
{
    // GIVEN
    const auto input = readTestInput("Revoked_PCK");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_PCK_REVOKED, actual);
}

TEST(sgxAttestationVerifyPCKCertificate, shouldReturnPCKRevokedWhenFewEntriedAndOneMatch)
{
    // GIVEN
    const auto input = readTestInput("Revoked_PckFewEntriesOneMatch");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_PCK_REVOKED, actual);
}

TEST(sgxAttestationVerifyPCKCertificate, shouldReturnStatusOkWhenFewCertRevokedButNotOurs)
{
    // GIVEN
    const auto input = readTestInput("Revoked_PckFewEntriesNoneMatch");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_OK, actual);
}

TEST(sgxAttestationVerifyPCKCertificate, shouldReturnIntermediateRevoked)
{
    // GIVEN
    const auto input = readTestInput("Revoked_Intermediate");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_INTERMEDIATE_CA_REVOKED, actual);
}

TEST(sgxAttestationVerifyPCKCertificate, shouldReturnIntermediateCrlUnknownIssuer)
{
    // GIVEN
    const auto input = readTestInput("Revoked_IntermediateUnknownIssuer");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_CRL_UNKNOWN_ISSUER, actual);
}

TEST(sgxAttestationVerifyPCKCertificate, shouldReturnRootCaCrlUnknownIssuer)
{
    // GIVEN
    const auto input = readTestInput("Revoked_RootCaUnknownIssuer");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_CRL_UNKNOWN_ISSUER, actual);
}

////////////////////////
//  In chain root ca

TEST(sgxAttestationVerifyPCKCertificate, shouldReturnRootCaMissing)
{
    // GIVEN
    const auto input = readTestInput("InChainRoot_InvalidSubject");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_ROOT_CA_MISSING, actual);
}


TEST(sgxAttestationVerifyPCKCertificate, shouldReturnRootCaInvalid)
{
    // GIVEN
    const auto input = readTestInput("InChainRoot_InvalidValidityPeriod");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_ROOT_CA_INVALID, actual);
}

TEST(sgxAttestationVerifyPCKCertificate, shouldReturnRootCaInvalidExtension)
{
    // GIVEN
    const auto input = readTestInput("InChainRoot_InvalidExtensions");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_ROOT_CA_INVALID_EXTENSIONS, actual);
}

TEST(sgxAttestationVerifyPCKCertificate, shouldReturnRootCaInvalidIssuer)
{
    // GIVEN
    const auto input = readTestInput("InChainRoot_InvalidIssuer");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_ROOT_CA_INVALID_ISSUER, actual);
}

TEST(sgxAttestationVerifyPCKCertificate, shouldReturnRootCaInvalidIssuerWhenInChainRootCantVerifyItsOwnSignature)
{
    // GIVEN
    const auto input = readTestInput("InChainRoot_InvalidIssuerCantVerifySignature");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_ROOT_CA_INVALID_ISSUER, actual);
}

/////////////
// intermediate ca

TEST(sgxAttestationVerifyPCKCertificate, shouldReturnIntermediateCaMissing)
{
    // GIVEN
    const auto input = readTestInput("Intermediate_InvalidSubject");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_INTERMEDIATE_CA_MISSING, actual);
}

TEST(sgxAttestationVerifyPCKCertificate, shouldReturnIntermediateExpired)
{
    // GIVEN
    const auto input = readTestInput("Intermediate_InvalidValidityPeriod");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_INTERMEDIATE_CA_INVALID, actual);
}

TEST(sgxAttestationVerifyPCKCertificate, shouldReturnIntermediateInvalidExtensions)
{
    // GIVEN
    const auto input = readTestInput("Intermediate_InvalidExtensions");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_INTERMEDIATE_CA_INVALID_EXTENSIONS, actual);
}

TEST(sgxAttestationVerifyPCKCertificate, shouldReturnIntermediateInvalidIssuer)
{
    // GIVEN
    const auto input = readTestInput("Intermediate_InvalidIssuer");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_INTERMEDIATE_CA_INVALID_ISSUER, actual);
}

TEST(sgxAttestationVerifyPCKCertificate, shouldReturnIntermediateInvalidIssuerWhenCantVerifySignature)
{
    // GIVEN
    const auto input = readTestInput("Intermediate_InvalidIssuerCantVerifySignature");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_INTERMEDIATE_CA_INVALID_ISSUER, actual);
}

//////////////
// PCK

TEST(sgxAttestationVerifyPCKCertificate, shouldReturnPCKMissing)
{
    // GIVEN
    const auto input = readTestInput("Pck_InvalidSubject");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_PCK_MISSING, actual);
}

TEST(sgxAttestationVerifyPCKCertificate, shouldReturnPCKInvalidValidityPeriod)
{
    // GIVEN
    const auto input = readTestInput("Pck_InvalidValidityPeriod");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_PCK_INVALID, actual);
}

TEST(sgxAttestationVerifyPCKCertificate, shouldReturnPCKInvalidExtenionsWhenStandardOneMissing)
{
    // GIVEN
    const auto input = readTestInput("Pck_InvalidExtensions");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_PCK_INVALID_EXTENSIONS, actual);
}

TEST(sgxAttestationVerifyPCKCertificate, shouldReturnPCKInvalidExtenionsWhenSGXCustomOneMissing)
{
    // GIVEN
    const auto input = readTestInput("Pck_InvalidSGXExtensions");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_PCK_INVALID_EXTENSIONS, actual);
}

TEST(sgxAttestationVerifyPCKCertificate, shouldReturnPCKInvalidIssuer)
{
    // GIVEN
    const auto input = readTestInput("Pck_InvalidIssuer");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_PCK_INVALID_ISSUER, actual);
}

TEST(sgxAttestationVerifyPCKCertificate, shouldReturnPCKInvalidIssuerWhenCantVerifySignature)
{
    // GIVEN
    const auto input = readTestInput("Pck_InvalidIssuerCantVerifySignature");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_PCK_INVALID_ISSUER, actual);
}

//////////////
// trusted root ca

TEST(sgxAttestationVerifyPCKCertificate, shouldReturnInvalidTrustedRootCA)
{
    // GIVEN
    const auto input = readTestInput("TrustedRoot_InvalidSubject");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_TRUSTED_ROOT_CA_INVALID, actual);
}

TEST(sgxAttestationVerifyPCKCertificate, shouldReturnChainUntrusted)
{
    // GIVEN
    const auto input = readTestInput("TrustedRoot_UntrustedChain");

    // WHEN
    const auto actual = sgxAttestationVerifyPCKCertificate(input.certChain.c_str(), input.crls.data() , input.trustedRootCert.c_str());

    // THEN
    EXPECT_EQ(STATUS_SGX_PCK_CERT_CHAIN_UNTRUSTED, actual);
}
