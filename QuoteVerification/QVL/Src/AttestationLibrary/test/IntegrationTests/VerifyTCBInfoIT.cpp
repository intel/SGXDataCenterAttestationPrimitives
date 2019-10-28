/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <SgxEcdsaAttestation/QuoteVerification.h>
#include <CertVerification/X509Constants.h>
#include <EcdsaSignatureGenerator.h>
#include "X509CertGenerator.h"
#include "X509CrlGenerator.h"
#include "TcbInfoJsonGenerator.h"

using namespace testing;
using namespace intel::sgx::qvl::test;
using namespace intel::sgx::qvl;

struct VerifyTCBInfoIT : public Test
{
    X509CertGenerator certGenerator;
    X509CrlGenerator crlGenerator;

    Bytes rootSerial {0x00, 0x45};

    crypto::X509_uptr rootCaCert = crypto::make_unique<X509>(nullptr);
    crypto::X509_uptr tcbSigningCert = crypto::make_unique<X509>(nullptr);
    crypto::X509_CRL_uptr rootCaCrl = crypto::make_unique<X509_CRL>(nullptr);

    crypto::EVP_PKEY_uptr rootKeys = crypto::make_unique<EVP_PKEY>(nullptr);
    crypto::EVP_PKEY_uptr tcbSigningKey = crypto::make_unique<EVP_PKEY>(nullptr);

    int timeNow = 0;
    int timeOneHour = 3600;

    const Bytes serialNumber {0x23, 0x45};


    VerifyTCBInfoIT()
    {
        rootKeys = certGenerator.generateEcKeypair();
        tcbSigningKey = certGenerator.generateEcKeypair();

        rootCaCert = certGenerator.generateCaCert(2, rootSerial, timeNow, timeOneHour, rootKeys.get(), rootKeys.get(),
                                                  constants::ROOT_CA_SUBJECT, constants::ROOT_CA_SUBJECT);
        tcbSigningCert = certGenerator.generateCaCert(2, serialNumber, timeNow, timeOneHour, tcbSigningKey.get(), rootKeys.get(),
                                                           constants::TCB_SUBJECT, constants::ROOT_CA_SUBJECT);
        rootCaCrl = crlGenerator.generateCRL(CRLVersion::CRL_VERSION_2, timeNow, timeOneHour, rootCaCert, std::vector<Bytes>{});
    }

    std::string GenerateTCBInfoJSON() const
    {
        const auto tcbInfoBody = tcbInfoJsonBody(
                1,                      //version
                "2018-07-22T10:09:10Z", //issueDate
                "2118-08-23T10:09:10Z", //nextUpdate
                "04F34445AA00",         //fmspc
                "0000",                 //pceId
                getRandomTcb(),         //tcb
                0,                      //pcesvn
                "UpToDate"              //status
        );

        auto tcbInfoBodyBytes = Bytes{};
        tcbInfoBodyBytes.insert(tcbInfoBodyBytes.end(), tcbInfoBody.begin(), tcbInfoBody.end());
        auto signature = EcdsaSignatureGenerator::signECDSA_SHA256(tcbInfoBodyBytes, tcbSigningKey.get());

        return tcbInfoJsonGenerator(tcbInfoBody, EcdsaSignatureGenerator::signatureToHexString(signature));
    }
};

TEST_F(VerifyTCBInfoIT, shouldReturnCertUnsupportedFormatWhenInvalidInput)
{
    EXPECT_EQ(STATUS_UNSUPPORTED_CERT_FORMAT, sgxAttestationVerifyTCBInfo(nullptr, nullptr, nullptr, nullptr, nullptr));
    EXPECT_EQ(STATUS_UNSUPPORTED_CERT_FORMAT, sgxAttestationVerifyTCBInfo(nullptr, "str", "str", "str", nullptr));
    EXPECT_EQ(STATUS_UNSUPPORTED_CERT_FORMAT, sgxAttestationVerifyTCBInfo("str", nullptr, "str", "str", nullptr));
    EXPECT_EQ(STATUS_UNSUPPORTED_CERT_FORMAT, sgxAttestationVerifyTCBInfo("str", "str", nullptr, "str", nullptr));
    EXPECT_EQ(STATUS_UNSUPPORTED_CERT_FORMAT, sgxAttestationVerifyTCBInfo("str", "str", "str", nullptr, nullptr));
}

TEST_F(VerifyTCBInfoIT, verifyTCBInfoShouldReturnStatusOk)
{
    const auto rootCaCertPem = certGenerator.x509ToString(rootCaCert.get());
    const auto tcbSigningPem = certGenerator.x509ToString(tcbSigningCert.get());
    const auto certChain = rootCaCertPem  + tcbSigningPem;
    const auto rootCaCrlPem = X509CrlGenerator::x509CrlToString(rootCaCrl.get());

    const auto tcbInfoJSON = GenerateTCBInfoJSON();

    ASSERT_EQ(STATUS_OK,
            sgxAttestationVerifyTCBInfo(tcbInfoJSON.c_str(), certChain.c_str(), rootCaCrlPem.c_str(), rootCaCertPem.c_str(), nullptr));
}

TEST_F(VerifyTCBInfoIT, shouldReturnUnsupportedCertFormatWhenInvalidCertChain)
{
    const auto trustedRootCaCert = certGenerator.x509ToString(rootCaCert.get());
    const auto invalidCertChainPem = "No a valid X509 CERT CHAIN PEM";
    const auto rootCaCrlPem = X509CrlGenerator::x509CrlToString(rootCaCrl.get());

    const auto tcbInfoJSON = GenerateTCBInfoJSON();

    EXPECT_EQ(STATUS_UNSUPPORTED_CERT_FORMAT,
            sgxAttestationVerifyTCBInfo(tcbInfoJSON.c_str(), invalidCertChainPem, rootCaCrlPem.c_str(), trustedRootCaCert.c_str(), nullptr));
}

TEST_F(VerifyTCBInfoIT, shouldReturnUnsupportedCertFormatWhenInvalidTrustedRootCaCert)
{
    const auto certChain = certGenerator.x509ToString(rootCaCert.get());
    const auto invalidTrustedRootCaCert = "No a valid X509 CERT PEM";
    const auto rootCaCrlPem = X509CrlGenerator::x509CrlToString(rootCaCrl.get());

    const auto tcbInfoJSON = GenerateTCBInfoJSON();

    EXPECT_EQ(STATUS_UNSUPPORTED_CERT_FORMAT,
            sgxAttestationVerifyTCBInfo(tcbInfoJSON.c_str(), certChain.c_str(), rootCaCrlPem.c_str(), invalidTrustedRootCaCert, nullptr));
}

TEST_F(VerifyTCBInfoIT, shouldReturnCrlUnsupportedFormatWhenInvalidRootCaCrl)
{
    const auto rootCaCertPem = certGenerator.x509ToString(rootCaCert.get());
    const auto tcbSigningPem = certGenerator.x509ToString(tcbSigningCert.get());
    const auto certChain = rootCaCertPem  + tcbSigningPem;
    const auto invalidRootCaCrlPem = "No a valid X509 CRL PEM";

    const auto tcbInfoJSON = GenerateTCBInfoJSON();

    EXPECT_EQ(STATUS_SGX_CRL_UNSUPPORTED_FORMAT,
            sgxAttestationVerifyTCBInfo(tcbInfoJSON.c_str(), certChain.c_str(), invalidRootCaCrlPem, rootCaCertPem.c_str(), nullptr));
}
