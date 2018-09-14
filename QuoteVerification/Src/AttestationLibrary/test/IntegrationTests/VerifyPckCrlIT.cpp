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

using namespace testing;

struct CRLVerificationTests : public Test
{
    const char placeholder[8] = "1234567";
    struct InputData{
        std::string crl;
        std::string trustedRootCert ;
        std::string certChain;
    };

    InputData readTestInput(const std::string& directory)
    {
        InputData data{};
        data.crl = readTextFile("VerifyPckCrl/" + directory + "/crl.pem");
        data.trustedRootCert = readTextFile("VerifyPckCrl/" + directory + "/trustedRoot.pem");
        data.certChain = readTextFile("VerifyPckCrl/" + directory + "/certChain.pem");
        if(data.crl.empty() || data.trustedRootCert.empty() || data.certChain.empty())
        {
            throw std::logic_error("Invalid input");
        }
        return data;
    }
};

TEST_F(CRLVerificationTests, killerCrlShouldReturnUnknownIssuer)
{
    auto testData = readTestInput("ValidRootCACRL");
    std::string killerCrl = "-----BEGIN X509 CRL-----\nMIIBpTCCAUsCAQEwCgYIKoZIzj0EAwIwcDEiMCAGA1UEAwgZSW50ZWwgU0dYIFBD\nSyBQbGF0Zm9ybSBDQTEaMBgGA1UECgwRSW50ZWwgQ29ycG9yYXRpb24xFDASBgNV\nBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTELMAkGA1UEBhMCVVMXDTE3MTAx\nOTA5MzAwMFoYDzk5OTkxMjMxMjI1OTU5WjB3MCYCFQCGd6wCBptFuX2DD97Qg6E1\n35feVxcNMTcxMDE5MDkzMDAwWjAlAhR6pltBU+a4pTiK9thmo8i03eX/nRcNMTcx\nMDE5MDkzMDAwWjAmAhUA1i/6taBMf+JQ69w3y5E3gNhdxa0XDTE3MTAxOTA5MzAw\nMFqgLzAtMAoGA1UdFAQDAgEBMB8GA1UdIwQYMBaAFA7dCcg+VveMFY751uri+HUm\nHvLmMAoGCCqGSM49BAMCA0gAMEUCIQDEbiQWNsT6YXzneNdXk+Kjvon5GaMPwRvN\n0zuB5aofSQIgeuRGLAbah4XvK6InsvtEd9N4//6/ZRvMjYkF4ZzzdrM=\n-----END X509 CRL-----";

    ASSERT_EQ(STATUS_SGX_CRL_UNKNOWN_ISSUER, sgxAttestationVerifyPCKRevocationList(
        killerCrl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(CRLVerificationTests, killerCertChainShouldReturnUnknownIssuer)
{
    auto testData = readTestInput("ValidRootCACRL");
    std::string killerPemCACertChain = "-----BEGIN CERTIFICATE-----\nMIICijCCAjCgAwIBAgIUMg7AoHp9SCdkt/JcYMPeKNGUv+MwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgOVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDQtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMCAXDTE3MTAxOTA4NTQ1NFoYDzk5OTkxMjMxMjI1OTU5WjBoMRow\nGAYDVQQDDBFJbnRlbCBTR1ggUm9vdCBDQTEaMBgGA1UECgwRSW50ZWwgQ29ycG9y\nYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTELMAkGA1UE\nBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQUFHgOgrHGksZlST/RwXzm\n6519awyJz59zdym46+bRoIVwneM0K7sTiaw26LIjzeMXcyXlNgh5c4QQYf5NSZUA\no4G1MIGyMB8GA1UdIwQYMBaAFDIOwKB6fUgnZLfyXGDD3ijRlL/jMEwGA1UdHwRF\nMEMwQaA/oD2GO2h0dHA6Ly9ub24tZXhpc3RpbmctZGVidWctb25seS5pbnRlbC5j\nb20vSW50ZWxTR1hSb290Q0EuY3JsMB0GA1UdDgQWBBQyDsCgen1IJ2S38lxgw94o\n0ZS/4zAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAKBggqhkjO\nPQQDAgNIADBFAiEAhti/a84JbjnToj4yHaKueCoe+o0M3UYEBpADH+6GEfwCIDj4\nyu2yCtDE4KUuAtKu4qOS0hrnMKbn+OYCK9Icxq3O\n-----END CERTIFICATE-----";

    ASSERT_EQ(STATUS_SGX_CA_CERT_INVALID, sgxAttestationVerifyPCKRevocationList(
        testData.crl.c_str(), killerPemCACertChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(CRLVerificationTests, killerRootShouldReturnUnknownIssuer)
{
    auto testData = readTestInput("ValidRootCACRL");
    std::string killerPemTrustedRootCaCert = "-----BEGIN CERTIFICATE-----\nMIICijCCAjCgAwIBAgIUMg7AoHp9SCdkt/JcYMPeKNGUv+MwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwsRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMCAXDTE3MTAxOTA4NTQ1NFoYDzk5O3kxMjMxMjI1OTU5WjBoMRow\nGAYDVQQDDBFJbnRlbCBTR1ggUm9vdCBDQTEaMBgGA1UECgwRSW50ZWwgQ29ycG9y\nYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTELMAkGA1UE\nBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQUFHgOgrHGksZlST/RwXzm\n6519awyJz59zdym46+bRoIVwneM0K7sTiaw26LIjzeMXcyXlNgh5c4QQYf5NSZUA\no4G1MIGyMB8GA1UdIwQYMBaAFDIOwKB6fUgnZLfyXGDD3ijRlL/jMEwGA1UdHwRF\nMEMwQaA/oD2GO+MwCgRoIVwneM0K7sTiLIjpbmctZGVidWctb25seS5pbnRlbC5j\nbA0vSW50ZWxTR1hSb290Q0EuY3JsMB0GA1UdDgQWBBQyDsCgen1IJ2S38lxgw94o\n0ZS/4zAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAKBggqhkjO\nPQQDAgNIADBFAiEAhti/a84JbjnToj4yHaKueCoe+o0M3UYEBpADH+6GEfwCIDj4\nyu2yCtDE4KUuAtKu4qOS0hrnMKbn+OYCK9Icxq3O\n-----END CERTIFICATE-----";

    ASSERT_EQ(STATUS_TRUSTED_ROOT_CA_UNSUPPORTED_FORMAT, sgxAttestationVerifyPCKRevocationList(
        testData.crl.c_str(), testData.certChain.c_str(), killerPemTrustedRootCaCert.c_str()));
}

TEST_F(CRLVerificationTests, nullptrArgumentsShoudReturnCrlUnsupportedStatus)
{
    ASSERT_EQ(STATUS_SGX_CRL_UNSUPPORTED_FORMAT, sgxAttestationVerifyPCKRevocationList(nullptr, nullptr, nullptr));
}

TEST_F(CRLVerificationTests, shouldFailWhenCRLFormatIsNotAValidPEM)
{
    const std::string crl = readTextFile("VerifyPckCrl/invalidCrl.pem");
    ASSERT_EQ(STATUS_SGX_CRL_UNSUPPORTED_FORMAT, sgxAttestationVerifyPCKRevocationList(crl.c_str(), placeholder, placeholder));
}


struct RootCACRLVerificationTests : public CRLVerificationTests
{};

TEST_F(RootCACRLVerificationTests, successfulEmptyCrlVerification)
{
    auto testData = readTestInput("ValidEmptyRootCACRL");

    ASSERT_EQ(STATUS_OK, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(RootCACRLVerificationTests, successfulCrlVerification)
{
    auto testData = readTestInput("ValidRootCACRL");

    ASSERT_EQ(STATUS_OK, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(RootCACRLVerificationTests, shouldFailWhenCRLIsCorrupt)
{
    auto testData = readTestInput("RootCACRL_InvalidFormat");

    ASSERT_EQ(STATUS_SGX_CRL_UNSUPPORTED_FORMAT, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(RootCACRLVerificationTests, shouldFailWhenRootCertInChainHasExpired)
{
    auto testData = readTestInput("RootCACRL_ChainRootCertExpired");

    ASSERT_EQ(STATUS_SGX_CA_CERT_INVALID, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(RootCACRLVerificationTests, shouldFailWhenRootCertInChainHasWrongIssuer)
{
    auto testData = readTestInput("RootCACRL_ChainRootCertWrongIssuer");

    ASSERT_EQ(STATUS_SGX_CA_CERT_INVALID, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(RootCACRLVerificationTests, shouldFailWhenRootCertInChainHasWrongSignature)
{
    auto testData = readTestInput("RootCACRL_ChainRootCertWrongSignature");

    ASSERT_EQ(STATUS_SGX_CA_CERT_INVALID, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(RootCACRLVerificationTests, shouldFailWhenRootCertInChainHasWrongSubject)
{
    auto testData = readTestInput("RootCACRL_ChainRootCertWrongSubject");

    ASSERT_EQ(STATUS_SGX_ROOT_CA_INVALID, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(RootCACRLVerificationTests, shouldFailWhenCRLHasExpired)
{
    auto testData = readTestInput("RootCACRL_Expired");

    ASSERT_EQ(STATUS_SGX_CRL_INVALID, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(RootCACRLVerificationTests, shouldFailWhenCRLHasWrongSignature)
{
    auto testData = readTestInput("RootCACRL_InvalidSignature");

    ASSERT_EQ(STATUS_SGX_CRL_INVALID_SIGNATURE, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(RootCACRLVerificationTests, shouldFailWhenCRLIsMissingMandatoryExtensions)
{
    auto testData = readTestInput("RootCACRL_MissingExtensions");

    ASSERT_EQ(STATUS_SGX_CRL_INVALID_EXTENSIONS, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(RootCACRLVerificationTests, shouldFailWhenRootCertInChainIsDIfferentThenTrustedRootCert)
{
    auto testData = readTestInput("RootCACRL_RootCertInChainNotATrustedRoot");

    ASSERT_EQ(STATUS_SGX_ROOT_CA_UNTRUSTED, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(RootCACRLVerificationTests, shouldFailWhenRootCertInChainIsMissingMandatoryExtensions)
{
    auto testData = readTestInput("RootCACRL_ChainRootMissingExtensions");

    ASSERT_EQ(STATUS_SGX_CA_CERT_INVALID, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(RootCACRLVerificationTests, shouldFailWhenCertChainHasIncorrectLength)
{
    auto testData = readTestInput("RootCACRL_WrongChainLength");

    ASSERT_EQ(STATUS_SGX_CA_CERT_UNSUPPORTED_FORMAT, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(RootCACRLVerificationTests, shouldFailWhenTrustedRootCAExpired)
{
    auto testData = readTestInput("TrustedRootCAExpired");

    ASSERT_EQ(STATUS_TRUSTED_ROOT_CA_INVALID, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(RootCACRLVerificationTests, shouldFailWhenTrustedRootCAHasWrongIssuer)
{
    auto testData = readTestInput("TrustedRootCAWrongIssuer");

    ASSERT_EQ(STATUS_TRUSTED_ROOT_CA_INVALID, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(RootCACRLVerificationTests, shouldFailWhenTrustedRootCAIsMissingMandatoryExtensions)
{
    auto testData = readTestInput("TrustedRootCAMissingExtensions");

    ASSERT_EQ(STATUS_TRUSTED_ROOT_CA_INVALID, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(RootCACRLVerificationTests, shouldFailWhenTrustedRootCAHasWrongSubject)
{
    auto testData = readTestInput("TrustedRootCAWrongSubject");

    ASSERT_EQ(STATUS_TRUSTED_ROOT_CA_INVALID, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(RootCACRLVerificationTests, shouldFailWhenTrustedRootCAHasWrongSignature)
{
    auto testData = readTestInput("TrustedRootCAWrongSignature");

    ASSERT_EQ(STATUS_TRUSTED_ROOT_CA_INVALID, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(RootCACRLVerificationTests, shouldFailWhenTrustedRootCAHasInvalidFormat)
{
    auto testData = readTestInput("TrustedRootCAWrongFormat");

    ASSERT_EQ(STATUS_TRUSTED_ROOT_CA_UNSUPPORTED_FORMAT, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

struct PCKPlatformCACRLVerificationTests : public CRLVerificationTests
{};

TEST_F(PCKPlatformCACRLVerificationTests, successfulCrlVerification)
{
    auto testData = readTestInput("ValidPlatformCACRL");

    ASSERT_EQ(STATUS_OK, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(PCKPlatformCACRLVerificationTests, shouldFailWhenCRLIssuerIsDifferent)
{
    auto testData = readTestInput("PlatformCACRL_IncorrectIssuer");

    ASSERT_EQ(STATUS_SGX_CA_CERT_UNSUPPORTED_FORMAT, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(PCKPlatformCACRLVerificationTests, shouldFailWhenCRLSignatureIsIncorrect)
{
    auto testData = readTestInput("PlatformCACRL_InvalidSignature");

    ASSERT_EQ(STATUS_SGX_CRL_INVALID_SIGNATURE, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(PCKPlatformCACRLVerificationTests, shouldFailWhenSigningCertSubjectIsIncorrect)
{
    auto testData = readTestInput("PlatformCACRL_SigningCertInvalidSubject");

    ASSERT_EQ(STATUS_SGX_CA_CERT_INVALID, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(PCKPlatformCACRLVerificationTests, shouldFailWhenSigningCertIsMissingMandatoryExtensions)
{
    auto testData = readTestInput("PlatformCACRL_SigningCertMissingExtensions");

    ASSERT_EQ(STATUS_SGX_CA_CERT_INVALID, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(PCKPlatformCACRLVerificationTests, shouldFailWhenSigningCertHasIncorrectIssuer)
{
    auto testData = readTestInput("PlatformCACRL_SigningCertWrongIssuer");

    ASSERT_EQ(STATUS_SGX_CA_CERT_INVALID, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(PCKPlatformCACRLVerificationTests, shouldFailWhenSigningCertChainLengthIsIncorrect)
{
    auto testData = readTestInput("PlatformCACRL_WrongChainLength");

    ASSERT_EQ(STATUS_SGX_CA_CERT_UNSUPPORTED_FORMAT, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

struct PCKProcessorCACRLVerificationTests : public CRLVerificationTests
{};

TEST_F(PCKProcessorCACRLVerificationTests, successfulCrlVerification)
{
    auto testData = readTestInput("ValidProcessorCACRL");

    ASSERT_EQ(STATUS_OK, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(PCKProcessorCACRLVerificationTests, shouldFailWhenSigningCertChainHasWrongFormat)
{
    auto testData = readTestInput("ProcessorCACRL_CertChainInvalid");

    ASSERT_EQ(STATUS_SGX_CA_CERT_UNSUPPORTED_FORMAT, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(PCKProcessorCACRLVerificationTests, shouldFailWhenCRLSignatureIsIncorrect)
{
    auto testData = readTestInput("ProcessorCACRL_InvalidSignature");

    ASSERT_EQ(STATUS_SGX_CRL_INVALID_SIGNATURE, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(PCKProcessorCACRLVerificationTests, shouldFailWhenCRLSigningCertHasExpired)
{
    auto testData = readTestInput("ProcessorCACRL_SigningCertExpired");

    ASSERT_EQ(STATUS_SGX_CA_CERT_INVALID, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(PCKProcessorCACRLVerificationTests, shouldFailWhenCRLSigningCertIsMissingMandatoryExtensions)
{
    auto testData = readTestInput("ProcessorCACRL_SigningCertMissingExtensions");

    ASSERT_EQ(STATUS_SGX_CA_CERT_INVALID, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(PCKProcessorCACRLVerificationTests, shouldFailWhenCRLSigningCertHasIncorrectSignature)
{
    auto testData = readTestInput("ProcessorCACRL_SigningCertWrongSignature");

    ASSERT_EQ(STATUS_SGX_CA_CERT_INVALID, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}

TEST_F(PCKProcessorCACRLVerificationTests, shouldFailWhenSigningCertChainLengthIsIncorrect)
{
    auto testData = readTestInput("ProcessorCACRL_WrongChainLength");

    ASSERT_EQ(STATUS_SGX_CA_CERT_UNSUPPORTED_FORMAT, sgxAttestationVerifyPCKRevocationList(testData.crl.c_str(), testData.certChain.c_str(), testData.trustedRootCert.c_str()));
}
