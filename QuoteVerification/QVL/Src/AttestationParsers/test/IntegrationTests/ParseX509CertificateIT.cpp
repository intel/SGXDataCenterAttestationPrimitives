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

#include <SgxEcdsaAttestation/AttestationParsers.h>

#include <gtest/gtest.h>
#include <gmock/gmock-generated-matchers.h>

using namespace intel::sgx::dcap::parser;
using namespace ::testing;


struct ParseX509CertificateIT: public testing::Test {};

std::string PEM("-----BEGIN CERTIFICATE-----\n"
                "MIIEfDCCBCGgAwIBAgIUQGawAUtxfPcB1bfY8TaxmelzlsgwCgYIKoZIzj0EAwIw\n"
                "cDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBQbGF0Zm9ybSBDQTEaMBgGA1UECgwR\n"
                "SW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQI\n"
                "DAJDQTELMAkGA1UEBhMCVVMwHhcNMTgwNDEzMDYyOTE2WhcNMjUwNDEzMDYyOTE2\n"
                "WjBwMSIwIAYDVQQDDBlJbnRlbCBTR1ggUENLIENlcnRpZmljYXRlMRowGAYDVQQK\n"
                "DBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNV\n"
                "BAgMAkNBMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLDN\n"
                "YKqS1g+C474FJhmp4ypDhdB+sbHfuLFKvyhBTHqizqqTPu74ih0CGT7mkiM3Kp71\n"
                "7yjm45RjaRSVevcQ++2jggKXMIICkzAfBgNVHSMEGDAWgBT00AUxOPl/E6r4Pbop\n"
                "i/Uz1ufd8TBYBgNVHR8EUTBPME2gS6BJhkdodHRwczovL2NlcnRpZmljYXRlcy50\n"
                "cnVzdGVkc2VydmljZXMuaW50ZWwuY29tL0ludGVsU0dYUENLUHJvY2Vzc29yLmNy\n"
                "bDAdBgNVHQ4EFgQU9XkaeRbUjMF6ktI8coX4TzjfJGAwDgYDVR0PAQH/BAQDAgbA\n"
                "MAwGA1UdEwEB/wQCMAAwggHXBgkqhkiG+E0BDQEBAf8EggHFMIIBwTAeBgoqhkiG\n"
                "+E0BDQEBBBATbgAAAAAAAAAAAAAAAAAAMIIBZAYKKoZIhvhNAQ0BAjCCAVQwEAYL\n"
                "KoZIhvhNAQ0BAgECAQAwEAYLKoZIhvhNAQ0BAgICAQAwEAYLKoZIhvhNAQ0BAgMC\n"
                "AQAwEAYLKoZIhvhNAQ0BAgQCAQAwEAYLKoZIhvhNAQ0BAgUCAQEwEAYLKoZIhvhN\n"
                "AQ0BAgYCAQEwEAYLKoZIhvhNAQ0BAgcCAQAwEAYLKoZIhvhNAQ0BAggCAQAwEAYL\n"
                "KoZIhvhNAQ0BAgkCAQAwEAYLKoZIhvhNAQ0BAgoCAQAwEAYLKoZIhvhNAQ0BAgsC\n"
                "AQAwEAYLKoZIhvhNAQ0BAgwCAQAwEAYLKoZIhvhNAQ0BAg0CAQAwEAYLKoZIhvhN\n"
                "AQ0BAg4CAQAwEAYLKoZIhvhNAQ0BAg8CAQAwEAYLKoZIhvhNAQ0BAhACAQAwEQYL\n"
                "KoZIhvhNAQ0BAhECAgMAMB8GCyqGSIb4TQENAQISBBAAAAAAAQEAAAAAAAAAAAAA\n"
                "MBAGCiqGSIb4TQENAQMEAgAAMBQGCiqGSIb4TQENAQQEBgBwfwAAADAPBgoqhkiG\n"
                "+E0BDQEFCgEAMAoGCCqGSM49BAMCA0kAMEYCIQC3S8KypLZdxzFrdVxMWZ2xgMJS\n"
                "DxqxLt0i6PU3K/xVpwIhAPZjmHC/wl0fiukfQHZxKBzxnYCR24KQ0JoB40CLN4WM\n"
                "-----END CERTIFICATE-----");

/// Example values for issuer
const std::string RAW_ISSUER("C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Intel SGX PCK Certificate");
const std::string COMMON_NAME_ISSUER("Intel SGX PCK Certificate");
const std::string COUNTRY_NAME_ISSUER("US");
const std::string ORGANIZATION_NAME_ISSUER("Intel Corporation");
const std::string LOCATION_NAME_ISSUER("Santa Clara");
const std::string STATE_NAME_ISSUER("CA");

/// Example values for subject
const std::string RAW_SUBJECT("C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Intel SGX PCK Platform CA");
const std::string COMMON_NAME_SUBJECT("Intel SGX PCK Platform CA");
const std::string COUNTRY_NAME_SUBJECT("US");
const std::string ORGANIZATION_NAME_SUBJECT("Intel Corporation");
const std::string LOCATION_NAME_SUBJECT("Santa Clara");
const std::string STATE_NAME_SUBJECT("CA");

const std::vector<uint8_t> RAW_DER = { 0x30, 0x46, 0x02, 0x21, 0x00, 0xB7, 0x4B, 0xC2,
                                       0xB2, 0xA4, 0xB6, 0x5D, 0xC7, 0x31, 0x6B, 0x75,
                                       0x5C, 0x4C, 0x59, 0x9D, 0xB1, 0x80, 0xC2, 0x52,
                                       0x0F, 0x1A, 0xB1, 0x2E, 0xDD, 0x22, 0xE8, 0xF5,
                                       0x37, 0x2B, 0xFC, 0x55, 0xA7, 0x02, 0x21, 0x00,
                                       0xF6, 0x63, 0x98, 0x70, 0xBF, 0xC2, 0x5D, 0x1F,
                                       0x8A, 0xE9, 0x1F, 0x40, 0x76, 0x71, 0x28, 0x1C,
                                       0xF1, 0x9D, 0x80, 0x91, 0xDB, 0x82, 0x90, 0xD0,
                                       0x9A, 0x01, 0xE3, 0x40, 0x8B, 0x37, 0x85, 0x8C };
const std::vector<uint8_t> R = { 0xB7, 0x4B, 0xC2, 0xB2, 0xA4, 0xB6, 0x5D, 0xC7,
                                 0x31, 0x6B, 0x75, 0x5C, 0x4C, 0x59, 0x9D, 0xB1,
                                 0x80, 0xC2, 0x52, 0x0F, 0x1A, 0xB1, 0x2E, 0xDD,
                                 0x22, 0xE8, 0xF5, 0x37, 0x2B, 0xFC, 0x55, 0xA7 };
const std::vector<uint8_t> S = { 0xF6, 0x63, 0x98, 0x70, 0xBF, 0xC2, 0x5D, 0x1F,
                                 0x8A, 0xE9, 0x1F, 0x40, 0x76, 0x71, 0x28, 0x1C,
                                 0xF1, 0x9D, 0x80, 0x91, 0xDB, 0x82, 0x90, 0xD0,
                                 0x9A, 0x01, 0xE3, 0x40, 0x8B, 0x37, 0x85, 0x8C };

const std::time_t NOT_BEFORE_TIME = 1523600956;
const std::time_t NOT_AFTER_TIME = 1744525756;

const std::vector<uint8_t> SERIAL_NUMBER { 0x40, 0x66, 0xB0, 0x01, 0x4B, 0x71, 0x7C, 0xF7, 0x01, 0xD5,
                                           0xB7, 0xD8, 0xF1, 0x36, 0xB1, 0x99, 0xE9, 0x73, 0x96, 0xC8 };

const std::vector<uint8_t> PUBLIC_KEY { 0x04, // header
                                        0xB0, 0xCD, 0x60, 0xAA, 0x92, 0xD6, 0x0F, 0x82, // X
                                        0xE3, 0xBE, 0x05, 0x26, 0x19, 0xA9, 0xE3, 0x2A,
                                        0x43, 0x85, 0xD0, 0x7E, 0xB1, 0xB1, 0xDF, 0xB8,
                                        0xB1, 0x4A, 0xBF, 0x28, 0x41, 0x4C, 0x7A, 0xA2,
                                        0xCE, 0xAA, 0x93, 0x3E, 0xEE, 0xF8, 0x8A, 0x1D, // Y
                                        0x02, 0x19, 0x3E, 0xE6, 0x92, 0x23, 0x37, 0x2A,
                                        0x9E, 0xF5, 0xEF, 0x28, 0xE6, 0xE3, 0x94, 0x63,
                                        0x69, 0x14, 0x95, 0x7A, 0xF7, 0x10, 0xFB, 0xED };

const std::vector<uint8_t> PPID({ 0x13, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });

const std::vector<uint8_t> PCE_ID({ 0x00, 0x00 });

const std::vector<uint8_t> FMSPC({ 0x00, 0x70, 0x7F, 0x00, 0x00, 0x00 });

const x509::SgxType SGX_TYPE = x509::SgxType::Standard;

TEST_F(ParseX509CertificateIT, parsePemEncodedPckCert)
{
    const auto& pckCertificate = x509::PckCertificate::parse(PEM);

    ASSERT_EQ(pckCertificate.getVersion(), 3);
    ASSERT_THAT(pckCertificate.getSerialNumber(), ElementsAreArray(SERIAL_NUMBER));
    ASSERT_THAT(pckCertificate.getPubKey(), ElementsAreArray(PUBLIC_KEY));

    const auto& subject = pckCertificate.getSubject();
    ASSERT_EQ(subject.getRaw(), RAW_ISSUER);
    ASSERT_EQ(subject.getCommonName(), COMMON_NAME_ISSUER);
    ASSERT_EQ(subject.getCountryName(), COUNTRY_NAME_ISSUER);
    ASSERT_EQ(subject.getOrganizationName(), ORGANIZATION_NAME_ISSUER);
    ASSERT_EQ(subject.getLocationName(), LOCATION_NAME_ISSUER);
    ASSERT_EQ(subject.getStateName(), STATE_NAME_ISSUER);

    const auto& issuer = pckCertificate.getIssuer();
    ASSERT_EQ(issuer.getRaw(), RAW_SUBJECT);
    ASSERT_EQ(issuer.getCommonName(), COMMON_NAME_SUBJECT);
    ASSERT_EQ(issuer.getCountryName(), COUNTRY_NAME_SUBJECT);
    ASSERT_EQ(issuer.getOrganizationName(), ORGANIZATION_NAME_SUBJECT);
    ASSERT_EQ(issuer.getLocationName(), LOCATION_NAME_SUBJECT);
    ASSERT_EQ(issuer.getStateName(), STATE_NAME_SUBJECT);

    ASSERT_NE(issuer, subject); // they may be equal if certificate is self-signed

    const auto& validity = pckCertificate.getValidity();
    ASSERT_EQ(validity.getNotBeforeTime(), NOT_BEFORE_TIME);
    ASSERT_EQ(validity.getNotAfterTime(), NOT_AFTER_TIME);

    const auto& signature = pckCertificate.getSignature();
    ASSERT_THAT(signature.getRawDer(), ElementsAreArray(RAW_DER));
    ASSERT_THAT(signature.getR(), ElementsAreArray(R));
    ASSERT_THAT(signature.getS(), ElementsAreArray(S));

    const auto& ppid = pckCertificate.getPpid();
    ASSERT_THAT(ppid, ElementsAreArray(PPID));

    const auto& pceId = pckCertificate.getPceId();
    ASSERT_THAT(pceId, ElementsAreArray(PCE_ID));

    const auto& fmspc = pckCertificate.getFmspc();
    ASSERT_THAT(fmspc, ElementsAreArray(FMSPC));

    const auto& sgxType = pckCertificate.getSgxType();
    ASSERT_EQ(sgxType, SGX_TYPE);
}

