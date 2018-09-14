
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

#include <CertVerification/CertificateChain.h>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

using namespace intel::sgx::qvl;
using namespace testing;
using sysclock = std::chrono::system_clock;

struct CertificateValidityTests : public Test
{
    const long SECONDS_IN_A_DAY = 3600 * 24;
    const long ADJUST_TIME_SECONDS = 7 * SECONDS_IN_A_DAY;

    // special never expire time: https://tools.ietf.org/html/rfc5280#section-4.1.2.5
    const std::string NEVER_EXPIRE_TIME_STRING = "99991231235959Z";
};

namespace { // anonymous namespace

crypto::X509_uptr generateSelfSignedCertificate(const long adjustNotBeforeTimeSeconds, const long adjustNotAfterTimeSeconds)
{
    // 1. Generate the key
    auto ecKey = crypto::make_unique<EC_KEY>(EC_KEY_new());
    auto ecGroup = crypto::make_unique<EC_GROUP>(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));

    if(1 != EC_KEY_set_group(ecKey.get(), ecGroup.get()))
    {
        return crypto::make_unique<X509>(nullptr);
    }

    if(1 != EC_KEY_generate_key(ecKey.get()))
    {
        return crypto::make_unique<X509>(nullptr);
    }

    auto pkey = crypto::make_unique<EVP_PKEY>(EVP_PKEY_new());
    EVP_PKEY_assign_EC_KEY(pkey.get(), ecKey.release()); // EVP_PKEY takes ownership of the EC_KEY*

    // 2. Generate certificate
    auto x509 = crypto::make_unique<X509>(X509_new());

    ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), 1);

    X509_gmtime_adj(X509_get_notBefore(x509.get()), adjustNotBeforeTimeSeconds);
    X509_gmtime_adj(X509_get_notAfter(x509.get()), adjustNotAfterTimeSeconds);

    X509_set_pubkey(x509.get(), pkey.get());

    // 3. Self-sign the certificate
    X509_sign(x509.get(), pkey.get(), EVP_sha1());

    return x509;
}

} // end of anonymous namespace

TEST_F(CertificateValidityTests, validityOfCertificate_inBetweenValidDates_shouldBeTrue)
{
    // GIVEN
    // Generate a certificate that is valid from a week before, until a week after
    crypto::X509_uptr x509 = generateSelfSignedCertificate(-ADJUST_TIME_SECONDS, +ADJUST_TIME_SECONDS);
    ASSERT_TRUE(x509) << "Failed to generate x509 certificate";

    // WHEN
    auto validity = pckparser::getValidity(*x509);
    auto currentTime = sysclock::to_time_t(sysclock::now());

    // THEN
    EXPECT_TRUE(validity.isValid());
    EXPECT_GT(currentTime, validity.notBeforeTime);
    EXPECT_LT(currentTime, validity.notAfterTime);
}

TEST_F(CertificateValidityTests, validityOfCertificate_thatIsNotYetValid_shouldBeFalse)
{
    // GIVEN
    // Generate a certificate that is not yet valid - it will be in a week
    crypto::X509_uptr x509 = generateSelfSignedCertificate(+ADJUST_TIME_SECONDS, +ADJUST_TIME_SECONDS * 2);
    ASSERT_TRUE(x509) << "Failed to generate x509 certificate";

    // WHEN
    auto validity = pckparser::getValidity(*x509);
    auto currentTime = sysclock::to_time_t(sysclock::now());

    // THEN
    EXPECT_FALSE(validity.isValid());
    EXPECT_LT(currentTime, validity.notBeforeTime);
}

TEST_F(CertificateValidityTests, validityOfCertificate_thatHasAlreadyExpired_shouldBeFalse)
{
    // GIVEN
    // Generate a certificate that has already expired a week ago
    crypto::X509_uptr x509 = generateSelfSignedCertificate(-ADJUST_TIME_SECONDS * 2, -ADJUST_TIME_SECONDS);
    ASSERT_TRUE(x509) << "Failed to generate x509 certificate";

    // WHEN
    auto validity = pckparser::getValidity(*x509);
    auto currentTime = sysclock::to_time_t(sysclock::now());

    // THEN
    EXPECT_FALSE(validity.isValid());
    EXPECT_GT(currentTime, validity.notAfterTime);
}

TEST_F(CertificateValidityTests, validityOfCertificate_withIdenticalNotBeforeAndNotAfterDates_andCertExpired_shouldBeFalse)
{
    // GIVEN
    crypto::X509_uptr x509 = generateSelfSignedCertificate(-ADJUST_TIME_SECONDS, -ADJUST_TIME_SECONDS);
    ASSERT_TRUE(x509) << "Failed to generate x509 certificate";

    // WHEN
    auto validity = pckparser::getValidity(*x509);
    auto currentTime = sysclock::to_time_t(sysclock::now());

    // THEN
    EXPECT_FALSE(validity.isValid());
    EXPECT_GT(currentTime, validity.notBeforeTime);
    EXPECT_GT(currentTime, validity.notAfterTime);
}

TEST_F(CertificateValidityTests, validityOfCertificate_withIdenticalNotBeforeAndNotAfterDates_andCertNotYetValid_shouldBeFalse)
{
    // GIVEN
    crypto::X509_uptr x509 = generateSelfSignedCertificate(+ADJUST_TIME_SECONDS, +ADJUST_TIME_SECONDS);
    ASSERT_TRUE(x509) << "Failed to generate x509 certificate";

    // WHEN
    auto validity = pckparser::getValidity(*x509);
    auto currentTime = sysclock::to_time_t(sysclock::now());

    // THEN
    EXPECT_FALSE(validity.isValid());
    EXPECT_LT(currentTime, validity.notBeforeTime);
    EXPECT_LT(currentTime, validity.notAfterTime);
}

TEST_F(CertificateValidityTests, validityOfCertificate_priorToNotBeforeDate_andBeyondNotAfterDate_shouldBeFalse)
{
    // GIVEN
    // This is a special "sanity" check case:
    //  - 'notBefore' date has not yet came -> cert not valid yet
    //  - 'notAfter' date is long in the past -> cert already expired
    crypto::X509_uptr x509 = generateSelfSignedCertificate(+ADJUST_TIME_SECONDS, -ADJUST_TIME_SECONDS);
    ASSERT_TRUE(x509) << "Failed to generate x509 certificate";

    // WHEN
    auto validity = pckparser::getValidity(*x509);
    auto currentTime = sysclock::to_time_t(sysclock::now());

    // THEN
    EXPECT_FALSE(validity.isValid());
    EXPECT_LT(currentTime, validity.notBeforeTime);
    EXPECT_GT(currentTime, validity.notAfterTime);
}

TEST_F(CertificateValidityTests, validityOfCertificate_withNotAfterDateSetToNeverExpire_andBeyondNotBeforeDate_shouldBeTrue)
{
    // GIVEN
    crypto::X509_uptr x509 = generateSelfSignedCertificate(-ADJUST_TIME_SECONDS, 0);
    ASSERT_TRUE(x509) << "Failed to generate x509 certificate";

    auto neverExpireTime = crypto::make_unique<ASN1_TIME>(ASN1_TIME_new());
    ASSERT_EQ(1, ASN1_TIME_set_string(neverExpireTime.get(), NEVER_EXPIRE_TIME_STRING.c_str()));
    ASSERT_EQ(1, X509_set1_notAfter(x509.get(), neverExpireTime.get()));

    // WHEN
    auto validity = pckparser::getValidity(*x509);
    auto currentTime = sysclock::to_time_t(sysclock::now());

    // THEN
    EXPECT_TRUE(validity.isValid());
    EXPECT_GT(currentTime, validity.notBeforeTime);
    EXPECT_LT(currentTime, validity.notAfterTime);
}

TEST_F(CertificateValidityTests, validityOfCertificate_withNotAfterDateSetToNeverExpire_andPriorToBeforeDate_shouldBeFalse)
{
    // GIVEN
    crypto::X509_uptr x509 = generateSelfSignedCertificate(+ADJUST_TIME_SECONDS, 0);
    ASSERT_TRUE(x509) << "Failed to generate x509 certificate";

    auto neverExpireTime = crypto::make_unique<ASN1_TIME>(ASN1_TIME_new());
    ASSERT_EQ(1, ASN1_TIME_set_string(neverExpireTime.get(), NEVER_EXPIRE_TIME_STRING.c_str()));
    ASSERT_EQ(1, X509_set1_notAfter(x509.get(), neverExpireTime.get()));

    // WHEN
    auto validity = pckparser::getValidity(*x509);
    auto currentTime = sysclock::to_time_t(sysclock::now());

    // THEN
    EXPECT_FALSE(validity.isValid());
    EXPECT_LT(currentTime, validity.notBeforeTime);
    EXPECT_LT(currentTime, validity.notAfterTime);
}
