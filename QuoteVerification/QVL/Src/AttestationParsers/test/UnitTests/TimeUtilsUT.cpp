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

#include <Utils/TimeUtils.h>

#include <gtest/gtest.h>

#include <chrono>

using namespace intel::sgx::dcap::parser;
using namespace ::testing;

struct TimeUtilsUT: public testing::TestWithParam<time_t>
{
    static void assertEqualTM(const tm *val1, const tm *val2)
    {
        ASSERT_EQ(val1->tm_sec, val2->tm_sec);
        ASSERT_EQ(val1->tm_min, val2->tm_min);
        ASSERT_EQ(val1->tm_hour, val2->tm_hour);
        ASSERT_EQ(val1->tm_mday, val2->tm_mday);
        ASSERT_EQ(val1->tm_mon, val2->tm_mon);
        ASSERT_EQ(val1->tm_year, val2->tm_year);
        ASSERT_EQ(val1->tm_isdst, val2->tm_isdst);
    }

    time_t now = time(0);
    struct tm *tm_now = std::gmtime(&now);
    time_t tmp = std::mktime(tm_now);
    time_t timeZoneDiff = now - tmp; // Enclave assumes that given time is always GMT
};

TEST_P(TimeUtilsUT, gmtime)
{
    std::cout << "gmtime input value: " << GetParam() << std::endl;
    assertEqualTM(standard::gmtime(&GetParam()), enclave::gmtime(&GetParam()));
}

const time_t positiveInput[] = {
        0,
        rand(),
        rand(),
};

INSTANTIATE_TEST_CASE_P(TestsWithParameters, TimeUtilsUT, ::testing::ValuesIn(positiveInput),);

TEST_P(TimeUtilsUT, mktime)
{
    std::cout << "mktime input value: " << GetParam() << std::endl;
    auto val = std::gmtime(&GetParam());
    ASSERT_EQ(standard::mktime(val), enclave::mktime(val) - timeZoneDiff);
}

TEST_F(TimeUtilsUT, mktimeNullAsParam)
{
    ASSERT_EQ(standard::gmtime(nullptr), enclave::gmtime(nullptr));
}

TEST_F(TimeUtilsUT, getTimeFromString)
{
    auto date = std::string("2017-10-04T11:10:45Z");
    const auto standard = standard::getTimeFromString(date);
    const auto enclave = enclave::getTimeFromString(date);
    assertEqualTM(&standard, &enclave);
}

TEST_F(TimeUtilsUT, getTimeFromString_empty)
{
    auto date = std::string("");
    const auto standard = standard::getTimeFromString(date);
    const auto enclave = enclave::getTimeFromString(date);
    assertEqualTM(&standard, &enclave);
}

TEST_F(TimeUtilsUT, isValidTimeString)
{
    auto date = std::string("2017-10-04T11:10:45Z");
    ASSERT_EQ(standard::isValidTimeString(date), enclave::isValidTimeString(date));
}

TEST_F(TimeUtilsUT, isValidTimeString_empty)
{
    auto date = std::string("");
    ASSERT_EQ(standard::isValidTimeString(date), enclave::isValidTimeString(date));
}
