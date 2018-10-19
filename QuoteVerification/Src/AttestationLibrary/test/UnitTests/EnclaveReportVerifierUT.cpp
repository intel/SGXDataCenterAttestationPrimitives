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
#include <Verifiers/EnclaveReportVerifier.h>
#include <Verifiers/EnclaveIdentityJsonVerifier.h>
#include <numeric>
#include <iostream>
#include <QuoteGenerator.h>
#include <QuoteVerification/Quote.h>
#include <array>
#include <QEIdentityJsonGenerator.h>

using namespace testing;
using namespace ::intel::sgx::qvl;
using namespace std;

struct EnclaveReportVerifierUT : public Test
{
    EnclaveReportVerifier enclaveReportVerifier;
    test::QuoteGenerator quoteGenerator;
    test::QuoteGenerator::EnclaveReport enclaveReport;

    Quote::EnclaveReport getEnclaveReport()
    {
        quoteGenerator.withBody(enclaveReport);
        const auto enclaveReportBody = quoteGenerator.getBody().bytes();
        Quote quote;
        quote.parseEnclaveReport(enclaveReportBody);
        return quote.getBody();
    }
};


TEST_F(EnclaveReportVerifierUT, shouldReturnEnclaveReportMiscselectMismatchWhenMiscselectIsDifferent)
{
    QEIdentityVectorModel model;
    model.miscselect = {{1, 1, 1, 1}};
    model.applyTo(enclaveReport);
    string json = model.toJSON();

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    enclaveIdentityJsonVerifier.parse(json);

    auto result = enclaveReportVerifier.verify(enclaveIdentityJsonVerifier, getEnclaveReport());

    ASSERT_EQ(STATUS_SGX_ENCLAVE_REPORT_MISCSELECT_MISMATCH, result);
}

TEST_F(EnclaveReportVerifierUT, shouldReturnEnclaveReportAttributestMismatchWhenAttributesIsDifferent)
{
    QEIdentityVectorModel model;
    model.applyTo(enclaveReport);
    model.attributes = {{9, 9, 9, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
    string json = model.toJSON();

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    enclaveIdentityJsonVerifier.parse(json);

    auto result = enclaveReportVerifier.verify(enclaveIdentityJsonVerifier, getEnclaveReport());

    ASSERT_EQ(STATUS_SGX_ENCLAVE_REPORT_ATTRIBUTES_MISMATCH, result);
}

TEST_F(EnclaveReportVerifierUT, shouldReturnEnclaveReportAttributestMismatchWhenIdentityAttributesHasIncorrectSize)
{
    QEIdentityVectorModel model;
    model.attributesMask = {{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}};
    model.applyTo(enclaveReport);
    string json = model.toJSON();

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    enclaveIdentityJsonVerifier.parse(json);

    auto result = enclaveReportVerifier.verify(enclaveIdentityJsonVerifier, getEnclaveReport());

    ASSERT_EQ(STATUS_SGX_ENCLAVE_REPORT_ATTRIBUTES_MISMATCH, result);
}

TEST_F(EnclaveReportVerifierUT, shouldReturnEnclaveReportMrenclaveMismatchWhenMrenclaveIsDifferent)
{
    QEIdentityVectorModel model;
    model.applyTo(enclaveReport);
    model.mrenclave = {{8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8}};
    string json = model.toJSON();

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    enclaveIdentityJsonVerifier.parse(json);

    auto result = enclaveReportVerifier.verify(enclaveIdentityJsonVerifier, getEnclaveReport());

    ASSERT_EQ(STATUS_SGX_ENCLAVE_REPORT_MRENCLAVE_MISMATCH, result);
}

TEST_F(EnclaveReportVerifierUT, shouldReturnStausOkWhenMrenclaveIsNotPresent)
{
    QEIdentityVectorModel model;
    model.applyTo(enclaveReport);
    string json = model.toJSON();

    removeWordFromString("mrenclave", json);

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    enclaveIdentityJsonVerifier.parse(json);

    auto result = enclaveReportVerifier.verify(enclaveIdentityJsonVerifier, getEnclaveReport());

    ASSERT_EQ(STATUS_OK, result);
}

TEST_F(EnclaveReportVerifierUT, shouldReturnStausOkWhenMrsignerIsNotPresent)
{
    QEIdentityVectorModel model;
    model.applyTo(enclaveReport);
    string json = model.toJSON();

    removeWordFromString("mrsigner", json);

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    enclaveIdentityJsonVerifier.parse(json);

    auto result = enclaveReportVerifier.verify(enclaveIdentityJsonVerifier, getEnclaveReport());

    ASSERT_EQ(STATUS_OK, result);
}

TEST_F(EnclaveReportVerifierUT, shouldReturnStausOkWhenIsvprodidIsNotPresent)
{
    QEIdentityVectorModel model;
    model.applyTo(enclaveReport);
    string json = model.toJSON();

    removeWordFromString("isvprodid", json);

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    enclaveIdentityJsonVerifier.parse(json);

    auto result = enclaveReportVerifier.verify(enclaveIdentityJsonVerifier, getEnclaveReport());

    ASSERT_EQ(STATUS_OK, result);
}

TEST_F(EnclaveReportVerifierUT, shouldReturnStausOkWhenIsvsvnIsNotPresent)
{
    QEIdentityVectorModel model;
    model.applyTo(enclaveReport);
    string json = model.toJSON();

    removeWordFromString("isvsvn", json);

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    enclaveIdentityJsonVerifier.parse(json);

    auto result = enclaveReportVerifier.verify(enclaveIdentityJsonVerifier, getEnclaveReport());

    ASSERT_EQ(STATUS_OK, result);
}

TEST_F(EnclaveReportVerifierUT, shouldReturnEnclaveReportMrsignerMismatchWhenMrsignerIsDifferent)
{
    QEIdentityVectorModel model{};
    model.applyTo(enclaveReport);
    model.mrsigner = {{8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
    string json = model.toJSON();

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    enclaveIdentityJsonVerifier.parse(json);

    auto result = enclaveReportVerifier.verify(enclaveIdentityJsonVerifier, getEnclaveReport());

    ASSERT_EQ(STATUS_SGX_ENCLAVE_REPORT_MRSIGNER_MISMATCH, result);
}

TEST_F(EnclaveReportVerifierUT, shouldReturnEnclaveReportIsvprodidMismatchWhenIsvprodidIsDifferent)
{
    QEIdentityVectorModel model;
    model.applyTo(enclaveReport);
    model.isvprodid = 11;
    string json = model.toJSON();

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    enclaveIdentityJsonVerifier.parse(json);

    auto result = enclaveReportVerifier.verify(enclaveIdentityJsonVerifier, getEnclaveReport());

    ASSERT_EQ(STATUS_SGX_ENCLAVE_REPORT_ISVPRODID_MISMATCH, result);
}

TEST_F(EnclaveReportVerifierUT, shouldReturnEnclaveReportIsvsvnMismatchWhenIsvsvnIsDifferent)
{
    QEIdentityVectorModel model;
    model.applyTo(enclaveReport);
    model.isvsvn = 11;
    string json = model.toJSON();

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    enclaveIdentityJsonVerifier.parse(json);

    auto result = enclaveReportVerifier.verify(enclaveIdentityJsonVerifier, getEnclaveReport());

    ASSERT_EQ(STATUS_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE, result);
}

TEST_F(EnclaveReportVerifierUT, shouldReturnStatusOkWhenJsonIsOk)
{
    QEIdentityVectorModel model;
    model.applyTo(enclaveReport);
    string json = model.toJSON();

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    enclaveIdentityJsonVerifier.parse(json);

    auto result = enclaveReportVerifier.verify(enclaveIdentityJsonVerifier, getEnclaveReport());

    ASSERT_EQ(STATUS_OK, result);
}

TEST_F(EnclaveReportVerifierUT, shouldReturnEnclaveIdentityInvalidWhenIssueDateInTheFuture)
{
    QEIdentityVectorModel model;
    model.issueDate = "2119-08-22T10:09:10Z";
    model.applyTo(enclaveReport);
    string json = model.toJSON();

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    enclaveIdentityJsonVerifier.parse(json);

    auto result = enclaveReportVerifier.verify(enclaveIdentityJsonVerifier, getEnclaveReport());

    ASSERT_EQ(STATUS_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE, result);
}

TEST_F(EnclaveReportVerifierUT, shouldReturnEnclaveIdentityInvalidWhenNextUpdateExpired)
{
    QEIdentityVectorModel model;
    model.nextUpdate = "2000-08-22T10:09:10Z";
    model.applyTo(enclaveReport);
    string json = model.toJSON();

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    enclaveIdentityJsonVerifier.parse(json);

    auto result = enclaveReportVerifier.verify(enclaveIdentityJsonVerifier, getEnclaveReport());

    ASSERT_EQ(STATUS_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE, result);
}
