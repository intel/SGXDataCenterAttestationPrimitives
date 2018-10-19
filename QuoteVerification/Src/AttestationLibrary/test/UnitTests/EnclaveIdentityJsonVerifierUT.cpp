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
#include <QEIdentityJsonGenerator.h>

using namespace testing;
using namespace ::intel::sgx::qvl;
using namespace std;

struct EnclaveIdentityJsonVerifierUT : public Test
{
};

TEST_F(EnclaveIdentityJsonVerifierUT, shouldReturnEnclaveReportUnuprtedFormatWhenJsonIsEmpty)
{
    string emptyJson = "";

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    auto result = enclaveIdentityJsonVerifier.parse(emptyJson);

    ASSERT_EQ(STATUS_SGX_ENCLAVE_REPORT_UNSUPPORTED_FORMAT, result);
}

TEST_F(EnclaveIdentityJsonVerifierUT, shouldReturnEnclaveIdentityInvalidWhenMiscselectIsWrong)
{
    QEIdentityVectorModel model;
    model.miscselect = {{1, 1}};

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    auto result = enclaveIdentityJsonVerifier.parse(model.toJSON());

    ASSERT_EQ(STATUS_SGX_ENCLAVE_IDENTITY_INVALID, result);
}

TEST_F(EnclaveIdentityJsonVerifierUT, shouldReturnEnclaveIdentityInvalidWhenOptionalFieldIsInvalid)
{
    QEIdentityVectorModel model;
    string json = model.toJSON();
    removeWordFromString("mrenclave", json);
    removeWordFromString("mrsigner", json);
    removeWordFromString("isvprodid", json);
    removeWordFromString("isvsvn", json);

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    auto result = enclaveIdentityJsonVerifier.parse(json);

    ASSERT_EQ(STATUS_SGX_ENCLAVE_IDENTITY_INVALID, result);
}

TEST_F(EnclaveIdentityJsonVerifierUT, shouldReturnEnclaveIdentityInvalidWhenVerionFieldIsInvalid)
{
    QEIdentityVectorModel model;
    string json = model.toJSON();
    removeWordFromString("version", json);

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    auto result = enclaveIdentityJsonVerifier.parse(json);

    ASSERT_EQ(STATUS_SGX_ENCLAVE_IDENTITY_INVALID, result);
}

TEST_F(EnclaveIdentityJsonVerifierUT, shouldReturnEnclaveIdentityInvalidWhenMiscselectHasIncorrectSize)
{
    QEIdentityVectorModel model;
    model.miscselect= {{1, 1}};
    string json = model.toJSON();

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    auto result = enclaveIdentityJsonVerifier.parse(json);

    ASSERT_EQ(STATUS_SGX_ENCLAVE_IDENTITY_INVALID, result);
}

TEST_F(EnclaveIdentityJsonVerifierUT, shouldReturnEnclaveIdentityInvalidWhenMiscselectIsNotHexString)
{
    QEIdentityStringModel model;
    model.miscselect = "xyz00000";
    string json = model.toJSON();

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    auto result = enclaveIdentityJsonVerifier.parse(json);

    ASSERT_EQ(STATUS_SGX_ENCLAVE_IDENTITY_INVALID, result);
}

TEST_F(EnclaveIdentityJsonVerifierUT, shouldReturnEnclaveIdentityInvalidWhenMiscselectMaskHasIncorrectSize)
{
    QEIdentityVectorModel model;
    model.miscselectMask = {{1, 1}};
    string json = model.toJSON();

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    auto result = enclaveIdentityJsonVerifier.parse(json);

    ASSERT_EQ(STATUS_SGX_ENCLAVE_IDENTITY_INVALID, result);
}

TEST_F(EnclaveIdentityJsonVerifierUT, shouldReturnEnclaveIdentityInvalidWhenMiscselectMaskIsNotHexString)
{
    QEIdentityStringModel model;
    model.miscselectMask = "xyz00000";
    string json = model.toJSON();

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    auto result = enclaveIdentityJsonVerifier.parse(json);

    ASSERT_EQ(STATUS_SGX_ENCLAVE_IDENTITY_INVALID, result);
}

TEST_F(EnclaveIdentityJsonVerifierUT, shouldReturnEnclaveIdentityInvalidWhenAttributesHasIncorrectSize)
{
    QEIdentityVectorModel model;
    model.attributes = {{1, 1}};
    string json = model.toJSON();

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    auto result = enclaveIdentityJsonVerifier.parse(json);

    ASSERT_EQ(STATUS_SGX_ENCLAVE_IDENTITY_INVALID, result);
}

TEST_F(EnclaveIdentityJsonVerifierUT, shouldReturnEnclaveIdentityInvalidWhenAttributesIsNotHexString)
{
    QEIdentityStringModel model;
    model.attributes = "xyz45678900000000000000123456789";
    string json = model.toJSON();

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    auto result = enclaveIdentityJsonVerifier.parse(json);

    ASSERT_EQ(STATUS_SGX_ENCLAVE_IDENTITY_INVALID, result);
}

TEST_F(EnclaveIdentityJsonVerifierUT, shouldReturnEnclaveIdentityInvalidWhenAttributesMaskHasIncorrectSize)
{
    QEIdentityVectorModel model;
    model.attributesMask = {{1, 1}};
    string json = model.toJSON();

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    auto result = enclaveIdentityJsonVerifier.parse(json);

    ASSERT_EQ(STATUS_SGX_ENCLAVE_IDENTITY_INVALID, result);
}

TEST_F(EnclaveIdentityJsonVerifierUT, shouldReturnEnclaveIdentityInvalidWhenAttributesMaskIsNotHexString)
{
    QEIdentityStringModel model;
    model.attributesMask = "xyz45678900000000000000123456789";
    string json = model.toJSON();

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    auto result = enclaveIdentityJsonVerifier.parse(json);

    ASSERT_EQ(STATUS_SGX_ENCLAVE_IDENTITY_INVALID, result);
}

TEST_F(EnclaveIdentityJsonVerifierUT, shouldReturnEnclaveIdentityInvalidWhenIssuedateIsWrong)
{
    QEIdentityStringModel model;
    model.issueDate = "2018-08-22T10:09:";
    string json = model.toJSON();

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    auto result = enclaveIdentityJsonVerifier.parse(json);

    ASSERT_EQ(STATUS_SGX_ENCLAVE_IDENTITY_INVALID, result);
}

TEST_F(EnclaveIdentityJsonVerifierUT, shouldReturnEnclaveIdentityInvalidWhenNextUpdateIsWrong)
{
    QEIdentityStringModel model;
    model.nextUpdate = "2018-08-22T10:09:";
    string json = model.toJSON();

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    auto result = enclaveIdentityJsonVerifier.parse(json);

    ASSERT_EQ(STATUS_SGX_ENCLAVE_IDENTITY_INVALID, result);
}

TEST_F(EnclaveIdentityJsonVerifierUT, shouldReturnStatusOkWhenJsonIsOk)
{
    string json = QEIdentityVectorModel().toJSON();

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    auto result = enclaveIdentityJsonVerifier.parse(json);

    ASSERT_EQ(STATUS_OK, result);
}

TEST_F(EnclaveIdentityJsonVerifierUT, shouldReturnEnclaveIdentityUnsuportedVersionWhenVersionIsWrong)
{
    QEIdentityVectorModel model;
    model.version = 5;
    string json = model.toJSON();

    EnclaveIdentityJsonVerifier enclaveIdentityJsonVerifier;
    auto result = enclaveIdentityJsonVerifier.parse(json);

    ASSERT_EQ(STATUS_SGX_ENCLAVE_IDENTITY_UNSUPPORTED_VERSION, result);
}
