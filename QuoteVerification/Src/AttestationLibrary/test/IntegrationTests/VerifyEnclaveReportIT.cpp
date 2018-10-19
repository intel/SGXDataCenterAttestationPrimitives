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
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <SgxEcdsaAttestation/QuoteVerification.h>
#include <QEIdentityGenerator.h>
#include <QuoteGenerator.h>
#include <QEIdentityJsonGenerator.h>
#include <string>

using namespace testing;
using namespace testutils;
using namespace intel::sgx::qvl;
using namespace std;

struct VerifyEnclaveReportIT : public Test
{
    test::QuoteGenerator::EnclaveReport enclaveReport;

    VerifyEnclaveReportIT()
    {
    }

};

TEST_F(VerifyEnclaveReportIT, nullptrArgumentsShouldReturnEnclaveReportUnsuportedFormat)
{
    ASSERT_EQ(STATUS_SGX_ENCLAVE_REPORT_UNSUPPORTED_FORMAT, sgxAttestationVerifyEnclaveReport(nullptr, nullptr));
}

TEST_F(VerifyEnclaveReportIT, nullptrEnclaveIdentityShouldReturnEnclaveReportUnsuportedFormat)
{
    QEIdentityVectorModel model;
    model.applyTo(enclaveReport);
    auto json = model.toJSON();

    ASSERT_EQ(STATUS_SGX_ENCLAVE_REPORT_UNSUPPORTED_FORMAT, sgxAttestationVerifyEnclaveReport(nullptr, json.c_str()));
}

TEST_F(VerifyEnclaveReportIT, nullptrEnclaveReportShouldReturnEnclaveReportUnsuportedFormat)
{
    QEIdentityVectorModel model;
    model.applyTo(enclaveReport);
    auto json = model.toJSON();

    ASSERT_EQ(STATUS_SGX_ENCLAVE_REPORT_UNSUPPORTED_FORMAT, sgxAttestationVerifyEnclaveReport(enclaveReport.bytes().data(), nullptr));
}

TEST_F(VerifyEnclaveReportIT, validEncaveReportandEnclaveIdentityShouldReturnStatusOk)
{
    QEIdentityVectorModel model;
    model.applyTo(enclaveReport);
    auto json = model.toJSON();

    ASSERT_EQ(STATUS_OK, sgxAttestationVerifyEnclaveReport(enclaveReport.bytes().data(), json.c_str()));
}

TEST_F(VerifyEnclaveReportIT, validDataFormatShouldReturnEnclaveIdentityInvalid)
{
    QEIdentityVectorModel model;
    model.issueDate = "2018-080:09:10Z";
    model.applyTo(enclaveReport);
    auto json = model.toJSON();

    ASSERT_EQ(STATUS_SGX_ENCLAVE_IDENTITY_INVALID,
            sgxAttestationVerifyEnclaveReport(enclaveReport.bytes().data(), json.c_str()));
}
