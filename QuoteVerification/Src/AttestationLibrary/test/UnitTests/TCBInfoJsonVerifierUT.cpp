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
#include <Verifiers/TCBInfoJsonVerifier.h>
#include <TcbInfoGenerator.h>

using namespace testing;
using namespace intel::sgx::qvl;

struct TCBInfoJsonVerifierTests : public Test
{
};

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenInitializedWithEmptyString)
{
    EXPECT_EQ(STATUS_SGX_TCB_INFO_UNSUPPORTED_FORMAT, TCBInfoJsonVerifier{}.parse(""));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWHenInitializedWithInvalidJSON)
{
    EXPECT_EQ(STATUS_SGX_TCB_INFO_UNSUPPORTED_FORMAT, TCBInfoJsonVerifier().parse("Plain string."));
}

TEST_F(TCBInfoJsonVerifierTests, shouldSuccessfullyParseWhenAllRequiredDataProvided)
{
    auto tcbInfoJson = generateTcbInfo();
    std::vector<uint8_t> expectedCpusvn{12, 23, 34, 45, 100, 0, 1, 156, 208, 255, 2, 3, 4, 5, 6, 7};
    unsigned int expectedPcesvn = 30865;

    TCBInfoJsonVerifier verifier{};

    EXPECT_EQ(STATUS_OK, verifier.parse(tcbInfoJson));
    EXPECT_EQ(1, verifier.getTcbLevels().size());
    EXPECT_EQ(expectedCpusvn, verifier.getTcbLevels().begin()->cpusvn);
    EXPECT_EQ(expectedPcesvn, verifier.getTcbLevels().begin()->pcesvn);
    EXPECT_EQ("UpToDate", verifier.getTcbLevels().begin()->status);
}

TEST_F(TCBInfoJsonVerifierTests, shouldSuccessfullyParseMultipleTcbLevels)
{
    std::vector<uint8_t> expectedCpusvn{55, 0, 0, 1, 10, 0, 0, 77, 200, 200, 250, 250, 55, 2, 2, 2};
    unsigned int expectedPcesvn = 66;
    std::vector<uint8_t> expectedRevokedCpusvn{44, 0, 0, 1, 10, 0, 0, 77, 200, 200, 250, 250, 55, 2, 2, 2};
    unsigned int expectedRevokedPcesvn = 65;
    const std::string upToDateTcb = R"json(
    "tcb": {
        "sgxtcbcomp01svn": 55,
        "sgxtcbcomp02svn": 0,
        "sgxtcbcomp03svn": 0,
        "sgxtcbcomp04svn": 1,
        "sgxtcbcomp05svn": 10,
        "sgxtcbcomp06svn": 0,
        "sgxtcbcomp07svn": 0,
        "sgxtcbcomp08svn": 77,
        "sgxtcbcomp09svn": 200,
        "sgxtcbcomp10svn": 200,
        "sgxtcbcomp11svn": 250,
        "sgxtcbcomp12svn": 250,
        "sgxtcbcomp13svn": 55,
        "sgxtcbcomp14svn": 2,
        "sgxtcbcomp15svn": 2,
        "sgxtcbcomp16svn": 2,
        "pcesvn": 66
    })json";
    const std::string revokedTcb = R"json(
    "tcb": {
        "sgxtcbcomp01svn": 44,
        "sgxtcbcomp02svn": 0,
        "sgxtcbcomp03svn": 0,
        "sgxtcbcomp04svn": 1,
        "sgxtcbcomp05svn": 10,
        "sgxtcbcomp06svn": 0,
        "sgxtcbcomp07svn": 0,
        "sgxtcbcomp08svn": 77,
        "sgxtcbcomp09svn": 200,
        "sgxtcbcomp10svn": 200,
        "sgxtcbcomp11svn": 250,
        "sgxtcbcomp12svn": 250,
        "sgxtcbcomp13svn": 55,
        "sgxtcbcomp14svn": 2,
        "sgxtcbcomp15svn": 2,
        "sgxtcbcomp16svn": 2,
        "pcesvn": 65
    })json";
    const std::string configurationNeededTcb = R"json(
    "tcb": {
        "sgxtcbcomp01svn": 48,
        "sgxtcbcomp02svn": 0,
        "sgxtcbcomp03svn": 0,
        "sgxtcbcomp04svn": 1,
        "sgxtcbcomp05svn": 10,
        "sgxtcbcomp06svn": 0,
        "sgxtcbcomp07svn": 0,
        "sgxtcbcomp08svn": 77,
        "sgxtcbcomp09svn": 200,
        "sgxtcbcomp10svn": 200,
        "sgxtcbcomp11svn": 250,
        "sgxtcbcomp12svn": 222,
        "sgxtcbcomp13svn": 55,
        "sgxtcbcomp14svn": 2,
        "sgxtcbcomp15svn": 2,
        "sgxtcbcomp16svn": 2,
        "pcesvn": 66
    })json";
    const std::string tcbLevels = generateTcbLevel(validTcbLevelTemplate, validTcb, validOutOfDateStatus)
        + "," + generateTcbLevel(validTcbLevelTemplate, upToDateTcb, validUpToDateStatus)
        + "," + generateTcbLevel(validTcbLevelTemplate, revokedTcb, validRevokedStatus)
        + "," + generateTcbLevel(validTcbLevelTemplate, configurationNeededTcb, validConfigurationNeededStatus);
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, tcbLevels);

    TCBInfoJsonVerifier verifier{};
    EXPECT_EQ(STATUS_OK, verifier.parse(tcbInfoJson));
    EXPECT_EQ(4, verifier.getTcbLevels().size());
    auto iterator = verifier.getTcbLevels().begin();
    EXPECT_EQ(expectedCpusvn, iterator->cpusvn);
    EXPECT_EQ(expectedPcesvn, iterator->pcesvn);
    EXPECT_EQ("UpToDate", iterator->status);
    std::advance(iterator, 2);
    EXPECT_EQ(expectedRevokedCpusvn, iterator->cpusvn);
    EXPECT_EQ(expectedRevokedPcesvn, iterator->pcesvn);
    EXPECT_EQ("Revoked", iterator->status);
}

TEST_F(TCBInfoJsonVerifierTests, shouldSuccessfullyParseMultipleRevokedTcbLevels)
{
    std::vector<uint8_t> expectedRevokedCpusvn{44, 0, 0, 1, 10, 0, 0, 77, 200, 222, 111, 121, 55, 2, 2, 2};
    uint16_t expectedRevokedPcesvn = 66;
    const std::string revokedTcbLatest = R"json(
    "tcb": {
        "sgxtcbcomp01svn": 44,
        "sgxtcbcomp02svn": 0,
        "sgxtcbcomp03svn": 0,
        "sgxtcbcomp04svn": 1,
        "sgxtcbcomp05svn": 10,
        "sgxtcbcomp06svn": 0,
        "sgxtcbcomp07svn": 0,
        "sgxtcbcomp08svn": 77,
        "sgxtcbcomp09svn": 200,
        "sgxtcbcomp10svn": 222,
        "sgxtcbcomp11svn": 111,
        "sgxtcbcomp12svn": 121,
        "sgxtcbcomp13svn": 55,
        "sgxtcbcomp14svn": 2,
        "sgxtcbcomp15svn": 2,
        "sgxtcbcomp16svn": 2,
        "pcesvn": 66
    })json";
    const std::string otherRevokedTcb1 = R"json(
    "tcb": {
        "sgxtcbcomp01svn": 44,
        "sgxtcbcomp02svn": 0,
        "sgxtcbcomp03svn": 0,
        "sgxtcbcomp04svn": 1,
        "sgxtcbcomp05svn": 10,
        "sgxtcbcomp06svn": 0,
        "sgxtcbcomp07svn": 0,
        "sgxtcbcomp08svn": 77,
        "sgxtcbcomp09svn": 200,
        "sgxtcbcomp10svn": 222,
        "sgxtcbcomp11svn": 111,
        "sgxtcbcomp12svn": 121,
        "sgxtcbcomp13svn": 55,
        "sgxtcbcomp14svn": 2,
        "sgxtcbcomp15svn": 2,
        "sgxtcbcomp16svn": 2,
        "pcesvn": 65
    })json";
    const std::string otherRevokedTcb2 = R"json(
    "tcb": {
        "sgxtcbcomp01svn": 44,
        "sgxtcbcomp02svn": 0,
        "sgxtcbcomp03svn": 0,
        "sgxtcbcomp04svn": 0,
        "sgxtcbcomp05svn": 10,
        "sgxtcbcomp06svn": 0,
        "sgxtcbcomp07svn": 0,
        "sgxtcbcomp08svn": 77,
        "sgxtcbcomp09svn": 200,
        "sgxtcbcomp10svn": 222,
        "sgxtcbcomp11svn": 111,
        "sgxtcbcomp12svn": 121,
        "sgxtcbcomp13svn": 55,
        "sgxtcbcomp14svn": 2,
        "sgxtcbcomp15svn": 2,
        "sgxtcbcomp16svn": 2,
        "pcesvn": 66
    })json";
    const std::string tcbLevels = generateTcbLevel(validTcbLevelTemplate, validTcb, validUpToDateStatus)
        + "," + generateTcbLevel(validTcbLevelTemplate, otherRevokedTcb1, validRevokedStatus)
        + "," + generateTcbLevel(validTcbLevelTemplate, revokedTcbLatest, validRevokedStatus)
        + "," + generateTcbLevel(validTcbLevelTemplate, otherRevokedTcb2, validRevokedStatus);
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, tcbLevels);

    TCBInfoJsonVerifier verifier{};
    EXPECT_EQ(STATUS_OK, verifier.parse(tcbInfoJson));
    EXPECT_EQ(4, verifier.getTcbLevels().size());
    auto iterator = verifier.getTcbLevels().begin();
    std::advance(iterator, 0);
    EXPECT_EQ(expectedRevokedCpusvn, iterator->cpusvn);
    EXPECT_EQ(expectedRevokedPcesvn, iterator->pcesvn);
    EXPECT_EQ("Revoked", iterator->status);
}

TEST_F(TCBInfoJsonVerifierTests, shouldSucceedWhenTcbLevelsContainsOnlyRevokedTcbs)
{
    std::vector<uint8_t> expectedRevokedCpusvn{55, 0, 0, 1, 10, 0, 0, 77, 200, 200, 250, 250, 55, 2, 2, 2};
    unsigned int expectedRevokedPcesvn = 66;
    const std::string revokedTcb1 = R"json(
    "tcb": {
        "sgxtcbcomp01svn": 55,
        "sgxtcbcomp02svn": 0,
        "sgxtcbcomp03svn": 0,
        "sgxtcbcomp04svn": 1,
        "sgxtcbcomp05svn": 10,
        "sgxtcbcomp06svn": 0,
        "sgxtcbcomp07svn": 0,
        "sgxtcbcomp08svn": 77,
        "sgxtcbcomp09svn": 200,
        "sgxtcbcomp10svn": 200,
        "sgxtcbcomp11svn": 250,
        "sgxtcbcomp12svn": 250,
        "sgxtcbcomp13svn": 55,
        "sgxtcbcomp14svn": 2,
        "sgxtcbcomp15svn": 2,
        "sgxtcbcomp16svn": 2,
        "pcesvn": 66
    })json";
    const std::string revokedTcb2 = R"json(
    "tcb": {
        "sgxtcbcomp01svn": 44,
        "sgxtcbcomp02svn": 0,
        "sgxtcbcomp03svn": 0,
        "sgxtcbcomp04svn": 1,
        "sgxtcbcomp05svn": 10,
        "sgxtcbcomp06svn": 0,
        "sgxtcbcomp07svn": 0,
        "sgxtcbcomp08svn": 77,
        "sgxtcbcomp09svn": 200,
        "sgxtcbcomp10svn": 200,
        "sgxtcbcomp11svn": 250,
        "sgxtcbcomp12svn": 250,
        "sgxtcbcomp13svn": 55,
        "sgxtcbcomp14svn": 2,
        "sgxtcbcomp15svn": 2,
        "sgxtcbcomp16svn": 2,
        "pcesvn": 65
    })json";
    const std::string tcbLevels = generateTcbLevel(validTcbLevelTemplate, revokedTcb1, validRevokedStatus)
        + "," + generateTcbLevel(validTcbLevelTemplate, revokedTcb2, validRevokedStatus);
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, tcbLevels);

    TCBInfoJsonVerifier verifier{};
    EXPECT_EQ(STATUS_OK, verifier.parse(tcbInfoJson));
    EXPECT_EQ(2, verifier.getTcbLevels().size());
    auto iterator = verifier.getTcbLevels().begin();
    std::advance(iterator, 0);
    EXPECT_EQ(expectedRevokedCpusvn, iterator->cpusvn);
    EXPECT_EQ(expectedRevokedPcesvn, iterator->pcesvn);
    EXPECT_EQ("Revoked", iterator->status);
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenTcbLevelsContainsNoTcbs)
{
    const std::string tcbLevels = "";
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, tcbLevels);

    TCBInfoJsonVerifier verifier{};
    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, verifier.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenTcbInfoFieldIsMissing)
{
    const std::string json = R"json({"signature": "ABBA3557"})json";

    EXPECT_EQ(STATUS_SGX_TCB_INFO_UNSUPPORTED_FORMAT, TCBInfoJsonVerifier().parse(json));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenJSONRootIsNotAnObject)
{
    const std::string tcbInfoTemplate = R"json([{
        "tcbInfo": {},
        "signature": "ABBA3557"}])json";
    const auto tcbInfoJson = generateTcbInfo(tcbInfoTemplate);

    EXPECT_EQ(STATUS_SGX_TCB_INFO_UNSUPPORTED_FORMAT, TCBInfoJsonVerifier().parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenTCBInfoIsNotAnObject)
{
    const std::string json = R"json({"tcbInfo": "text", "signature": "ABBA3557"})json";

    EXPECT_EQ(STATUS_SGX_TCB_INFO_UNSUPPORTED_FORMAT, TCBInfoJsonVerifier().parse(json));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenSignatureIsMissing)
{
    const std::string missingSignature = R"json("missing": "signature")json";
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, generateTcbLevel(), missingSignature);

    EXPECT_EQ(STATUS_SGX_TCB_INFO_UNSUPPORTED_FORMAT, TCBInfoJsonVerifier().parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenSignatureIsNotAString)
{
    const std::string invalidSignature = R"json("signature": 555)json";
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, generateTcbLevel(), invalidSignature);

    EXPECT_EQ(STATUS_SGX_TCB_INFO_UNSUPPORTED_FORMAT, TCBInfoJsonVerifier().parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenVersionIsMissing)
{
    const std::string tcbInfoWithoutVersion = R"json({
        "tcbInfo": {
            "issueDate": "2017-10-04T11:10:45Z",
            "nextUpdate": "2018-06-21T12:36:02Z",
            "fmspc": "0192837465AF",
            "pceId": "0000",
            "tcbLevels": [%s]
        },
        %s})json";
    const auto tcbInfoJson = generateTcbInfo(tcbInfoWithoutVersion);

    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier().parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenVersionIsNotAnInteger)
{
    const std::string tcbInfoInvalidVersion = R"json({
        "tcbInfo": {
            "version": "asd",
            "issueDate": "2017-10-04T11:10:45Z",
            "nextUpdate": "2018-06-21T12:36:02Z",
            "fmspc": "0192837465AF",
            "pceId": "0000",
            "tcbLevels": [%s]
        },
        %s})json";
    const auto tcbInfoJson = generateTcbInfo(tcbInfoInvalidVersion);

    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier().parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenIssueDateIsMissing)
{
    const std::string tcbInfoWithoutDate = R"json({
        "tcbInfo": {
            "version": 1,
            "nextUpdate": "2018-06-21T12:36:02Z",
            "fmspc": "0192837465AF",
            "pceId": "0000",
            "tcbLevels": [%s]
        },
        %s})json";
    const auto tcbInfoJson = generateTcbInfo(tcbInfoWithoutDate);

    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier().parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenIssueDateIsNotAString)
{
    const std::string tcbInfoInvalidDate = R"json({
        "tcbInfo": {
            "version": 1,
            "issueDate": true,
            "nextUpdate": "2018-06-21T12:36:02Z",
            "fmspc": "0192837465AF",
            "pceId": "0000",
            "tcbLevels": [%s]
        },
        %s})json";
    const auto tcbInfoJson = generateTcbInfo(tcbInfoInvalidDate);

    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier().parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenIssueDateIsNotInValidFormat)
{
    const std::string tcbInfoInvalidDate = R"json({
        "tcbInfo": {
            "version": 1,
            "issueDate": "20171004T111045Z",
            "nextUpdate": "2018-06-21T12:36:02Z",
            "fmspc": "0192837465AF",
            "pceId": "0000",
            "tcbLevels": [%s]
        },
        %s})json";
    const auto tcbInfoJson = generateTcbInfo(tcbInfoInvalidDate);

    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier().parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenIssueDateIsNotInUTC)
{
    const std::string tcbInfoInvalidDate = R"json({
        "tcbInfo": {
            "version": 1,
            "issueDate": "2017-10-04T11:10:45+01",
            "nextUpdate": "2018-06-21T12:36:02Z",
            "fmspc": "0192837465AF",
            "pceId": "0000",
            "tcbLevels": [%s]
        },
        %s})json";
    const auto tcbInfoJson = generateTcbInfo(tcbInfoInvalidDate);

    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier().parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenNextUpdateIsMissing)
{
    const std::string tcbInfoWithoutDate = R"json({
        "tcbInfo": {
            "version": 1,
            "issueDate": "2017-10-04T11:10:45Z",
            "fmspc": "0192837465AF",
            "pceId": "0000",
            "tcbLevels": [%s]
        },
        %s})json";
    const auto tcbInfoJson = generateTcbInfo(tcbInfoWithoutDate);

    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier().parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenNextUpdateIsNotAString)
{
    const std::string tcbInfoInvalidDate = R"json({
        "tcbInfo": {
            "version": 1,
            "issueDate": "2017-10-04T11:10:45Z",
            "nextUpdate": true,
            "fmspc": "0192837465AF",
            "pceId": "0000",
            "tcbLevels": [%s]
        },
        %s})json";
    const auto tcbInfoJson = generateTcbInfo(tcbInfoInvalidDate);

    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier().parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenNextUpdateIsNotInValidFormat)
{
    const std::string tcbInfoInvalidDate = R"json({
        "tcbInfo": {
            "version": 1,
            "issueDate": "2017-10-04T11:10:45Z",
            "nextUpdate": "20180621T123602Z",
            "fmspc": "0192837465AF",
            "pceId": "0000",
            "tcbLevels": [%s]
        },
        %s})json";
    const auto tcbInfoJson = generateTcbInfo(tcbInfoInvalidDate);

    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier().parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenNextUpdateIsNotInUTC)
{
    const std::string tcbInfoInvalidDate = R"json({
        "tcbInfo": {
            "version": 1,
            "issueDate": "2017-10-04T11:10:45Z",
            "nextUpdate": "2018-06-21T12:36:02+01",
            "fmspc": "0192837465AF",
            "pceId": "0000",
            "tcbLevels": [%s]
        },
        %s})json";
    const auto tcbInfoJson = generateTcbInfo(tcbInfoInvalidDate);

    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier().parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenFmspcIsMissing)
{
    const std::string tcbInfoTemplate = R"json({
        "tcbInfo": {
            "version": 1,
            "issueDate": "2017-10-04T11:10:45Z",
            "nextUpdate": "2018-06-21T12:36:02Z",
            "pceId": "0000",
            "tcbLevels": [%s]
        },
        %s})json";
    const auto tcbInfoJson = generateTcbInfo(tcbInfoTemplate);

    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenFmspcIsNotAString)
{
    const std::string tcbInfoTemplate = R"json({
        "tcbInfo": {
            "version": 1,
            "issueDate": "2017-10-04T11:10:45Z",
            "nextUpdate": "2018-06-21T12:36:02Z",
            "fmspc": 23,
            "pceId": "0000",
            "tcbLevels": [%s]
        },
        %s})json";
    const auto tcbInfoJson = generateTcbInfo(tcbInfoTemplate);

    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenFmspcIsTooLong)
{
    const std::string tcbInfoTemplate = R"json({
        "tcbInfo": {
            "version": 1,
            "issueDate": "2017-10-04T11:10:45Z",
            "nextUpdate": "2018-06-21T12:36:02Z",
            "fmspc": "0123456789ABC",
            "pceId": "0000",
            "tcbLevels": [%s]
        },
        %s})json";
    const auto tcbInfoJson = generateTcbInfo(tcbInfoTemplate);

    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenFmspcIsTooShort)
{
    const std::string tcbInfoTemplate = R"json({
        "tcbInfo": {
            "version": 1,
            "issueDate": "2017-10-04T11:10:45Z",
            "nextUpdate": "2018-06-21T12:36:02Z",
            "fmspc": "0123456789A",
            "pceId": "0000",
            "tcbLevels": [%s]
        },
        %s})json";
    const auto tcbInfoJson = generateTcbInfo(tcbInfoTemplate);

    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenFmspcIsNotAValidHexstring)
{
    const std::string tcbInfoTemplate = R"json({
        "tcbInfo": {
            "version": 1,
            "issueDate": "2017-10-04T11:10:45Z",
            "nextUpdate": "2018-06-21T12:36:02Z",
            "fmspc": "01invalid9AB",
            "pceId": "0000",
            "tcbLevels": [%s]
        },
        %s})json";
    const auto tcbInfoJson = generateTcbInfo(tcbInfoTemplate);

    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenPceIdIsMissing)
{
    const std::string tcbInfoTemplate = R"json({
        "tcbInfo": {
            "version": 1,
            "issueDate": "2017-10-04T11:10:45Z",
            "nextUpdate": "2018-06-21T12:36:02Z",
            "fmspc": "0192837465AF",
            "tcbLevels": [%s]
        },
        %s})json";
    const auto tcbInfoJson = generateTcbInfo(tcbInfoTemplate);

    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenPceIdIsNotAString)
{
    const std::string tcbInfoTemplate = R"json({
        "tcbInfo": {
            "version": 1,
            "issueDate": "2017-10-04T11:10:45Z",
            "nextUpdate": "2018-06-21T12:36:02Z",
            "fmspc": "0192837465AF",
            "pceId": 23,
            "tcbLevels": [%s]
        },
        %s})json";
    const auto tcbInfoJson = generateTcbInfo(tcbInfoTemplate);

    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenPceIdIsTooLong)
{
    const std::string tcbInfoTemplate = R"json({
        "tcbInfo": {
            "version": 1,
            "issueDate": "2017-10-04T11:10:45Z",
            "nextUpdate": "2018-06-21T12:36:02Z",
            "fmspc": "0192837465AF",
            "pceId": "00000",
            "tcbLevels": [%s]
        },
        %s})json";
    const auto tcbInfoJson = generateTcbInfo(tcbInfoTemplate);

    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenPceIdIsTooShort)
{
    const std::string tcbInfoTemplate = R"json({
        "tcbInfo": {
            "version": 1,
            "issueDate": "2017-10-04T11:10:45Z",
            "nextUpdate": "2018-06-21T12:36:02Z",
            "fmspc": "0192837465AF",
            "pceId": "000",
            "tcbLevels": [%s]
        },
        %s})json";
    const auto tcbInfoJson = generateTcbInfo(tcbInfoTemplate);

    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenPceIdIsNotAValidHexstring)
{
    const std::string tcbInfoTemplate = R"json({
        "tcbInfo": {
            "version": 1,
            "issueDate": "2017-10-04T11:10:45Z",
            "nextUpdate": "2018-06-21T12:36:02Z",
            "fmspc": "0192837465AF",
            "pceId": "xxxx",
            "tcbLevels": [%s]
        },
        %s})json";
    const auto tcbInfoJson = generateTcbInfo(tcbInfoTemplate);

    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenTcbLevelsArrayIsMissing)
{
    const std::string json = R"json({
        "tcbInfo": {
            "version": 1,
            "issueDate": "2017-10-04T11:10:45Z",
            "nextUpdate": "2018-06-21T12:36:02Z",
            "fmspc": "0192837465AF",
            "pceId": "0000"
        },
        "signature": "ABBA3557"})json";
    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(json));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenTcbLevelsIsNotAnArray)
{
    const std::string json = R"json({
        "tcbInfo": {
            "version": 1,
            "issueDate": "2017-10-04T11:10:45Z",
            "nextUpdate": "2018-06-21T12:36:02Z",
            "fmspc": "0192837465AF",
            "pceId": "0000",
            "tcbLevels": 0
        },
        "signature": "ABBA3557"})json";
    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(json));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenTcbLevelsArrayIsEmpty)
{
    const std::string tcbLevels = R"json()json";
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, tcbLevels);
    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenTcbLevelsArrayElementIsNotAnObject)
{
    const std::string tcbLevels = generateTcbLevel() + "," + generateTcbLevel(R"json("tcblevelString")json");
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, tcbLevels);
    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenTcbLevelsArrayElementIsEmpty)
{
    const std::string tcbLevels = generateTcbLevel() + "," + generateTcbLevel("{}");
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, tcbLevels);
    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenTcbLevelsArrayElementHasIncorrectNumberOfFields)
{
    const std::string tcbLevels = generateTcbLevel() + R"json(, {"status": "UpToDate"})json";
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, tcbLevels);
    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenTcbLevelsArrayElementIsMissingTcbField)
{
    const std::string tcbLevels = generateTcbLevel() + "," + generateTcbLevel(validTcbLevelTemplate, R"json("missing": "tcb")json");
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, tcbLevels);
    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenTcbLevelsArrayElementIsMissingStatusField)
{
    const std::string tcbLevels = generateTcbLevel() + "," + generateTcbLevel(validTcbLevelTemplate, validTcb, R"json("missing": "status")json");
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, tcbLevels);
    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenTcbLevelsArrayElementStatusIsNotAString)
{
    const std::string tcbLevels = generateTcbLevel() + "," + generateTcbLevel(validTcbLevelTemplate, validTcb, R"json("status": 78763124)json");
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, tcbLevels);
    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenTcbLevelsArrayElementTcbIsNotAnObject)
{
    const std::string tcbLevels = generateTcbLevel() + "," + generateTcbLevel(validTcbLevelTemplate, R"json("tcb": "qwerty")json");
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, tcbLevels);
    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenTcbLevelsArrayElementStatusIsNotAValidValue)
{
    const std::string tcbLevels = generateTcbLevel() + "," + generateTcbLevel(validTcbLevelTemplate, validTcb, R"json("status": "unknown value")json");
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, tcbLevels);
    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenTcbLevelsArrayElementTcbComponentsAreMissing)
{
    const std::string invalidTcb = R"json(
    "tcb": {
        "sgxtcbcomp01svn": 12,
        "sgxtcbcomp02svn": 34,
        "sgxtcbcomp03svn": 56,
        "sgxtcbcomp04svn": 78,
        "sgxtcbcomp08svn": 254,
        "sgxtcbcomp09svn": 9,
        "sgxtcbcomp10svn": 87,
        "sgxtcbcomp11svn": 65,
        "sgxtcbcomp12svn": 43,
        "sgxtcbcomp13svn": 21,
        "sgxtcbcomp14svn": 222,
        "sgxtcbcomp15svn": 184,
        "sgxtcbcomp16svn": 98,
        "pcesvn": 37240
    })json";
    const std::string tcbLevels = generateTcbLevel() + "," + generateTcbLevel(validTcbLevelTemplate, invalidTcb);
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, tcbLevels);
    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenTcbLevelsArrayElementTcbComponentIsNotAnInteger)
{
    const std::string invalidTcb = R"json(
    "tcb": {
        "sgxtcbcomp01svn": "12",
        "pcesvn": 37240
    })json";
    const std::string tcbLevels = generateTcbLevel() + "," + generateTcbLevel(validTcbLevelTemplate, invalidTcb);
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, tcbLevels);
    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenTcbLevelsArrayElementTcbComponentIsNegative)
{
    const std::string invalidTcb = R"json(
    "tcb": {
        "sgxtcbcomp01svn": -23,
        "pcesvn": 37240
    })json";
    const std::string tcbLevels = generateTcbLevel() + "," + generateTcbLevel(validTcbLevelTemplate, invalidTcb);
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, tcbLevels);
    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenTcbLevelsArrayElementTcbComponentPcesvnIsMissing)
{
    const std::string invalidTcb = R"json(
    "tcb": {
        "sgxtcbcomp01svn": 12,
        "sgxtcbcomp02svn": 34,
        "sgxtcbcomp03svn": 56,
        "sgxtcbcomp04svn": 78,
        "sgxtcbcomp05svn": 10,
        "sgxtcbcomp06svn": 0,
        "sgxtcbcomp07svn": 0,
        "sgxtcbcomp08svn": 254,
        "sgxtcbcomp09svn": 9,
        "sgxtcbcomp10svn": 87,
        "sgxtcbcomp11svn": 65,
        "sgxtcbcomp12svn": 43,
        "sgxtcbcomp13svn": 21,
        "sgxtcbcomp14svn": 222,
        "sgxtcbcomp15svn": 184,
        "sgxtcbcomp16svn": 98
    })json";
    const std::string tcbLevels = generateTcbLevel() + "," + generateTcbLevel(validTcbLevelTemplate, invalidTcb);
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, tcbLevels);
    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenTcbLevelsArrayElementTcbComponentPcesvnIsNegative)
{
    const std::string invalidTcb = R"json(
    "tcb": {
        "sgxtcbcomp01svn": 12,
        "sgxtcbcomp02svn": 34,
        "sgxtcbcomp03svn": 56,
        "sgxtcbcomp04svn": 78,
        "sgxtcbcomp05svn": 10,
        "sgxtcbcomp06svn": 0,
        "sgxtcbcomp07svn": 0,
        "sgxtcbcomp08svn": 254,
        "sgxtcbcomp09svn": 9,
        "sgxtcbcomp10svn": 87,
        "sgxtcbcomp11svn": 65,
        "sgxtcbcomp12svn": 43,
        "sgxtcbcomp13svn": 21,
        "sgxtcbcomp14svn": 222,
        "sgxtcbcomp15svn": 184,
        "sgxtcbcomp16svn": 98,
        "pcesvn": -4
    })json";
    const std::string tcbLevels = generateTcbLevel() + "," + generateTcbLevel(validTcbLevelTemplate, invalidTcb);
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, tcbLevels);
    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenTcbLevelsArrayElementTcbComponentPcesvnIsNotANumber)
{
    const std::string invalidTcb = R"json(
    "tcb": {
        "sgxtcbcomp01svn": 12,
        "sgxtcbcomp02svn": 34,
        "sgxtcbcomp03svn": 56,
        "sgxtcbcomp04svn": 78,
        "sgxtcbcomp05svn": 10,
        "sgxtcbcomp06svn": 0,
        "sgxtcbcomp07svn": 0,
        "sgxtcbcomp08svn": 254,
        "sgxtcbcomp09svn": 9,
        "sgxtcbcomp10svn": 87,
        "sgxtcbcomp11svn": 65,
        "sgxtcbcomp12svn": 43,
        "sgxtcbcomp13svn": 21,
        "sgxtcbcomp14svn": 222,
        "sgxtcbcomp15svn": 184,
        "sgxtcbcomp16svn": 98,
        "pcesvn": "78xy"
    })json";
    const std::string tcbLevels = generateTcbLevel() + "," + generateTcbLevel(validTcbLevelTemplate, invalidTcb);
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, tcbLevels);
    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenTcbLevelsArrayHasTwoIdenticalElements)
{
    const std::string tcbLevels = generateTcbLevel() + "," + generateTcbLevel();
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, tcbLevels);
    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenTcbLevelsArrayHasTwoElementsWithSameSvnsAndDifferentStatus)
{
    const std::string tcbLevels = generateTcbLevel() + "," + generateTcbLevel(validTcbLevelTemplate, validTcb, validRevokedStatus);
    const auto tcbInfoJson = generateTcbInfo(validTcbInfoTemplate, tcbLevels);
    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}

TEST_F(TCBInfoJsonVerifierTests, shouldFailWhenVersionIsNot1)
{
    const std::string invalidTcbInfoTemplate = R"json({
        "tcbInfo": {
            "version": 2,
            "issueDate": "2017-10-04T11:10:45Z",
            "nextUpdate": "2018-06-21T12:36:02Z",
            "fmspc": "0192837465AF",
            "pceId": "0000",
            "tcbLevels": [%s]
        },
        %s})json";
    auto tcbInfoJson = generateTcbInfo(invalidTcbInfoTemplate);

    EXPECT_EQ(STATUS_SGX_TCB_INFO_INVALID, TCBInfoJsonVerifier{}.parse(tcbInfoJson));
}
