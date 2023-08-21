/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
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

#include "TcbInfoGenerator.h"
#include "SgxEcdsaAttestation/AttestationParsers.h"
#include "X509Constants.h"
#include <Utils/TimeUtils.h>

#include <gtest/gtest.h>
#include "rapidjson/document.h"

using namespace testing;
using namespace intel::sgx::dcap;

struct TdxTcbInfoV3UT : public Test
{
};

TEST_F(TdxTcbInfoV3UT, shouldSuccessfullyParseTdxTcbInfoWhenAllDataIsProvided)
{
    auto tcbInfoJson = TcbInfoGenerator::generateTdxTcbInfo(
            validTdxTcbInfoV3Template,
            TcbInfoGenerator::generateTcbLevelV3(validTcbLevelV3Template, validTdxTcbV3),
            TcbInfoGenerator::generateTdxModuleIdentities());

    const auto tcbInfo = parser::json::TcbInfo::parse(tcbInfoJson);

    EXPECT_EQ(tcbInfo.getId(), parser::json::TcbInfo::TDX_ID);
    EXPECT_EQ(tcbInfo.getPceId(), DEFAULT_PCEID);
    EXPECT_EQ(tcbInfo.getFmspc(), DEFAULT_FMSPC);
    EXPECT_EQ(tcbInfo.getSignature(), DEFAULT_SIGNATURE);
    EXPECT_EQ(tcbInfo.getTcbType(), DEFAULT_TCB_TYPE);
    EXPECT_EQ(tcbInfo.getTcbEvaluationDataNumber(), DEFAULT_TCB_EVALUATION_DATA_NUMBER);
    EXPECT_EQ(tcbInfo.getIssueDate(), getEpochTimeFromString(DEFAULT_ISSUE_DATE));
    EXPECT_EQ(tcbInfo.getNextUpdate(), getEpochTimeFromString(DEFAULT_NEXT_UPDATE));
    EXPECT_EQ(tcbInfo.getVersion(), 3);

    EXPECT_EQ(1, tcbInfo.getTcbLevels().size());
    auto iterator = tcbInfo.getTcbLevels().begin();
    EXPECT_NE(iterator, tcbInfo.getTcbLevels().end());

    EXPECT_EQ(iterator->getSgxTcbComponents().size(), 16);
    auto cpusvn = iterator->getCpuSvn();
    EXPECT_EQ(cpusvn.size(), 16);
    for (uint32_t i=0; i < constants::CPUSVN_BYTE_LEN; i++)
    {
        EXPECT_EQ(iterator->getSgxTcbComponentSvn(i), DEFAULT_CPUSVN[i]);
        EXPECT_EQ(iterator->getSgxTcbComponent(i).getSvn(), DEFAULT_CPUSVN[i]);
        EXPECT_EQ(cpusvn[i], DEFAULT_CPUSVN[i]);
    }
    auto component = iterator->getSgxTcbComponent(0);
    EXPECT_EQ(component.getCategory(), "cat1");
    EXPECT_EQ(component.getType(), "type1");

    component = iterator->getSgxTcbComponent(5);
    EXPECT_EQ(component.getCategory(), "cat1");
    EXPECT_EQ(component.getType(), "type2");

    component = iterator->getSgxTcbComponent(6);
    EXPECT_EQ(component.getCategory(), "cat2");
    EXPECT_EQ(component.getType(), "type1");

    EXPECT_EQ(iterator->getTcbDate(), getEpochTimeFromString(DEFAULT_TCB_DATE));
    EXPECT_EQ(iterator->getPceSvn(), DEFAULT_PCESVN);
    EXPECT_EQ(iterator->getStatus(), "UpToDate");

    const auto& tdxModule = tcbInfo.getTdxModule();
    EXPECT_EQ(tdxModule.getMrSigner(), DEFAULT_TDXMODULE_MRSIGNER);
    EXPECT_EQ(tdxModule.getAttributes(), DEFAULT_TDXMODULE_ATTRIBUTES);
    EXPECT_EQ(tdxModule.getAttributesMask(), DEFAULT_TDXMODULE_ATTRIBUTESMASK);

    const auto& tdxModuleIdentities = tcbInfo.getTdxModuleIdentities();
    for (const auto& tdxIdentity : tdxModuleIdentities)
    {
        EXPECT_EQ(tdxIdentity.getId(), "TDX_O0");
        EXPECT_EQ(tdxIdentity.getMrSigner(), DEFAULT_TDXMODULE_MRSIGNER);
        EXPECT_EQ(tdxIdentity.getAttributes(), DEFAULT_TDXMODULE_ATTRIBUTES);
        EXPECT_EQ(tdxIdentity.getAttributesMask(), DEFAULT_TDXMODULE_ATTRIBUTESMASK);

        const auto& tdxIdentityTcbLevels = tdxIdentity.getTcbLevels();
        for (const auto& tdxIdentityTcbLevel : tdxIdentityTcbLevels)
        {
            const auto& tcb = tdxIdentityTcbLevel.getTcb();
            EXPECT_EQ(tcb.getIsvSvn(), 1);
            EXPECT_EQ(tdxIdentityTcbLevel.getTcbDate(), getEpochTimeFromString(DEFAULT_TCB_DATE));
            EXPECT_EQ(tdxIdentityTcbLevel.getStatus(), "UpToDate");

            const auto& advisoryIds = tdxIdentityTcbLevel.getAdvisoryIDs();
            EXPECT_EQ(advisoryIds.size(), 2);
            EXPECT_EQ(advisoryIds.at(0), "INTEL-SA-00079");
            EXPECT_EQ(advisoryIds.at(1), "INTEL-SA-00076");
        }
    }

    iterator = tcbInfo.getTcbLevels().begin();
    EXPECT_NE(iterator, tcbInfo.getTcbLevels().end());

    EXPECT_EQ(iterator->getTdxTcbComponents().size(), 16);

    for (uint32_t i=0; i < constants::CPUSVN_BYTE_LEN; i++)
    {
        EXPECT_EQ(iterator->getTdxTcbComponent(i).getSvn(), DEFAULT_CPUSVN[i]);
    }
    component = iterator->getTdxTcbComponent(0);
    EXPECT_EQ(component.getCategory(), "cat1");
    EXPECT_EQ(component.getType(), "type1");

    component = iterator->getTdxTcbComponent(5);
    EXPECT_EQ(component.getCategory(), "cat1");
    EXPECT_EQ(component.getType(), "type2");

    component = iterator->getTdxTcbComponent(6);
    EXPECT_EQ(component.getCategory(), "cat2");
    EXPECT_EQ(component.getType(), "type1");
}

TEST_F(TdxTcbInfoV3UT, shouldSuccessfullyParseTdxTcbInfoWhenOptionalDataIsMissing)
{
    auto tcbInfoJson = TcbInfoGenerator::generateTdxTcbInfo(validTdxTcbInfoV3Template, TcbInfoGenerator::generateTcbLevelV3(validTcbLevelV3Template, validTdxTcbV3),
                                                            "");

    const auto tcbInfo = parser::json::TcbInfo::parse(tcbInfoJson);

    EXPECT_EQ(tcbInfo.getId(), parser::json::TcbInfo::TDX_ID);
    EXPECT_EQ(tcbInfo.getPceId(), DEFAULT_PCEID);
    EXPECT_EQ(tcbInfo.getFmspc(), DEFAULT_FMSPC);
    EXPECT_EQ(tcbInfo.getSignature(), DEFAULT_SIGNATURE);
    EXPECT_EQ(tcbInfo.getTcbType(), DEFAULT_TCB_TYPE);
    EXPECT_EQ(tcbInfo.getTcbEvaluationDataNumber(), DEFAULT_TCB_EVALUATION_DATA_NUMBER);
    EXPECT_EQ(tcbInfo.getIssueDate(), getEpochTimeFromString(DEFAULT_ISSUE_DATE));
    EXPECT_EQ(tcbInfo.getNextUpdate(), getEpochTimeFromString(DEFAULT_NEXT_UPDATE));
    EXPECT_EQ(tcbInfo.getVersion(), 3);

    EXPECT_EQ(1, tcbInfo.getTcbLevels().size());
    auto iterator = tcbInfo.getTcbLevels().begin();
    EXPECT_NE(iterator, tcbInfo.getTcbLevels().end());

    EXPECT_EQ(iterator->getSgxTcbComponents().size(), 16);
    auto cpusvn = iterator->getCpuSvn();
    EXPECT_EQ(cpusvn.size(), 16);
    for (uint32_t i=0; i < constants::CPUSVN_BYTE_LEN; i++)
    {
        EXPECT_EQ(iterator->getSgxTcbComponentSvn(i), DEFAULT_CPUSVN[i]);
        EXPECT_EQ(iterator->getSgxTcbComponent(i).getSvn(), DEFAULT_CPUSVN[i]);
        EXPECT_EQ(cpusvn[i], DEFAULT_CPUSVN[i]);
    }
    auto component = iterator->getSgxTcbComponent(0);
    EXPECT_EQ(component.getCategory(), "cat1");
    EXPECT_EQ(component.getType(), "type1");

    component = iterator->getSgxTcbComponent(5);
    EXPECT_EQ(component.getCategory(), "cat1");
    EXPECT_EQ(component.getType(), "type2");

    component = iterator->getSgxTcbComponent(6);
    EXPECT_EQ(component.getCategory(), "cat2");
    EXPECT_EQ(component.getType(), "type1");

    EXPECT_EQ(iterator->getTcbDate(), getEpochTimeFromString(DEFAULT_TCB_DATE));
    EXPECT_EQ(iterator->getPceSvn(), DEFAULT_PCESVN);
    EXPECT_EQ(iterator->getStatus(), "UpToDate");

    const auto& tdxModule = tcbInfo.getTdxModule();
    EXPECT_EQ(tdxModule.getMrSigner(), DEFAULT_TDXMODULE_MRSIGNER);
    EXPECT_EQ(tdxModule.getAttributes(), DEFAULT_TDXMODULE_ATTRIBUTES);
    EXPECT_EQ(tdxModule.getAttributesMask(), DEFAULT_TDXMODULE_ATTRIBUTESMASK);

    iterator = tcbInfo.getTcbLevels().begin();
    EXPECT_NE(iterator, tcbInfo.getTcbLevels().end());

    EXPECT_EQ(iterator->getTdxTcbComponents().size(), 16);

    for (uint32_t i=0; i < constants::CPUSVN_BYTE_LEN; i++)
    {
        EXPECT_EQ(iterator->getTdxTcbComponent(i).getSvn(), DEFAULT_CPUSVN[i]);
    }
    component = iterator->getTdxTcbComponent(0);
    EXPECT_EQ(component.getCategory(), "cat1");
    EXPECT_EQ(component.getType(), "type1");

    component = iterator->getTdxTcbComponent(5);
    EXPECT_EQ(component.getCategory(), "cat1");
    EXPECT_EQ(component.getType(), "type2");

    component = iterator->getTdxTcbComponent(6);
    EXPECT_EQ(component.getCategory(), "cat2");
    EXPECT_EQ(component.getType(), "type1");
}

TEST_F(TdxTcbInfoV3UT, shouldFailWhenTdxTcbComponentsIsNotArray)
{
    const std::string tcbJsonTemplate = R"json(
    "tcb": {
        "sgxtcbcomponents": [
            {"svn": 12, "category": "cat1", "type": "type1"},
            {"svn": 23 },
            {"svn": 34 },
            {"svn": 45 },
            {"svn": 100 },
            {"svn": 0, "category": "cat1", "type": "type2"},
            {"svn": 1, "category": "cat2", "type": "type1"},
            {"svn": 156 },
            {"svn": 208 },
            {"svn": 255 },
            {"svn": 2 },
            {"svn": 3 },
            {"svn": 4 },
            {"svn": 5, "category": "cat2", "type": "type2"},
            {"svn": 6, "category": "cat1", "type": "type3"},
            {"svn": 7 }
        ],
        "tdxtcbcomponents": "test",
        "pcesvn": 30865
    })json";

    auto tcbInfoJson = TcbInfoGenerator::generateTdxTcbInfo(validTdxTcbInfoV3Template, TcbInfoGenerator::generateTcbLevelV3(validTcbLevelV3Template, tcbJsonTemplate));

    try
    {
        const auto tcbInfo = parser::json::TcbInfo::parse(tcbInfoJson);
        FAIL() << "Parser should throw";
    }
    catch(const parser::FormatException &err)
    {
        EXPECT_EQ(std::string(err.what()), "TCB level JSON's [tdxtcbcomponents] field should be an array");
    }
}

TEST_F(TdxTcbInfoV3UT, shouldFailWhenTcbComponentCategoryIsNotString)
{
    const std::string tcbJsonTemplate = R"json(
    "tcb": {
        "sgxtcbcomponents": [
            {"svn": 12, "category": 5, "type": "type1"},
            {"svn": 23 },
            {"svn": 34 },
            {"svn": 45 },
            {"svn": 100 },
            {"svn": 0, "category": "cat1", "type": "type2"},
            {"svn": 1, "category": "cat2", "type": "type1"},
            {"svn": 156 },
            {"svn": 208 },
            {"svn": 255 },
            {"svn": 2 },
            {"svn": 3 },
            {"svn": 4 },
            {"svn": 5 },
            {"svn": 6 },
            {"svn": 7 }
        ],
        "pcesvn": 30865
    })json";

    auto tcbInfoJson = TcbInfoGenerator::generateTdxTcbInfo(validTdxTcbInfoV3Template, TcbInfoGenerator::generateTcbLevelV3(validTcbLevelV3Template, tcbJsonTemplate));
    try
    {
        const auto tcbInfo = parser::json::TcbInfo::parse(tcbInfoJson);
        FAIL() << "Parser should throw";
    }
    catch(const parser::FormatException &err)
    {
        EXPECT_EQ(std::string(err.what()), "TCB Component JSON's [category] field should be string");
    }
}

TEST_F(TdxTcbInfoV3UT, shouldFailWhenTcbComponentTypeIsNotString)
{
    const std::string tcbJsonTemplate = R"json(
    "tcb": {
        "sgxtcbcomponents": [
            {"svn": 12, "category": "test", "type": 4},
            {"svn": 23 },
            {"svn": 34 },
            {"svn": 45 },
            {"svn": 100 },
            {"svn": 0, "category": "cat1", "type": "type2"},
            {"svn": 1, "category": "cat2", "type": "type1"},
            {"svn": 156 },
            {"svn": 208 },
            {"svn": 255 },
            {"svn": 2 },
            {"svn": 3 },
            {"svn": 4 },
            {"svn": 5 },
            {"svn": 6 },
            {"svn": 7 }
        ],
        "pcesvn": 30865
    })json";

    auto tcbInfoJson = TcbInfoGenerator::generateTdxTcbInfo(validTdxTcbInfoV3Template, TcbInfoGenerator::generateTcbLevelV3(validTcbLevelV3Template, tcbJsonTemplate));
    try
    {
        const auto tcbInfo = parser::json::TcbInfo::parse(tcbInfoJson);
        FAIL() << "Parser should throw";
    }
    catch(const parser::FormatException &err)
    {
        EXPECT_EQ(std::string(err.what()), "TCB Component JSON's [type] field should be string");
    }
}

TEST_F(TdxTcbInfoV3UT, shouldFailWhenTcbComponentSvnIsNotInteger)
{
    const std::string tcbJsonTemplate = R"json(
    "tcb": {
        "sgxtcbcomponents": [
            {"svn": "test", "category": "test", "type": "test"},
            {"svn": 23 },
            {"svn": 34 },
            {"svn": 45 },
            {"svn": 100 },
            {"svn": 0, "category": "cat1", "type": "type2"},
            {"svn": 1, "category": "cat2", "type": "type1"},
            {"svn": 156 },
            {"svn": 208 },
            {"svn": 255 },
            {"svn": 2 },
            {"svn": 3 },
            {"svn": 4 },
            {"svn": 5 },
            {"svn": 6 },
            {"svn": 7 }
        ],
        "pcesvn": 30865
    })json";

    auto tcbInfoJson = TcbInfoGenerator::generateTdxTcbInfo(validTdxTcbInfoV3Template, TcbInfoGenerator::generateTcbLevelV3(validTcbLevelV3Template, tcbJsonTemplate));
    try
    {
        const auto tcbInfo = parser::json::TcbInfo::parse(tcbInfoJson);
        FAIL() << "Parser should throw";
    }
    catch(const parser::FormatException &err)
    {
        EXPECT_EQ(std::string(err.what()), "TCB Component JSON should has [svn] field and it should be unsigned integer");
    }
}

TEST_F(TdxTcbInfoV3UT, shouldFailWhenTcbComponentDoesntHaveSvnField)
{
    const std::string tcbJsonTemplate = R"json(
    "tcb": {
        "sgxtcbcomponents": [
            {"svn": 5, "category": "test", "type": "test"},
            {"svn": 23 },
            {"svn": 34 },
            {"svn": 45 },
            {"svn": 100 },
            {"category": "cat1", "type": "type2"},
            {"svn": 1, "category": "cat2", "type": "type1"},
            {"svn": 156 },
            {"svn": 208 },
            {"svn": 255 },
            {"svn": 2 },
            {"svn": 3 },
            {"svn": 4 },
            {"svn": 5 },
            {"svn": 6 },
            {"svn": 7 }
        ],
        "pcesvn": 30865
    })json";

    auto tcbInfoJson = TcbInfoGenerator::generateTdxTcbInfo(validTdxTcbInfoV3Template, TcbInfoGenerator::generateTcbLevelV3(validTcbLevelV3Template, tcbJsonTemplate));
    try
    {
        const auto tcbInfo = parser::json::TcbInfo::parse(tcbInfoJson);
        FAIL() << "Parser should throw";
    }
    catch(const parser::FormatException &err)
    {
        EXPECT_EQ(std::string(err.what()), "TCB Component JSON should has [svn] field and it should be unsigned integer");
    }
}


TEST_F(TdxTcbInfoV3UT, shouldFailWhenTdxTcbInfoDoesntHaveTdxTcbComponents)
{
    auto tcbInfoJson = TcbInfoGenerator::generateTdxTcbInfo(validTdxTcbInfoV3Template, TcbInfoGenerator::generateTcbLevelV3(validTcbLevelV3Template, validSgxTcbV3));

    try
    {
        const auto tcbInfo = parser::json::TcbInfo::parse(tcbInfoJson);
        FAIL() << "Parser should throw";
    }
    catch(const parser::FormatException &err)
    {
        EXPECT_EQ(std::string(err.what()), "TCB level JSON for TDX should have [tdxtcbcomponents] field");
    }
}

TEST_F(TdxTcbInfoV3UT, shouldFailWhenTdxTcbInfoDoesntHaveSgxTcbComponents)
{
    const std::string tcbJsonTemplate = R"json(
    "tcb": {
        "tdxtcbcomponents": [
            {"svn": 12, "category": "cat1", "type": "type1"},
            {"svn": 23 },
            {"svn": 34 },
            {"svn": 45 },
            {"svn": 100 },
            {"svn": 0, "category": "cat1", "type": "type2"},
            {"svn": 1, "category": "cat2", "type": "type1"},
            {"svn": 156 },
            {"svn": 208 },
            {"svn": 255 },
            {"svn": 2 },
            {"svn": 3 },
            {"svn": 4 },
            {"svn": 5, "category": "cat2", "type": "type2"},
            {"svn": 6, "category": "cat1", "type": "type3"},
            {"svn": 7 }
        ],
        "pcesvn": 30865
    })json";

    auto tcbInfoJson = TcbInfoGenerator::generateTdxTcbInfo(validTdxTcbInfoV3Template, TcbInfoGenerator::generateTcbLevelV3(validTcbLevelV3Template, tcbJsonTemplate));

    try
    {
        const auto tcbInfo = parser::json::TcbInfo::parse(tcbInfoJson);
        FAIL() << "Parser should throw";
    }
    catch(const parser::FormatException &err)
    {
        EXPECT_EQ(std::string(err.what()), "TCB level JSON should have [sgxtcbcomponents] field");
    }
}

TEST_F(TdxTcbInfoV3UT, shouldFailWhenTdxTcbInfoHaveWrongNumberOfSgxTcbComponents)
{
    const std::string tcbJsonTemplate = R"json(
    "tcb": {
        "sgxtcbcomponents": [
            {"svn": 12, "category": "cat1", "type": "type1"},
            {"svn": 23 },
            {"svn": 34 },
            {"svn": 45 },
            {"svn": 100 },
            {"svn": 0, "category": "cat1", "type": "type2"},
            {"svn": 1, "category": "cat2", "type": "type1"},
            {"svn": 156 },
            {"svn": 208 },
            {"svn": 255 },
            {"svn": 2 },
            {"svn": 3 },
            {"svn": 4 },
            {"svn": 5, "category": "cat2", "type": "type2"},
            {"svn": 6, "category": "cat1", "type": "type3"}
        ],
        "tdxtcbcomponents": [
            {"svn": 12, "category": "cat1", "type": "type1"},
            {"svn": 23 },
            {"svn": 34 },
            {"svn": 45 },
            {"svn": 100 },
            {"svn": 0, "category": "cat1", "type": "type2"},
            {"svn": 1, "category": "cat2", "type": "type1"},
            {"svn": 156 },
            {"svn": 208 },
            {"svn": 255 },
            {"svn": 2 },
            {"svn": 3 },
            {"svn": 4 },
            {"svn": 5, "category": "cat2", "type": "type2"},
            {"svn": 6, "category": "cat1", "type": "type3"},
            {"svn": 7 }
        ],
        "pcesvn": 30865
    })json";

    auto tcbInfoJson = TcbInfoGenerator::generateTdxTcbInfo(validTdxTcbInfoV3Template, TcbInfoGenerator::generateTcbLevelV3(validTcbLevelV3Template, tcbJsonTemplate));

    try
    {
        const auto tcbInfo = parser::json::TcbInfo::parse(tcbInfoJson);
        FAIL() << "Parser should throw";
    }
    catch(const parser::FormatException &err)
    {
        EXPECT_EQ(std::string(err.what()), "TCB level [sgxtcbcomponents] array should have 16 entries");
    }
}

TEST_F(TdxTcbInfoV3UT, shouldFailWhenTdxTcbInfoHaveWrongNumberOfTdxTcbComponents)
{
    const std::string tcbJsonTemplate = R"json(
    "tcb": {
        "sgxtcbcomponents": [
            {"svn": 12, "category": "cat1", "type": "type1"},
            {"svn": 23 },
            {"svn": 34 },
            {"svn": 45 },
            {"svn": 100 },
            {"svn": 0, "category": "cat1", "type": "type2"},
            {"svn": 1, "category": "cat2", "type": "type1"},
            {"svn": 156 },
            {"svn": 208 },
            {"svn": 255 },
            {"svn": 2 },
            {"svn": 3 },
            {"svn": 4 },
            {"svn": 5, "category": "cat2", "type": "type2"},
            {"svn": 6, "category": "cat1", "type": "type3"},
            {"svn": 7 }
        ],
        "tdxtcbcomponents": [
            {"svn": 23 },
            {"svn": 34 },
            {"svn": 45 },
            {"svn": 100 },
            {"svn": 0, "category": "cat1", "type": "type2"},
            {"svn": 1, "category": "cat2", "type": "type1"},
            {"svn": 156 },
            {"svn": 208 },
            {"svn": 255 },
            {"svn": 2 },
            {"svn": 3 },
            {"svn": 4 },
            {"svn": 5, "category": "cat2", "type": "type2"},
            {"svn": 6, "category": "cat1", "type": "type3"},
            {"svn": 7 }
        ],
        "pcesvn": 30865
    })json";

    auto tcbInfoJson = TcbInfoGenerator::generateTdxTcbInfo(validTdxTcbInfoV3Template, TcbInfoGenerator::generateTcbLevelV3(validTcbLevelV3Template, tcbJsonTemplate));

    try
    {
        const auto tcbInfo = parser::json::TcbInfo::parse(tcbInfoJson);
        FAIL() << "Parser should throw";
    }
    catch(const parser::FormatException &err)
    {
        EXPECT_EQ(std::string(err.what()), "TCB level [tdxtcbcomponents] array should have 16 entries");
    }
}

TEST_F(TdxTcbInfoV3UT, shouldFailWhenTdxTcbInfoHasInvalidTdxModuleTcb)
{
    std::string json = R"json(
        {
            "tcb": { "isvsvn": "1" },
            "tcbDate": "2021-08-06T13:55:15Z",
            "tcbStatus": "UpToDate",
            "advisoryIDs": [
                "INTEL-SA-00079",
                "INTEL-SA-00076"
            ]
        }
    )json";
    auto tcbInfoJson = TcbInfoGenerator::generateTdxTcbInfo(
            validTdxTcbInfoV3Template,
            TcbInfoGenerator::generateTcbLevelV3(validTcbLevelV3Template, validTdxTcbV3),
            TcbInfoGenerator::generateTdxModuleIdentities(validTdxModuleIdentitiesTemplate, json));

    try {
        parser::json::TcbInfo::parse(tcbInfoJson);
        FAIL() << "Parser should throw";
    }
    catch(const parser::FormatException &err)
    {
        EXPECT_EQ(std::string(err.what()), "TDX Module TCB JSON's [isvsvn] field should be an unsigned integer");
    }
}

TEST_F(TdxTcbInfoV3UT, shouldFailWhenTdxTcbInfoHasTooLowTdxModuleTcb)
{
    std::string json = R"json(
        {
            "tcb": { "isvsvn": -1 },
            "tcbDate": "2021-08-06T13:55:15Z",
            "tcbStatus": "UpToDate",
            "advisoryIDs": [
                "INTEL-SA-00079",
                "INTEL-SA-00076"
            ]
        }
    )json";
    auto tcbInfoJson = TcbInfoGenerator::generateTdxTcbInfo(
            validTdxTcbInfoV3Template,
            TcbInfoGenerator::generateTcbLevelV3(validTcbLevelV3Template, validTdxTcbV3),
            TcbInfoGenerator::generateTdxModuleIdentities(validTdxModuleIdentitiesTemplate, json));

    try {
        parser::json::TcbInfo::parse(tcbInfoJson);
        FAIL() << "Parser should throw";
    }
    catch(const parser::FormatException &err)
    {
        EXPECT_EQ(std::string(err.what()), "TDX Module TCB JSON's [isvsvn] field value should be within 0 and 65535");
    }
}

TEST_F(TdxTcbInfoV3UT, shouldFailWhenTdxTcbInfoHasInvalidTdxModuleTcbLevelDate)
{
    std::string json = R"json(
        {
            "tcb": { "isvsvn": 1 },
            "tcbDate": "Monday",
            "tcbStatus": "UpToDate",
            "advisoryIDs": [
                "INTEL-SA-00079",
                "INTEL-SA-00076"
            ]
        }
    )json";
    auto tcbInfoJson = TcbInfoGenerator::generateTdxTcbInfo(
            validTdxTcbInfoV3Template,
            TcbInfoGenerator::generateTcbLevelV3(validTcbLevelV3Template, validTdxTcbV3),
            TcbInfoGenerator::generateTdxModuleIdentities(validTdxModuleIdentitiesTemplate, json));

    try {
        parser::json::TcbInfo::parse(tcbInfoJson);
        FAIL() << "Parser should throw";
    }
    catch(const parser::FormatException &err)
    {
        EXPECT_EQ(std::string(err.what()), "TDX Module TCB Level JSON's [tcbDate] field should be a string compliant to ISO 8601");
    }
}

TEST_F(TdxTcbInfoV3UT, shouldFailWhenTdxTcbInfoHaveEmptyTdxTcbComponents)
{
    const std::string tcbJsonTemplate = R"json(
    "tcb": {
        "sgxtcbcomponents": [
            {"svn": 23 },
            {"svn": 23 },
            {"svn": 34 },
            {"svn": 45 },
            {"svn": 100 },
            {"svn": 0, "category": "cat1", "type": "type2"},
            {"svn": 1, "category": "cat2", "type": "type1"},
            {"svn": 156 },
            {"svn": 208 },
            {"svn": 255 },
            {"svn": 2 },
            {"svn": 3 },
            {"svn": 4 },
            {"svn": 5, "category": "cat2", "type": "type2"},
            {"svn": 6, "category": "cat1", "type": "type3"},
            {"svn": 7 }
        ],
        "tdxtcbcomponents": [
        ],
        "pcesvn": 30865
    })json";

    auto tcbInfoJson = TcbInfoGenerator::generateTdxTcbInfo(validTdxTcbInfoV3Template, TcbInfoGenerator::generateTcbLevelV3(validTcbLevelV3Template, tcbJsonTemplate));

    try
    {
        const auto tcbInfo = parser::json::TcbInfo::parse(tcbInfoJson);
        FAIL() << "Parser should throw";
    }
    catch(const parser::FormatException &err)
    {
        EXPECT_EQ(std::string(err.what()), "TCB level [tdxtcbcomponents] array should have 16 entries");
    }
}

TEST_F(TdxTcbInfoV3UT, shouldFailWhenTdxTcbInfoHasInvalidTdxModuleTcbLevelStatus)
{
    std::string json = R"json(
        {
            "tcb": { "isvsvn": 1 },
            "tcbDate": "2021-08-06T13:55:15Z",
            "tcbStatus": 0,
            "advisoryIDs": [
                "INTEL-SA-00079",
                "INTEL-SA-00076"
            ]
        }
    )json";
    auto tcbInfoJson = TcbInfoGenerator::generateTdxTcbInfo(
            validTdxTcbInfoV3Template,
            TcbInfoGenerator::generateTcbLevelV3(validTcbLevelV3Template, validTdxTcbV3),
            TcbInfoGenerator::generateTdxModuleIdentities(validTdxModuleIdentitiesTemplate, json));

    try {
        parser::json::TcbInfo::parse(tcbInfoJson);
        FAIL() << "Parser should throw";
    }
    catch(const parser::FormatException &err)
    {
        EXPECT_EQ(std::string(err.what()), "TDX Module TCB Level JSON's [tcbStatus] field should be a string");
    }
}

TEST_F(TdxTcbInfoV3UT, shouldFailWhenTdxTcbInfoHasInvalidTdxModuleAdvisoryIDsFieldIsMissing)
{
    std::string json = R"json(
        {
            "tcbDate": "2021-08-06T13:55:15Z",
            "tcbStatus": "UpToDate",
            "advisoryIDs": ""
        }
    )json";
    auto tcbInfoJson = TcbInfoGenerator::generateTdxTcbInfo(
            validTdxTcbInfoV3Template,
            TcbInfoGenerator::generateTcbLevelV3(validTcbLevelV3Template, validTdxTcbV3),
            TcbInfoGenerator::generateTdxModuleIdentities(validTdxModuleIdentitiesTemplate, json));

    try {
        parser::json::TcbInfo::parse(tcbInfoJson);
        FAIL() << "Parser should throw";
    }
    catch(const parser::FormatException &err)
    {
        EXPECT_EQ(std::string(err.what()), "TDX Module TCB level JSON should have [tcb] field");
    }
}

TEST_F(TdxTcbInfoV3UT, shouldFailWhenTdxTcbInfoHasInvalidTdxModuleAdvisoryIDsFieldIsNotArray)
{
    std::string json = R"json(
        {
            "tcb": { "isvsvn": 1 },
            "tcbDate": "2021-08-06T13:55:15Z",
            "tcbStatus": "UpToDate",
            "advisoryIDs": ""
        }
    )json";
    auto tcbInfoJson = TcbInfoGenerator::generateTdxTcbInfo(
            validTdxTcbInfoV3Template,
            TcbInfoGenerator::generateTcbLevelV3(validTcbLevelV3Template, validTdxTcbV3),
            TcbInfoGenerator::generateTdxModuleIdentities(validTdxModuleIdentitiesTemplate, json));

    try {
        parser::json::TcbInfo::parse(tcbInfoJson);
        FAIL() << "Parser should throw";
    }
    catch(const parser::FormatException &err)
    {
        EXPECT_EQ(std::string(err.what()), "TDX Module TCB Level JSON's [advisoryIDs] field should be a string array");
    }
}

TEST_F(TdxTcbInfoV3UT, shouldFailWhenTdxTcbInfoHasInvalidId)
{
    std::string jsonTemplate = R"(
        "tdxModuleIdentities": [
            {
                "id": 1,
                "mrsigner": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F",
                "attributes": "0000000000000000",
                "attributesMask": "FFFFFFFFFFFFFFFF",
                "tcbLevels": [%s]
            }
        ],
    )";
    auto tcbInfoJson = TcbInfoGenerator::generateTdxTcbInfo(
            validTdxTcbInfoV3Template,
            TcbInfoGenerator::generateTcbLevelV3(validTcbLevelV3Template, validTdxTcbV3),
            TcbInfoGenerator::generateTdxModuleIdentities(jsonTemplate,
                                                          TcbInfoGenerator::generateTdxModuleTcbLevel()));

    try {
        parser::json::TcbInfo::parse(tcbInfoJson);
        FAIL() << "Parser should throw";
    }
    catch(const parser::FormatException &err)
    {
        EXPECT_EQ(std::string(err.what()), "TDX Module Identity JSON's [id] field should be a string");
    }
}

TEST_F(TdxTcbInfoV3UT, shouldFailWhenTdxTcbInfoHasInvalidMrsigner)
{
    std::string jsonTemplate = R"(
        "tdxModuleIdentities": [
            {
                "id": "1",
                "mrsigner": "invalid",
                "attributes": "0000000000000000",
                "attributesMask": "FFFFFFFFFFFFFFFF",
                "tcbLevels": [%s]
            }
        ],
    )";
    auto tcbInfoJson = TcbInfoGenerator::generateTdxTcbInfo(
            validTdxTcbInfoV3Template,
            TcbInfoGenerator::generateTcbLevelV3(validTcbLevelV3Template, validTdxTcbV3),
            TcbInfoGenerator::generateTdxModuleIdentities(jsonTemplate,
                                                          TcbInfoGenerator::generateTdxModuleTcbLevel()));

    try {
        parser::json::TcbInfo::parse(tcbInfoJson);
        FAIL() << "Parser should throw";
    }
    catch(const parser::FormatException &err)
    {
        EXPECT_EQ(std::string(err.what()), "TDX Module Identity JSON's [mrsigner] field should be a hex encoded string");
    }
}

TEST_F(TdxTcbInfoV3UT, shouldFailWhenTdxTcbInfoHasInvalidAttributes)
{
    std::string jsonTemplate = R"(
        "tdxModuleIdentities": [
            {
                "id": "1",
                "mrsigner": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F",
                "attributes": "invalid",
                "attributesMask": "FFFFFFFFFFFFFFFF",
                "tcbLevels": [%s]
            }
        ],
    )";
    auto tcbInfoJson = TcbInfoGenerator::generateTdxTcbInfo(
            validTdxTcbInfoV3Template,
            TcbInfoGenerator::generateTcbLevelV3(validTcbLevelV3Template, validTdxTcbV3),
            TcbInfoGenerator::generateTdxModuleIdentities(jsonTemplate,
                                                          TcbInfoGenerator::generateTdxModuleTcbLevel()));

    try {
        parser::json::TcbInfo::parse(tcbInfoJson);
        FAIL() << "Parser should throw";
    }
    catch(const parser::FormatException &err)
    {
        EXPECT_EQ(std::string(err.what()), "TDX Module Identity JSON's [attributes] field should be a hex encoded string");
    }
}

TEST_F(TdxTcbInfoV3UT, shouldFailWhenTdxTcbInfoHasInvalidAttributesMask)
{
    std::string jsonTemplate = R"(
        "tdxModuleIdentities": [
            {
                "id": "1",
                "mrsigner": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F",
                "attributes": "0000000000000000",
                "attributesMask": "invalid",
                "tcbLevels": [%s]
            }
        ],
    )";
    auto tcbInfoJson = TcbInfoGenerator::generateTdxTcbInfo(
            validTdxTcbInfoV3Template,
            TcbInfoGenerator::generateTcbLevelV3(validTcbLevelV3Template, validTdxTcbV3),
            TcbInfoGenerator::generateTdxModuleIdentities(jsonTemplate,
                                                          TcbInfoGenerator::generateTdxModuleTcbLevel()));

    try {
        parser::json::TcbInfo::parse(tcbInfoJson);
        FAIL() << "Parser should throw";
    }
    catch(const parser::FormatException &err)
    {
        EXPECT_EQ(std::string(err.what()), "TDX Module Identity JSON's [attributesMask] field should be a hex encoded string");
    }
}

TEST_F(TdxTcbInfoV3UT, shouldFailWhenTdxTcbInfoHasInvalidTdxModuleIdentitiesTcbLevels)
{
    std::string jsonTemplate = R"(
        "tdxModuleIdentities": [
            {
                "id": "1",
                "mrsigner": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F",
                "attributes": "0000000000000000",
                "attributesMask": "FFFFFFFFFFFFFFFF",
                "tcbLevels": "invalid"
            }
        ],
    )";
    auto tcbInfoJson = TcbInfoGenerator::generateTdxTcbInfo(
            validTdxTcbInfoV3Template,
            TcbInfoGenerator::generateTcbLevelV3(validTcbLevelV3Template, validTdxTcbV3),
            jsonTemplate);

    try {
        parser::json::TcbInfo::parse(tcbInfoJson);
        FAIL() << "Parser should throw";
    }
    catch(const parser::FormatException &err)
    {
        EXPECT_EQ(std::string(err.what()), "[tcbLevels] field of TDX Module Identity JSON should be a nonempty array");
    }
}

TEST_F(TdxTcbInfoV3UT, shouldFailWhenTdxTcbInfoHasEmptyTdxModuleIdentitiesTcbLevels)
{
    std::string jsonTemplate = R"(
        "tdxModuleIdentities": [
            {
                "id": "1",
                "mrsigner": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F",
                "attributes": "0000000000000000",
                "attributesMask": "FFFFFFFFFFFFFFFF",
                "tcbLevels": []
            }
        ],
    )";
    auto tcbInfoJson = TcbInfoGenerator::generateTdxTcbInfo(
            validTdxTcbInfoV3Template,
            TcbInfoGenerator::generateTcbLevelV3(validTcbLevelV3Template, validTdxTcbV3),
            jsonTemplate);

    try {
        parser::json::TcbInfo::parse(tcbInfoJson);
        FAIL() << "Parser should throw";
    }
    catch(const parser::FormatException &err)
    {
        EXPECT_EQ(std::string(err.what()), "Number of parsed [tcbLevels] should not be 0");
    }
}
