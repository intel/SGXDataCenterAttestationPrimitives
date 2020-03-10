/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
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

#include <cstring>

const std::string validTcb = R"json(
    "tcb": {
        "sgxtcbcomp01svn": 12,
        "sgxtcbcomp02svn": 23,
        "sgxtcbcomp03svn": 34,
        "sgxtcbcomp04svn": 45,
        "sgxtcbcomp05svn": 100,
        "sgxtcbcomp06svn": 0,
        "sgxtcbcomp07svn": 1,
        "sgxtcbcomp08svn": 156,
        "sgxtcbcomp09svn": 208,
        "sgxtcbcomp10svn": 255,
        "sgxtcbcomp11svn": 2,
        "sgxtcbcomp12svn": 3,
        "sgxtcbcomp13svn": 4,
        "sgxtcbcomp14svn": 5,
        "sgxtcbcomp15svn": 6,
        "sgxtcbcomp16svn": 7,
        "pcesvn": 30865
    })json";
const std::string validUpToDateStatus = R"json("status": "UpToDate")json";
const std::string validOutOfDateStatus = R"json("status": "OutOfDate")json";
const std::string validRevokedStatus = R"json("status": "Revoked")json";
const std::string validConfigurationNeededStatus = R"json("status": "ConfigurationNeeded")json";
const std::string validTcbLevelTemplate = "{%s, %s}";

const std::string validTcbInfoTemplate = R"json({
        "tcbInfo": {
            "version": 1,
            "issueDate": "2017-10-04T11:10:45Z",
            "nextUpdate": "2018-06-21T12:36:02Z",
            "fmspc": "0192837465AF",
            "pceId": "0000",
            "tcbLevels": [%s]
        },
        %s})json";

const std::string validSignatureTemplate = R"json("signature": "62f2eb97227d906c158e8500964c8d10029e1a318e0e95054fbc1b9636913555d7147ceefe07c4cb7ac1ac700093e2ee3fd4f7d00c7caf135dc5243be51e1def")json";

std::string generateTcbInfo(const std::string& tcbInfoTemplate, const std::string& tcbLevelsJson, const std::string& signature)
{
    auto jsonSize = tcbInfoTemplate.length() + tcbLevelsJson.length() + signature.length() + 1;
	char* tcbInfo = new char[jsonSize];
    sprintf(tcbInfo, tcbInfoTemplate.c_str(), tcbLevelsJson.c_str(), signature.c_str());
    auto str = std::string(tcbInfo);
	delete[]tcbInfo;
	return str;
}

std::string generateTcbLevel(const std::string& tcbLevelTemplate,
                             const std::string& tcb,
                             const std::string& status)
{
    auto jsonSize = tcbLevelTemplate.length() + tcb.length() + status.length() + 1;
	char* tcbInfo = new char[jsonSize];
    sprintf(tcbInfo, tcbLevelTemplate.c_str(), tcb.c_str(), status.c_str());
	auto str = std::string(tcbInfo);
	delete[]tcbInfo;
	return str;
}
