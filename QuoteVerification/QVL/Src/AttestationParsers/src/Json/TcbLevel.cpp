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

#include "SgxEcdsaAttestation/AttestationParsers.h"

#include "X509Constants.h"
#include "JsonParser.h"

#include <array>
#include <tuple>
#include <algorithm>

namespace intel { namespace sgx { namespace dcap { namespace parser { namespace json {

TcbLevel::TcbLevel(const std::vector<uint8_t>& cpuSvnComponents,
                   unsigned int pceSvn,
                   const std::string& status): _cpuSvnComponents(cpuSvnComponents),
                                               _pceSvn(pceSvn),
                                               _status(status)
{}

TcbLevel::TcbLevel(const std::vector<uint8_t>& cpuSvnComponents,
         unsigned int pceSvn,
         const std::string& status,
         std::time_t tcbDate,
         std::vector<std::string> advisoryIDs): _cpuSvnComponents(cpuSvnComponents),
                                                _pceSvn(pceSvn),
                                                _status(status),
                                                _tcbDate(tcbDate),
                                                _advisoryIDs(advisoryIDs)
{}

bool TcbLevel::operator>(const TcbLevel& other) const
{
    if(_cpuSvnComponents == other._cpuSvnComponents)
    {
        return _pceSvn > other._pceSvn;
    }
    return _cpuSvnComponents > other._cpuSvnComponents;
}

unsigned int TcbLevel::getSgxTcbComponentSvn(unsigned int componentNumber) const
{
    if (componentNumber > constants::CPUSVN_BYTE_LEN)
    {
        std::string err = "Invalid component SVN number [" + std::to_string(componentNumber) +
                          "]. Should be less than " + std::to_string(constants::CPUSVN_BYTE_LEN);
        throw FormatException(err);
    }
    return _cpuSvnComponents[componentNumber];
}

const std::vector<uint8_t>& TcbLevel::getCpuSvn() const
{
    return _cpuSvnComponents;
}

unsigned int TcbLevel::getPceSvn() const
{
    return _pceSvn;
}

const std::string& TcbLevel::getStatus() const
{
    return _status;
}

const std::time_t& TcbLevel::getTcbDate() const
{
    return _tcbDate;
}

const std::vector<std::string>& TcbLevel::getAdvisoryIDs() const
{
    return _advisoryIDs;
}

// private

TcbLevel::TcbLevel(const ::rapidjson::Value& tcbLevel, unsigned int version)
{
    JsonParser jsonParser;

    switch(version)
    {
        case 1:
            parseTcbLevelV1(tcbLevel, jsonParser);
            break;
        case 2:
            parseTcbLevelV2(tcbLevel, jsonParser);
            break;
        default:
            throw InvalidExtensionException("Unsupported version of tcbLevel");

    }
}

void TcbLevel::parseStatus(const ::rapidjson::Value &tcbLevel,
                           const std::vector<std::string> &validStatuses,
                           const std::string &filedName)
{
    const ::rapidjson::Value& status_v = tcbLevel[filedName.c_str()];
    if(!status_v.IsString())
    {
        throw FormatException("TCB level [" + filedName + "] JSON field should be a string");
    }
    _status = status_v.GetString();
    if(std::find(validStatuses.cbegin(), validStatuses.cend(), _status) == validStatuses.cend())
    {
        throw InvalidExtensionException("TCB level [" + filedName + "] JSON field has invalid value [" + _status + "]");
    }
}

void TcbLevel::parseSvns(const ::rapidjson::Value &tcbLevel, JsonParser& jsonParser)
{
    const ::rapidjson::Value& tcb = tcbLevel["tcb"];

    setCpuSvn(tcb, jsonParser);

    bool pceSvnValid = false;
    std::tie(_pceSvn, pceSvnValid) = jsonParser.getUintFieldOf(tcb, "pcesvn");
    if(!pceSvnValid)
    {
        throw FormatException("Could not parse [pcesvn] field of TCB level JSON to unsigned integer");
    }
}

void TcbLevel::parseTcbLevelV1(const ::rapidjson::Value &tcbLevel, JsonParser& jsonParser)
{
    if(!tcbLevel.IsObject() || tcbLevel.MemberCount() != 2)
    {
        throw FormatException("TCB level should be a JSON object having 2 members");
    }

    if(!tcbLevel.HasMember("tcb"))
    {
        throw FormatException("TCB level JSON should has [tcb] field");
    }

    if(!tcbLevel.HasMember("status"))
    {
        throw FormatException("TCB level JSON should has [status] field");
    }

    static const std::vector<std::string> validStatuses = {{"UpToDate", "OutOfDate", "ConfigurationNeeded", "Revoked"}};
    parseStatus(tcbLevel, validStatuses, "status");

    parseSvns(tcbLevel, jsonParser);
}

void TcbLevel::parseTcbLevelV2(const ::rapidjson::Value &tcbLevel, JsonParser& jsonParser)
{
    if(!tcbLevel.IsObject())
    {
        throw FormatException("TCB level should be a JSON object");
    }

    if(!tcbLevel.HasMember("tcb"))
    {
        throw FormatException("TCB level JSON should has [tcb] field");
    }

    if(!tcbLevel.HasMember("tcbStatus"))
    {
        throw FormatException("TCB level JSON should has [tcbStatus] field");
    }

    if(!tcbLevel.HasMember("tcbDate"))
    {
        throw FormatException("TCB level JSON should has [tcbDate] field");
    }

    if (!jsonParser.checkDateFieldOf(tcbLevel, "tcbDate"))
    {
        throw InvalidExtensionException("[tcbDate] field of TCB info JSON should be ISO formatted date");
    }

    bool tcbDateValid = false;
    std::tie(_tcbDate, tcbDateValid) = jsonParser.getDateFieldOf(tcbLevel, "tcbDate");
    if (!tcbDateValid)
    {
        throw InvalidExtensionException("Could not parse [tcbDate] field of TCB info JSON to date");
    }

    if(tcbLevel.HasMember("advisoryIDs"))
    {
        bool advisoryIDsValid = false;
        std::tie(_advisoryIDs, advisoryIDsValid) = jsonParser.getStringVecFieldOf(tcbLevel, "advisoryIDs");
        if (!advisoryIDsValid)
        {
            throw InvalidExtensionException("Could not parse [advisoryIDs] field of TCB info JSON to array");
        }
    }

    static const std::vector<std::string> validStatuses =
            {{"UpToDate", "OutOfDate", "ConfigurationNeeded", "Revoked", "OutOfDateConfigurationNeeded", "SWHardeningNeeded", "ConfigurationAndSWHardeningNeeded"}};
    parseStatus(tcbLevel, validStatuses, "tcbStatus");

    parseSvns(tcbLevel, jsonParser);
}

void TcbLevel::setCpuSvn(const ::rapidjson::Value& tcb, JsonParser& jsonParser)
{
    static constexpr size_t SGX_TCB_SVN_COMP_COUNT = 16;
    const std::array<std::string, SGX_TCB_SVN_COMP_COUNT> sgxTcbSvnComponentsNames {{
                                                                                            "sgxtcbcomp01svn",
                                                                                            "sgxtcbcomp02svn",
                                                                                            "sgxtcbcomp03svn",
                                                                                            "sgxtcbcomp04svn",
                                                                                            "sgxtcbcomp05svn",
                                                                                            "sgxtcbcomp06svn",
                                                                                            "sgxtcbcomp07svn",
                                                                                            "sgxtcbcomp08svn",
                                                                                            "sgxtcbcomp09svn",
                                                                                            "sgxtcbcomp10svn",
                                                                                            "sgxtcbcomp11svn",
                                                                                            "sgxtcbcomp12svn",
                                                                                            "sgxtcbcomp13svn",
                                                                                            "sgxtcbcomp14svn",
                                                                                            "sgxtcbcomp15svn",
                                                                                            "sgxtcbcomp16svn",
                                                                                    }};

    if(!tcb.IsObject())
    {
        throw FormatException("[tcb] field of TCB level should be a JSON object");
    }

    _cpuSvnComponents.reserve(SGX_TCB_SVN_COMP_COUNT);
    for(const auto &componentName : sgxTcbSvnComponentsNames)
    {
        const auto componentNameRaw = componentName.data();
        bool status = false;
        unsigned int componentValue = 0u;
        std::tie(componentValue, status) = jsonParser.getUintFieldOf(tcb, componentNameRaw);
        if(!status)
        {
            throw FormatException("Could not parse [" + componentName + "] field of TCB level JSON to unsigned integer");
        }
        _cpuSvnComponents.push_back(static_cast<uint8_t>(componentValue));
    }
}

}}}}} // namespace intel { namespace sgx { namespace dcap { namespace parser { namespace json {
