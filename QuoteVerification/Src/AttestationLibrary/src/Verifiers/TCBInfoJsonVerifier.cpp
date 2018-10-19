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

#include "TCBInfoJsonVerifier.h"

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include <ctime>
#include <algorithm>

#include <OpensslHelpers/KeyUtils.h>
#include <OpensslHelpers/Bytes.h>
#include <QuoteVerification/QuoteConstants.h>
#include <CertVerification/X509Constants.h>
#include <iomanip>

namespace intel { namespace sgx { namespace qvl {

Status TCBInfoJsonVerifier::parse(const std::string& input)
{
    if(!jsonParser.parse(input))
    {
        return STATUS_SGX_TCB_INFO_UNSUPPORTED_FORMAT;
    }

    const auto* tcbInfo = jsonParser.getField("tcbInfo");
    const auto* signature = jsonParser.getField("signature");
    if(tcbInfo == nullptr || signature == nullptr)
    {
        return STATUS_SGX_TCB_INFO_UNSUPPORTED_FORMAT;
    }

    const Status tcbInfoStatus = parseTCBInfo(*tcbInfo);
    if(tcbInfoStatus != STATUS_OK)
    {
        return tcbInfoStatus;
    }

    if(!signature->IsString() || signature->GetStringLength() != constants::ECDSA_P256_SIGNATURE_BYTE_LEN * 2)
    {
        return STATUS_SGX_TCB_INFO_UNSUPPORTED_FORMAT;
    }
    tcbInfoSignature = hexStringToBytes(signature->GetString());

    return STATUS_OK;
}

Status TCBInfoJsonVerifier::parseTCBInfo(const ::rapidjson::Value& tcbInfo)
{
    if(!tcbInfo.IsObject())
    {
        return STATUS_SGX_TCB_INFO_UNSUPPORTED_FORMAT;
    }

    if(!checkVersion(tcbInfo)
        || !jsonParser.checkDateFieldOf(tcbInfo, "issueDate") || !jsonParser.checkDateFieldOf(tcbInfo, "nextUpdate")
        || !parseFmspc(tcbInfo) || !parsePceId(tcbInfo) || !parseTcbLevels(tcbInfo))
    {
        return STATUS_SGX_TCB_INFO_INVALID;
    }

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    tcbInfo.Accept(writer);

    tcbInfoBody = std::vector<uint8_t>{buffer.GetString(),
                                       &buffer.GetString()[buffer.GetSize()]};
    return STATUS_OK;
}

bool TCBInfoJsonVerifier::parseFmspc(const ::rapidjson::Value& tcbInfo)
{
    bool parseSuccessful = false;
    static constexpr size_t FMSPC_LENGTH = constants::FMSPC_BYTE_LEN * 2;
    std::tie(fmspc, parseSuccessful) = jsonParser.getHexstringFieldOf(tcbInfo, "fmspc", FMSPC_LENGTH);
    return parseSuccessful;
}

bool TCBInfoJsonVerifier::parsePceId(const ::rapidjson::Value& tcbInfo)
{
    bool parseSuccessful = false;
    static constexpr size_t PCEID_LENGTH = constants::PCEID_BYTE_LEN * 2;
    std::tie(pceId, parseSuccessful) = jsonParser.getHexstringFieldOf(tcbInfo, "pceId", PCEID_LENGTH);
    return parseSuccessful;
}

bool TCBInfoJsonVerifier::checkVersion(const ::rapidjson::Value& tcbInfo) const
{
    static const int SUPPORTED_TCB_INFO_VERSION = 1;
    int version = 0;
    bool status = false;
    std::tie(version, status) = jsonParser.getIntFieldOf(tcbInfo, "version");
    return status && (version == SUPPORTED_TCB_INFO_VERSION);
}

std::string TCBInfoJsonVerifier::extractTcbLevelStatus(const ::rapidjson::Value& tcbLevel) const
{
    static const std::array<std::string, 4> validStatuses = {{"UpToDate", "OutOfDate", "ConfigurationNeeded", "Revoked"}};
    const ::rapidjson::Value& status_v = tcbLevel["status"];
    if(!status_v.IsString())
    {
        return {};
    }
    const std::string status = status_v.GetString();
    if(std::find(validStatuses.cbegin(), validStatuses.cend(), status) == validStatuses.cend())
    {
        return {};
    }
    return status;
}

std::vector<uint8_t> TCBInfoJsonVerifier::extractTcbLevelCpusvn(const ::rapidjson::Value& tcb) const
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
        return {};
    }

    std::vector<uint8_t> combinedCpusvn{};
    combinedCpusvn.reserve(SGX_TCB_SVN_COMP_COUNT);
    for(const auto &componentName : sgxTcbSvnComponentsNames)
    {
        const auto componentNameRaw = componentName.data();
        bool status = false;
        uint componentValue = 0u;
        std::tie(componentValue, status) = jsonParser.getUintFieldOf(tcb, componentNameRaw);
        if(!status)
        {
            return {};
        }
        combinedCpusvn.push_back(static_cast<uint8_t>(componentValue));
    }
    return combinedCpusvn;
}

bool TCBInfoJsonVerifier::parseTcbLevel(const ::rapidjson::Value& tcbLevel)
{
    if(!tcbLevel.IsObject() || tcbLevel.MemberCount() != 2)
    {
        return false;
    }

    if(!tcbLevel.HasMember("tcb") || !tcbLevel.HasMember("status"))
    {
        return false;
    }

    const auto status = extractTcbLevelStatus(tcbLevel);
    if(status.empty())
    {
        return false;
    }

    const ::rapidjson::Value& tcb = tcbLevel["tcb"];

    const auto combinedCpusvn = extractTcbLevelCpusvn(tcb);
    if(combinedCpusvn.empty())
    {
        return false;
    }

    unsigned int pcesvn = {};
    bool pcesvnValid = false;
    std::tie(pcesvn, pcesvnValid) = jsonParser.getUintFieldOf(tcb, "pcesvn");
    if(!pcesvnValid)
    {
        return false;
    }

    bool inserted = false;
    std::tie(std::ignore, inserted) = tcbs.emplace(
        TCBInfoJsonVerifier::TcbLevel{combinedCpusvn, pcesvn, status});
    return inserted;
}

bool TCBInfoJsonVerifier::parseTcbLevels(const ::rapidjson::Value& tcbInfo)
{
    if(!tcbInfo.HasMember("tcbLevels"))
    {
        return false;
    }
    const auto& tcb = tcbInfo["tcbLevels"];
    if(!tcb.IsArray() || tcb.Size() == 0)
    {
        return false;
    }

    for(auto tcbLevelIndex = 0; tcbLevelIndex < tcb.Size(); ++tcbLevelIndex)
    {
        if(!parseTcbLevel(tcb[tcbLevelIndex]))
        {
            return false;
        }
    }

    if(tcbs.empty())
    {
        return false;
    }

    return true;
}

const std::vector<uint8_t>& TCBInfoJsonVerifier::getInfoBody() const
{
    return tcbInfoBody;
}

const std::vector<uint8_t>& TCBInfoJsonVerifier::getSignature() const
{
    return tcbInfoSignature;
}

const std::vector<uint8_t>& TCBInfoJsonVerifier::getFmspc() const
{
    return fmspc;
}

const std::vector<uint8_t>& TCBInfoJsonVerifier::getPceId() const
{
    return pceId;
}

const std::set<TCBInfoJsonVerifier::TcbLevel, std::greater<>>& TCBInfoJsonVerifier::getTcbLevels() const
{
    return tcbs;
}

}}} // namespace intel { namespace sgx { namespace qvl {
