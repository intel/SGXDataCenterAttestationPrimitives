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
    if(input.empty())
    {
        return STATUS_UNSUPPORTED_CERT_FORMAT;
    }

    ::rapidjson::Document jsonDoc;
    jsonDoc.Parse(input.c_str());
    if(jsonDoc.HasParseError() || !jsonDoc.IsObject()
        || !jsonDoc.HasMember("tcbInfo") || !jsonDoc.HasMember("signature"))
    {
        return STATUS_SGX_TCB_INFO_UNSUPPORTED_FORMAT;
    }

    const Status tcbInfoStatus = parseTCBInfo(jsonDoc["tcbInfo"]);
    if(tcbInfoStatus != STATUS_OK)
    {
        return tcbInfoStatus;
    }

    const ::rapidjson::Value& signature_v = jsonDoc["signature"];
    if(!signature_v.IsString() || signature_v.GetStringLength() != constants::ECDSA_P256_SIGNATURE_BYTE_LEN * 2)
    {
        return STATUS_SGX_TCB_INFO_UNSUPPORTED_FORMAT;
    }
    tcbInfoSignature = hexStringToBytes(signature_v.GetString());

    return STATUS_OK;
}

Status TCBInfoJsonVerifier::parseTCBInfo(const ::rapidjson::Value& tcbInfo)
{
    if(!tcbInfo.IsObject())
    {
        return STATUS_SGX_TCB_INFO_UNSUPPORTED_FORMAT;
    }

    if(!checkVersion(tcbInfo) || !checkDate(tcbInfo, "issueDate") || !checkDate(tcbInfo, "nextUpdate")
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
    if(!tcbInfo.HasMember("fmspc"))
    {
        return false;
    }
    static constexpr size_t FMSPC_LENGTH = constants::FMSPC_BYTE_LEN * 2;
    const ::rapidjson::Value& fmspc_v = tcbInfo["fmspc"];
    if(!fmspc_v.IsString())
    {
        return false;
    }

    const std::string fmspcStr = fmspc_v.GetString();
    if(fmspcStr.length() == FMSPC_LENGTH && isValidHexstring(fmspcStr))
    {
        fmspc = hexStringToBytes(fmspcStr);
        return true;
    }
    return false;
}

bool TCBInfoJsonVerifier::parsePceId(const ::rapidjson::Value& tcbInfo)
{
    if(!tcbInfo.HasMember("pceId"))
    {
        return false;
    }
    static constexpr size_t PCEID_LENGTH = constants::PCEID_BYTE_LEN * 2;
    const ::rapidjson::Value& pceId_v = tcbInfo["pceId"];
    if(!pceId_v.IsString())
    {
        return false;
    }

    const std::string pceIdStr = pceId_v.GetString();
    if(pceIdStr.length() == PCEID_LENGTH && isValidHexstring(pceIdStr))
    {
        pceId = hexStringToBytes(pceIdStr);
        return true;
    }
    return false;
}

bool TCBInfoJsonVerifier::checkDate(const ::rapidjson::Value& tcbInfo, const std::string fieldName) const
{
    if(!tcbInfo.HasMember(fieldName.c_str()))
    {
        return false;
    }
    const ::rapidjson::Value& issueDate_v = tcbInfo[fieldName.c_str()];
    return issueDate_v.IsString() && isValidTimeString(issueDate_v.GetString());
}

bool TCBInfoJsonVerifier::checkVersion(const ::rapidjson::Value& tcbInfo) const
{
    if(!tcbInfo.HasMember("version"))
    {
        return false;
    }
    static const int SUPPORTED_TCB_INFO_VERSION = 1;
    const ::rapidjson::Value& version_v = tcbInfo["version"];
    if(!version_v.IsInt())
    {
        return false;
    }
    return version_v.GetInt() == SUPPORTED_TCB_INFO_VERSION;
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
        if(!tcb.HasMember(componentNameRaw))
        {
            return {};
        }
        const ::rapidjson::Value& component_v = tcb[componentNameRaw];
        if(!component_v.IsUint())
        {
            return {};
        }
        combinedCpusvn.push_back(static_cast<uint8_t>(component_v.GetUint()));
    }
    return combinedCpusvn;
}

std::pair<unsigned int, bool> TCBInfoJsonVerifier::extractTcbLevelPcesvn(const ::rapidjson::Value& tcb) const
{
    static const auto EXTRACTION_FAILED = std::make_pair(unsigned(), false);
    if(!tcb.HasMember("pcesvn"))
    {
        return EXTRACTION_FAILED;
    }
    const ::rapidjson::Value& pcesvn_v = tcb["pcesvn"];
    if(!pcesvn_v.IsUint())
    {
        return EXTRACTION_FAILED;
    }
    return {pcesvn_v.GetUint(), true};
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
    std::tie(pcesvn, pcesvnValid) = extractTcbLevelPcesvn(tcb);
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

    auto latestTcb = findLatest("UpToDate");
    if(latestTcb != tcbs.cend())
    {
        latestCpuSvn = latestTcb->cpusvn;
        latestPcesvn = latestTcb->pcesvn;
    }

    auto latestRevokedTcb = findLatest("Revoked");
    if(latestRevokedTcb != tcbs.cend())
    {
        latestRevokedCpuSvn = latestRevokedTcb->cpusvn;
        latestRevokedPcesvn = latestRevokedTcb->pcesvn;
    }

    if(latestTcb == tcbs.cend() && latestRevokedTcb == tcbs.cend())
    {
        return false;
    }

    return true;
}

bool TCBInfoJsonVerifier::isValidHexstring(const std::string& hexString) const
{
    return std::find_if(hexString.cbegin(), hexString.cend(),
        [](const char c){return !std::isxdigit(c);}) == hexString.cend();
}

bool TCBInfoJsonVerifier::isValidTimeString(const std::string& timeString) const
{
    std::tm time{};
    return strptime(timeString.c_str(), "%Y-%m-%dT%H:%M:%SZ", &time) != nullptr;
}

std::set<TCBInfoJsonVerifier::TcbLevel>::const_iterator TCBInfoJsonVerifier::findLatest(const std::string& status) const
{
    return std::find_if(tcbs.cbegin(), tcbs.cend(), [&status](const TcbLevel& e)-> bool
        {
            return e.status == status;
        });
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

const std::vector<uint8_t>& TCBInfoJsonVerifier::getLatestCpusvn() const
{
    return latestCpuSvn;
}

unsigned int TCBInfoJsonVerifier::getLatestPcesvn() const
{
    return latestPcesvn;
}

const std::vector<uint8_t>& TCBInfoJsonVerifier::getRevokedCpusvn() const
{
    return latestRevokedCpuSvn;
}

unsigned int TCBInfoJsonVerifier::getRevokedPcesvn() const
{
    return latestRevokedPcesvn;
}

}}} // namespace intel { namespace sgx { namespace qvl {
