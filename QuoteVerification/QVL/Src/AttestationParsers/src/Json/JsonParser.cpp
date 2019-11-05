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

#include "JsonParser.h"

#include "OpensslHelpers/Bytes.h"
#include "Utils/TimeUtils.h"

#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include <tuple>
#include <algorithm>

namespace intel { namespace sgx { namespace dcap { namespace parser { namespace json {

bool JsonParser::parse(const std::string& json)
{
    if(json.empty())
    {
        return false;
    }
    jsonDocument.Parse(json.c_str());
    return !jsonDocument.HasParseError() && jsonDocument.IsObject();
}

const rapidjson::Value* JsonParser::getField(const std::string& fieldName) const
{
    if(!jsonDocument.HasMember(fieldName.c_str()))
    {
        return nullptr;
    }
    return &jsonDocument[fieldName.c_str()];
}

std::pair<std::vector<std::string>, bool> JsonParser::getStringVecFieldOf(const ::rapidjson::Value& parent, const std::string& fieldName) const
{
    std::vector<std::string> advisoryIDs;
    static auto FailedReturnValue = std::make_pair(advisoryIDs, false);
    if(!parent.HasMember(fieldName.c_str()))
    {
        return FailedReturnValue;
    }
    const ::rapidjson::Value& property_v = parent[fieldName.c_str()];
    if(!property_v.IsArray())
    {
        return FailedReturnValue;
    }

    for (rapidjson::SizeType i = 0; i < property_v.Size(); i++)
    {
        advisoryIDs.push_back(property_v[i].GetString());
    }

    return std::make_pair(advisoryIDs, true);
}

std::pair<std::vector<uint8_t>, bool> JsonParser::getBytesFieldOf(const ::rapidjson::Value &parent,
                                                                  const std::string &fieldName, size_t length) const
{
    static auto FailedReturnValue = std::make_pair(std::vector<uint8_t>{}, false);
    if(!parent.HasMember(fieldName.c_str()))
    {
        return FailedReturnValue;
    }
    const ::rapidjson::Value& property_v = parent[fieldName.c_str()];
    if(!property_v.IsString())
    {
        return FailedReturnValue;
    }

    const std::string propertyStr = property_v.GetString();
    if(propertyStr.length() == length && isValidHexstring(propertyStr))
    {
        return std::make_pair(hexStringToBytes(propertyStr), true);
    }
    return FailedReturnValue;
}


std::pair<time_t, bool> JsonParser::getDateFieldOf(const ::rapidjson::Value& parent, const std::string& fieldName) const
{
    if(!parent.HasMember(fieldName.c_str()))
    {
        return std::make_pair(time_t{}, false);
    }
    const auto& date = parent[fieldName.c_str()];
    if(!date.IsString() || !isValidTimeString(date.GetString()))
    {
        return std::make_pair(time_t{}, false);
    }
    return std::make_pair(getEpochTimeFromString(date.GetString()), true);
}

bool JsonParser::checkDateFieldOf(const ::rapidjson::Value& parent, const std::string& fieldName) const
{
    bool status = false;
    std::tie(std::ignore, status) = getDateFieldOf(parent, fieldName);
    return status;
}

std::pair<unsigned int, bool> JsonParser::getUintFieldOf(const ::rapidjson::Value& parent, const std::string& fieldName) const
{
    if(!parent.HasMember(fieldName.c_str()))
    {
        return std::make_pair(0u, false);
    }
    const ::rapidjson::Value& value = parent[fieldName.c_str()];
    if(!value.IsUint())
    {
        return std::make_pair(0u, false);
    }
    return std::make_pair(value.GetUint(), true);
}

std::pair<int, bool> JsonParser::getIntFieldOf(const ::rapidjson::Value& parent, const std::string& fieldName) const
{
    if(!parent.HasMember(fieldName.c_str()))
    {
        return std::make_pair(0, false);
    }
    const ::rapidjson::Value& value = parent[fieldName.c_str()];
    if(!value.IsInt())
    {
        return std::make_pair(0, false);
    }
    return std::make_pair(value.GetInt(), true);
}

bool JsonParser::isValidHexstring(const std::string& hexString) const
{
    return std::find_if(hexString.cbegin(), hexString.cend(),
        [](const char c){return !::isxdigit(c);}) == hexString.cend();
}

}}}}} // namespace intel { namespace sgx { namespace dcap { namespace parser { namespace json {
