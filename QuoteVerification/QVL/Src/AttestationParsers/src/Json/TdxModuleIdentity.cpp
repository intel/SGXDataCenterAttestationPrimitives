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

#include "SgxEcdsaAttestation/AttestationParsers.h"
#include "JsonParser.h"
#include "Utils/Logger.h"

#include <tuple>

namespace intel { namespace sgx { namespace dcap { namespace parser { namespace json {

TdxModuleIdentity::TdxModuleIdentity(const std::string& id, const std::vector<uint8_t>& mrsigner,
                                     const std::vector<uint8_t>& attributes, const std::vector<uint8_t>& attributesMask,
                                     const std::set<TdxModuleTcbLevel, std::greater<TdxModuleTcbLevel>>& tcbLevels) :
                                     _id(id), _mrsigner(mrsigner), _attributes(attributes),
                                     _attributesMask(attributesMask), _tcbLevels(tcbLevels)
{}

TdxModuleIdentity::TdxModuleIdentity(const ::rapidjson::Value &tdxModuleIdentity)
{
    JsonParser jsonParser;
    auto status = JsonParser::Missing;

    std::tie(_id, status) = jsonParser.getStringFieldOf(tdxModuleIdentity, "id");
    if (status != JsonParser::OK)
    {
        LOG_AND_THROW(FormatException, "TDX Module Identity JSON's [id] field should be a string");
    }

    std::tie(_mrsigner, status) = jsonParser.getBytesFieldOf(tdxModuleIdentity, "mrsigner", 96);
    if (status != JsonParser::OK)
    {
        LOG_AND_THROW(FormatException, "TDX Module Identity JSON's [mrsigner] field should be a hex encoded string");
    }

    std::tie(_attributes, status) = jsonParser.getBytesFieldOf(tdxModuleIdentity, "attributes", 16);
    if (status != JsonParser::OK)
    {
        LOG_AND_THROW(FormatException, "TDX Module Identity JSON's [attributes] field should be a hex encoded string");
    }

    std::tie(_attributesMask, status) = jsonParser.getBytesFieldOf(tdxModuleIdentity, "attributesMask", 16);
    if (status != JsonParser::OK)
    {
        LOG_AND_THROW(FormatException, "TDX Module Identity JSON's [attributesMask] field should be a hex encoded string");
    }

    const auto tcbLevels = &tdxModuleIdentity["tcbLevels"];
    if(!tcbLevels->IsArray())
    {
        LOG_AND_THROW(FormatException, "[tcbLevels] field of TDX Module Identity JSON should be a nonempty array");
    }

    for (rapidjson::Value::ConstValueIterator itr = tcbLevels->Begin(); itr != tcbLevels->End(); ++itr) {
        bool inserted = false;
        std::tie(std::ignore, inserted) = _tcbLevels.emplace(TdxModuleTcbLevel(*itr));
        if (!inserted)
        {
            LOG_AND_THROW(FormatException, "Detected duplicated TDX Module Identity TCB levels");
        }
    }

    if(_tcbLevels.empty())
    {
        LOG_AND_THROW(FormatException, "Number of parsed [tcbLevels] should not be 0");
    }
}

std::string TdxModuleIdentity::getId() const
{
    return _id;
}

const std::vector<uint8_t>& TdxModuleIdentity::getMrSigner() const
{
    return _mrsigner;
}

const std::vector<uint8_t>& TdxModuleIdentity::getAttributes() const
{
    return _attributes;
}

const std::vector<uint8_t>& TdxModuleIdentity::getAttributesMask() const
{
    return _attributesMask;
}

const std::set<TdxModuleTcbLevel, std::greater<TdxModuleTcbLevel>>& TdxModuleIdentity::getTcbLevels() const
{
    return _tcbLevels;
}

}}}}} // namespace intel { namespace sgx { namespace dcap { namespace parser { namespace json {