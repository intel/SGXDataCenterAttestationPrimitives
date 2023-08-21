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

TdxModuleTcbLevel::TdxModuleTcbLevel(const TdxModuleTcb& tcb, const std::time_t& tcbDate,
                                     const std::string& tcbStatus, const std::vector<std::string>& advisoryIDs) :
                                     _tcb(tcb), _tcbDate(tcbDate), _tcbStatus(tcbStatus), _advisoryIDs(advisoryIDs)
{}

TdxModuleTcbLevel::TdxModuleTcbLevel(const ::rapidjson::Value& tdxModuleTcbLevel)
{
    JsonParser jsonParser;
    auto status = JsonParser::Missing;

    if(!tdxModuleTcbLevel.HasMember("tcb"))
    {
        LOG_AND_THROW(FormatException, "TDX Module TCB level JSON should have [tcb] field");
    }

    _tcb = TdxModuleTcb(tdxModuleTcbLevel["tcb"]);

    std::tie(_tcbDate, status) = jsonParser.getDateFieldOf(tdxModuleTcbLevel, "tcbDate");
    if (status != JsonParser::OK)
    {
        LOG_AND_THROW(FormatException, "TDX Module TCB Level JSON's [tcbDate] field should be a string compliant to ISO 8601");
    }

    std::tie(_tcbStatus, status) = jsonParser.getStringFieldOf(tdxModuleTcbLevel, "tcbStatus");
    if (status != JsonParser::OK)
    {
        LOG_AND_THROW(FormatException, "TDX Module TCB Level JSON's [tcbStatus] field should be a string");
    }

    std::tie(_advisoryIDs, status) = jsonParser.getStringVecFieldOf(tdxModuleTcbLevel, "advisoryIDs");
    if (status == JsonParser::Invalid) // Optional field
    {
        LOG_AND_THROW(FormatException, "TDX Module TCB Level JSON's [advisoryIDs] field should be a string array");
    }
}

bool TdxModuleTcbLevel::operator>(const TdxModuleTcbLevel& other) const
{
    {
        return _tcb._isvsvn > other._tcb._isvsvn;
    }
}

const TdxModuleTcb& TdxModuleTcbLevel::getTcb() const
{
    return _tcb;
}

const std::time_t& TdxModuleTcbLevel::getTcbDate() const
{
    return _tcbDate;
}

const std::string& TdxModuleTcbLevel::getStatus() const
{
    return _tcbStatus;
}

const std::vector<std::string>& TdxModuleTcbLevel::getAdvisoryIDs() const
{
    return _advisoryIDs;
}

}}}}} // namespace intel { namespace sgx { namespace dcap { namespace parser { namespace json {