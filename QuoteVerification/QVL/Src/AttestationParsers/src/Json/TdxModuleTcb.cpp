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

TdxModuleTcb::TdxModuleTcb(uint16_t isvSvn) : _isvsvn(isvSvn)
{}

TdxModuleTcb::TdxModuleTcb(const ::rapidjson::Value& tdxModuleTcb)
{
    JsonParser jsonParser;
    auto status = JsonParser::Missing;
    int32_t isvsvn;
    std::tie(isvsvn, status) = jsonParser.getIntFieldOf(tdxModuleTcb, "isvsvn");
    if (status != JsonParser::OK)
    {
        LOG_AND_THROW(FormatException, "TDX Module TCB JSON's [isvsvn] field should be an unsigned integer");
    }
    if (isvsvn < 0 || isvsvn > UINT16_MAX)
    {
        const std::string err = "TDX Module TCB JSON's [isvsvn] field value should be within 0 and " + std::to_string(UINT16_MAX);
        LOG_AND_THROW(FormatException, err);
    }
    _isvsvn = (uint16_t) isvsvn;
}

uint16_t TdxModuleTcb::getIsvSvn() const
{
    return _isvsvn;
}

}}}}} // namespace intel { namespace sgx { namespace dcap { namespace parser { namespace json {