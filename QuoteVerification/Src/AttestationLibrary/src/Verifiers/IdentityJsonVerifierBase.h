/*
* Copyright (c) 2018, Intel Corporation
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
*    * Redistributions of source code must retain the above copyright notice,
*      this list of conditions and the following disclaimer.
*    * Redistributions in binary form must reproduce the above copyright
*      notice, this list of conditions and the following disclaimer in the
*      documentation and/or other materials provided with the distribution.
*    * Neither the name of Intel Corporation nor the names of its contributors
*      may be used to endorse or promote products derived from this software
*      without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef SGXECDSAATTESTATION_JSONVERIFIERBASE_H
#define SGXECDSAATTESTATION_JSONVERIFIERBASE_H

#include <rapidjson/fwd.h>
#include <string>
#include <vector>
#include <ctime>
#include <SgxEcdsaAttestation/QuoteVerification.h>
#include <Utils/JsonParser.h>

namespace intel { namespace sgx { namespace qvl {

class IdentityJsonVerifierBase {

public:
    virtual ~IdentityJsonVerifierBase() = default;

    virtual Status parse(const std::string &input) = 0;
    virtual Status parseJson(const ::rapidjson::Value &qeIdentity) = 0;

    const std::vector<uint8_t>& getMiscselect() const;
    const std::vector<uint8_t>& getMiscselectMask() const;
    const std::vector<uint8_t>& getAttributes() const;
    const std::vector<uint8_t>& getAttributesMask() const;
    const std::vector<uint8_t>& getMrenclave() const;
    const std::vector<uint8_t>& getMrsigner() const;
    const uint getIsvProdId() const;
    const uint getIsvSvn() const;
    const int getVersion() const;
    bool isIsvProdIdParseSuccess() const;
    bool isIsvSvnParseSuccess() const;
    bool checkDateCorrectness() const;

protected:
    bool parseMiscselect(const rapidjson::Value &input);
    bool parseMiscselectMask(const rapidjson::Value &input);
    bool parseAttributes(const rapidjson::Value &input);
    bool parseAttributesMask(const rapidjson::Value &input);
    bool parseMrsigner(const rapidjson::Value &input);
    bool parseMrenclave(const rapidjson::Value &input);
    bool parseIsvprodid(const rapidjson::Value &input);
    bool parseIsvsvn(const rapidjson::Value &input);
    bool parseVersion(const rapidjson::Value &input);
    bool parseIssueDate(const rapidjson::Value &input);
    bool parseNextUpdate(const rapidjson::Value &input);

    bool parseHexstringProperty(const rapidjson::Value &object, const std::string &propertyName, size_t length, std::vector<uint8_t> &saveAs);
    bool parseUintProperty(const rapidjson::Value &object, const std::string &propertyName, uint &saveAs);

    JsonParser jsonParser;
    std::vector<uint8_t> miscselect;
    std::vector<uint8_t> miscselectMask;
    std::vector<uint8_t> attributes;
    std::vector<uint8_t> attributesMask;
    std::vector<uint8_t> mrenclave;
    std::vector<uint8_t> mrsigner;
    tm issueDate;
    tm nextUpdate;
    uint isvProdId;
    uint isvSvn;
    int version;

    bool isvProdIdParseSuccess;
    bool isvSvnParseSuccess;
};

}}} // namespace intel { namespace sgx { namespace qvl {

#endif //SGXECDSAATTESTATION_JSONVERIFIERBASE_H
