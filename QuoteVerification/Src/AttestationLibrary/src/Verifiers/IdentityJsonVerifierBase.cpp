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

#include "IdentityJsonVerifierBase.h"
#include <CertVerification/X509Constants.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <QuoteVerification/QuoteConstants.h>
#include <OpensslHelpers/Bytes.h>
#include <algorithm>
#include <ctime>
#include <iomanip>

namespace intel { namespace sgx { namespace qvl {

const std::vector<uint8_t>& IdentityJsonVerifierBase::getMiscselect() const
{
    return miscselect;
}

const std::vector<uint8_t>& IdentityJsonVerifierBase::getMiscselectMask() const
{
    return miscselectMask;
}

const std::vector<uint8_t>& IdentityJsonVerifierBase::getAttributes() const
{
    return attributes;
}

const std::vector<uint8_t>& IdentityJsonVerifierBase::getAttributesMask() const
{
    return attributesMask;
}

const std::vector<uint8_t>& IdentityJsonVerifierBase::getMrsigner() const
{
    return mrsigner;
}

const uint IdentityJsonVerifierBase::getIsvProdId() const
{
    return isvProdId;
}

const uint IdentityJsonVerifierBase::getIsvSvn() const
{
    return isvSvn;
}

const std::vector<uint8_t>& IdentityJsonVerifierBase::getMrenclave() const
{
    return mrenclave;
}

const int IdentityJsonVerifierBase::getVersion() const
{
    return version;
}

bool IdentityJsonVerifierBase::parseVersion(const rapidjson::Value &input)
{
    bool status = false;
    std::tie(version, status) = jsonParser.getIntFieldOf(input, "version");
    return status;
}

bool IdentityJsonVerifierBase::parseIssueDate(const rapidjson::Value &input)
{
    bool status = false;
    std::tie(issueDate, status) = jsonParser.getDateFieldOf(input, "issueDate");
    return status;
}

bool IdentityJsonVerifierBase::parseNextUpdate(const rapidjson::Value &input)
{
    bool status = false;
    std::tie(nextUpdate, status) = jsonParser.getDateFieldOf(input, "nextUpdate");
    return status;
}

bool IdentityJsonVerifierBase::parseMiscselect(const rapidjson::Value &input)
{
    return parseHexstringProperty(input, "miscselect", constants::MISCSELECT_BYTE_LEN * 2, miscselect);
}

bool IdentityJsonVerifierBase::parseMiscselectMask(const rapidjson::Value &input)
{
    return parseHexstringProperty(input, "miscselectMask", constants::MISCSELECT_BYTE_LEN * 2, miscselectMask);
}

bool IdentityJsonVerifierBase::parseAttributes(const rapidjson::Value &input)
{
    return parseHexstringProperty(input, "attributes", constants::ATTRIBUTES_BYTE_LEN * 2, attributes);
}

bool IdentityJsonVerifierBase::parseAttributesMask(const rapidjson::Value &input)
{
    return parseHexstringProperty(input, "attributesMask", constants::ATTRIBUTES_BYTE_LEN * 2, attributesMask);
}

bool IdentityJsonVerifierBase::parseMrsigner(const rapidjson::Value &input)
{
    return parseHexstringProperty(input, "mrsigner", constants::MRSIGNER_BYTE_LEN * 2, mrsigner);
}

bool IdentityJsonVerifierBase::parseMrenclave(const rapidjson::Value &input)
{
    return parseHexstringProperty(input, "mrenclave", constants::MRENCLAVE_BYTE_LEN * 2, mrenclave);
}

bool IdentityJsonVerifierBase::parseHexstringProperty(const rapidjson::Value &object, const std::string &propertyName, const size_t length, std::vector<uint8_t> &saveAs)
{
    bool parseSuccessful = false;
    std::tie(saveAs, parseSuccessful) = jsonParser.getHexstringFieldOf(object, propertyName, length);
    return parseSuccessful;
}

bool IdentityJsonVerifierBase::parseIsvprodid(const rapidjson::Value &input)
{
    isvProdIdParseSuccess = parseUintProperty(input, "isvprodid", isvProdId);
    return isvProdIdParseSuccess;
}

bool IdentityJsonVerifierBase::parseIsvsvn(const rapidjson::Value &input)
{
    isvSvnParseSuccess = parseUintProperty(input, "isvsvn", isvSvn);
    return isvSvnParseSuccess;
}

bool IdentityJsonVerifierBase::parseUintProperty(const rapidjson::Value &object, const std::string &propertyName, uint &saveAs)
{
    bool parseSuccessful = false;
    std::tie(saveAs, parseSuccessful) = jsonParser.getUintFieldOf(object, propertyName);
    return parseSuccessful;
}

bool IdentityJsonVerifierBase::isIsvProdIdParseSuccess() const
{
    return isvProdIdParseSuccess;
}

bool IdentityJsonVerifierBase::isIsvSvnParseSuccess() const
{
    return isvSvnParseSuccess;
}

bool IdentityJsonVerifierBase::checkDateCorrectness() const
{
    auto currentTime = time(nullptr);
    auto universalTime = gmtime(&currentTime);

    auto makeTuple = [](const tm& time) -> auto {
        return std::tie(time.tm_year,
                 time.tm_mon,
                 time.tm_mday,
                 time.tm_hour,
                 time.tm_min,
                 time.tm_sec);
    };

    return makeTuple(*universalTime) >= makeTuple(issueDate) && makeTuple(*universalTime) < makeTuple(nextUpdate);
}

}}} // namespace intel { namespace sgx { namespace qvl {
