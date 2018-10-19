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
#include "QEIdentityJsonVerifier.h"

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include <QuoteVerification/QuoteConstants.h>
#include <OpensslHelpers/Bytes.h>
#include <algorithm>
#include <ctime>
#include <iomanip>
#include <CertVerification/X509Constants.h>

namespace intel { namespace sgx { namespace qvl {

Status QEIdentityJsonVerifier::parse(const std::string& input)
{
    if(!jsonParser.parse(input))
    {
        status = STATUS_SGX_QE_IDENTITY_UNSUPPORTED_FORMAT;
        return status;
    }

    const auto* qeIdentity = jsonParser.getField("qeIdentity");
    const auto* signature = jsonParser.getField("signature");
    if(qeIdentity == nullptr || signature == nullptr)
    {
        status = STATUS_SGX_QE_IDENTITY_UNSUPPORTED_FORMAT;
        return status;
    }


    status = parseJson(*qeIdentity);
    if(status != STATUS_OK)
    {
        return status;
    }

    if(!signature->IsString() || signature->GetStringLength() != constants::ECDSA_P256_SIGNATURE_BYTE_LEN * 2)
    {
        status = STATUS_SGX_QE_IDENTITY_INVALID;
        return status;
    }

    this->signature = hexStringToBytes(signature->GetString());

    status = STATUS_OK;
    return status;
}

Status QEIdentityJsonVerifier::parseJson(const ::rapidjson::Value &qeIdentity)
{
    if(!qeIdentity.IsObject())
    {
        return STATUS_SGX_QE_IDENTITY_UNSUPPORTED_FORMAT;
    }

    if(!checkVersion(qeIdentity)
        || !parseIssueDate(qeIdentity) || !parseNextUpdate(qeIdentity)
        || !parseMiscselect(qeIdentity) || !parseMiscselectMask(qeIdentity)
        || !parseAttributes(qeIdentity) || !parseAttributesMask(qeIdentity) || !parseMrsigner(qeIdentity)
        || !parseIsvprodid(qeIdentity) || !parseIsvsvn(qeIdentity))
    {
        return STATUS_SGX_QE_IDENTITY_INVALID;
    }

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    qeIdentity.Accept(writer);

    body = std::vector<uint8_t>{buffer.GetString(), &buffer.GetString()[buffer.GetSize()]};
    return STATUS_OK;
}

const std::vector<uint8_t>& QEIdentityJsonVerifier::getSignature() const
{
    return signature;
}

bool QEIdentityJsonVerifier::checkVersion(const ::rapidjson::Value &qeIdentity)
{
    static const int SUPPORTED_QE_IDENTITY_VERSION = 1;
    return parseVersion(qeIdentity) && version == SUPPORTED_QE_IDENTITY_VERSION;
}

const std::vector<uint8_t>& QEIdentityJsonVerifier::getQeIdentityBody() const
{
    return body;
}

const Status QEIdentityJsonVerifier::getStatus() const
{
    return status;
};

}}} // namespace intel { namespace sgx { namespace qvl {
