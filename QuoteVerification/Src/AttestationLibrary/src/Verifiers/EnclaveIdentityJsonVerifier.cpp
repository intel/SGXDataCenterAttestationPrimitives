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

#include "EnclaveIdentityJsonVerifier.h"
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

Status EnclaveIdentityJsonVerifier::parse(const std::string &input)
{
    if(!jsonParser.parse(input))
    {
        return STATUS_SGX_ENCLAVE_REPORT_UNSUPPORTED_FORMAT;
    }

    const Status bodyParseStatus = parseJson(*jsonParser.getRoot());
    if(bodyParseStatus != STATUS_OK)
    {
        return bodyParseStatus;
    }

    return STATUS_OK;
}

Status EnclaveIdentityJsonVerifier::parseJson(const ::rapidjson::Value &enclaveReport)
{
    if(!enclaveReport.IsObject())
    {
        return STATUS_SGX_ENCLAVE_REPORT_UNSUPPORTED_FORMAT;
    }

    if(!parseIssueDate(enclaveReport) || !parseNextUpdate(enclaveReport)
       || !parseMiscselect(enclaveReport) || !parseMiscselectMask(enclaveReport)
       || !parseAttributes(enclaveReport) || !parseAttributesMask(enclaveReport)
       || !parseVersion(enclaveReport) || !checkOptionalFields(enclaveReport))
    {
        return STATUS_SGX_ENCLAVE_IDENTITY_INVALID;
    }

    static const int SUPPORTED_ENLAVE_IDENTITY_VERSION = 1;
    if(version != SUPPORTED_ENLAVE_IDENTITY_VERSION)
    {
        return STATUS_SGX_ENCLAVE_IDENTITY_UNSUPPORTED_VERSION;
    }

    return STATUS_OK;
}

bool EnclaveIdentityJsonVerifier::checkOptionalFields(const rapidjson::Value &input)
{
    return parseMrenclave(input) | parseMrsigner(input) | parseIsvprodid(input) | parseIsvsvn(input);
}

}}} // namespace intel { namespace sgx { namespace qvl {
