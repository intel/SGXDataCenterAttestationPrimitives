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

#include <QuoteVerification/QuoteConstants.h>
#include <OpensslHelpers/Bytes.h>
#include "EnclaveIdentityParser.h"
#include "EnclaveIdentityV1.h"
#include "EnclaveIdentityV2.h"

#include <tuple>
#include <memory>

namespace intel { namespace sgx { namespace qvl {

    std::unique_ptr<qvl::EnclaveIdentity> EnclaveIdentityParser::parse(const std::string &input)
    {
        if (!jsonParser.parse(input))
        {
            throw ParserException(STATUS_SGX_ENCLAVE_IDENTITY_UNSUPPORTED_FORMAT);
        }

        if (!jsonParser.getRoot()->IsObject())
        {
            throw ParserException(STATUS_SGX_ENCLAVE_IDENTITY_INVALID);
        }

        const auto* signature = jsonParser.getField("signature");

        if (signature == nullptr)
        {
            throw ParserException(STATUS_SGX_ENCLAVE_IDENTITY_UNSUPPORTED_FORMAT);
        }

        if(!signature->IsString() || signature->GetStringLength() != constants::ECDSA_P256_SIGNATURE_BYTE_LEN * 2)
        {
            throw ParserException(STATUS_SGX_ENCLAVE_IDENTITY_INVALID);
        }

        auto signatureBytes = hexStringToBytes(signature->GetString());

        unsigned int version = 0;
        bool status = false;

        // v1 qeidentity has a different field name for enclave identity body.
        // First check if it exists.
        auto identityField = jsonParser.getField("qeIdentity");
        if (identityField == nullptr)
        {
            // If not take new field
            identityField = jsonParser.getField("enclaveIdentity");
        }

        if (identityField == nullptr || !identityField->IsObject())
        {
            throw ParserException(STATUS_SGX_ENCLAVE_IDENTITY_INVALID);
        }

        std::tie(version, status) = jsonParser.getIntFieldOf(*identityField, "version");
        if (!status)
        {
            throw ParserException(STATUS_SGX_ENCLAVE_IDENTITY_INVALID);
        }

        switch(version)
        {
            case EnclaveIdentity::V1:
            {
                std::unique_ptr<qvl::EnclaveIdentity> identity = std::unique_ptr<qvl::EnclaveIdentityV1>(new EnclaveIdentityV1(*identityField)); // TODO make std::make_unique work in SGX enclave
                if (identity->getStatus() != STATUS_OK)
                {
                    throw ParserException(identity->getStatus());
                }
                identity->setSignature(signatureBytes);

                return identity;
            }
            case EnclaveIdentity::V2:
            {
                std::unique_ptr<qvl::EnclaveIdentity> identity = std::unique_ptr<qvl::EnclaveIdentityV2>(new EnclaveIdentityV2(*identityField)); // TODO make std::make_unique work in SGX enclave
                if (identity->getStatus() != STATUS_OK)
                {
                    throw ParserException(identity->getStatus());
                }
                identity->setSignature(signatureBytes);
                return identity;
            }
            default:
                throw ParserException(STATUS_SGX_ENCLAVE_IDENTITY_UNSUPPORTED_VERSION);
        }
    }

    Status ParserException::getStatus() const
    {
        return status;
    }
}}}