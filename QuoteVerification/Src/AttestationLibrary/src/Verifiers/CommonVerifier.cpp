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


#include "CommonVerifier.h"

#include <CertVerification/X509Constants.h>
#include <OpensslHelpers/SignatureVerification.h>

#include <algorithm>

namespace intel { namespace sgx { namespace qvl {

bool CommonVerifier::checkStandardExtensions(const std::vector<pckparser::Extension> &presentExtensions, const std::vector<int> &opensslExtensionNids) const
{
    if(opensslExtensionNids.size() > presentExtensions.size())
    {
        return false;
    }

    for(const auto &requiredNid : opensslExtensionNids)
    {
        const auto found = std::find_if(presentExtensions.begin(),
                                        presentExtensions.end(),
                                        [&requiredNid](const pckparser::Extension &ext){
                                            return ext.opensslNid == requiredNid; 
                                        });
        
        if(found == presentExtensions.end())
        {
            return false;
        }
    }

    return true;
}

bool CommonVerifier::checkSGXExtensions(const std::vector<pckparser::SgxExtension> &presentSgxExtensions,
                                        const std::vector<pckparser::SgxExtension::Type> &requiredSgxExtensions) const
{
    if(requiredSgxExtensions.size() > presentSgxExtensions.size())
    {
        return false;
    }

    for(const auto &requiredSgxExtension : requiredSgxExtensions)
    {
        const auto found = std::find_if(presentSgxExtensions.begin(),
                                        presentSgxExtensions.end(),
                                        [&requiredSgxExtension](const pckparser::SgxExtension &ext){
                                            return ext.type == requiredSgxExtension;
                                        });

        if(found == presentSgxExtensions.end() || !checkValueFormat(*found))
        {
            return false;
        }
        if(found->type == pckparser::SgxExtension::Type::TCB
           && !checkSGXExtensions(found->asSequence(), constants::TCB_REQUIRED_SGX_EXTENSIONS))
        {
            return false;
        }

    }

    return true;
}

bool CommonVerifier::checkValueFormat(const pckparser::SgxExtension& ext) const
{
    switch(ext.type)
    {
        case pckparser::SgxExtension::Type::PPID:
            return ext.size() == constants::PPID_BYTE_LEN;
        case pckparser::SgxExtension::Type::CPUSVN:
            return ext.size() == constants::CPUSVN_BYTE_LEN;
        case pckparser::SgxExtension::Type::PCEID:
            return ext.size() == constants::PCEID_BYTE_LEN;
        case pckparser::SgxExtension::Type::FMSPC:
            return ext.size() == constants::FMSPC_BYTE_LEN;
        case pckparser::SgxExtension::Type::SGX_TYPE:
            return ext.size() == constants::SGX_TYPE_BYTE_LEN;
        case pckparser::SgxExtension::Type::DYNAMIC_PLATFORM:
            return ext.size() == constants::DYNAMIC_PLATFORM_BYTE_LEN;
        case pckparser::SgxExtension::Type::CACHED_KEYS:
            return ext.size() == constants::CACHED_KEYS_BYTE_LEN;
        case pckparser::SgxExtension::Type::TCB:
            return ext.size() == constants::TCB_SEQUENCE_LEN;
        case pckparser::SgxExtension::Type::SGX_TCB_COMP01_SVN:
        case pckparser::SgxExtension::Type::SGX_TCB_COMP02_SVN:
        case pckparser::SgxExtension::Type::SGX_TCB_COMP03_SVN:
        case pckparser::SgxExtension::Type::SGX_TCB_COMP04_SVN:
        case pckparser::SgxExtension::Type::SGX_TCB_COMP05_SVN:
        case pckparser::SgxExtension::Type::SGX_TCB_COMP06_SVN:
        case pckparser::SgxExtension::Type::SGX_TCB_COMP07_SVN:
        case pckparser::SgxExtension::Type::SGX_TCB_COMP08_SVN:
        case pckparser::SgxExtension::Type::SGX_TCB_COMP09_SVN:
        case pckparser::SgxExtension::Type::SGX_TCB_COMP10_SVN:
        case pckparser::SgxExtension::Type::SGX_TCB_COMP11_SVN:
        case pckparser::SgxExtension::Type::SGX_TCB_COMP12_SVN:
        case pckparser::SgxExtension::Type::SGX_TCB_COMP13_SVN:
        case pckparser::SgxExtension::Type::SGX_TCB_COMP14_SVN:
        case pckparser::SgxExtension::Type::SGX_TCB_COMP15_SVN:
        case pckparser::SgxExtension::Type::SGX_TCB_COMP16_SVN:
        case pckparser::SgxExtension::Type::PCESVN:
            return ext.size() > 0;
        case pckparser::SgxExtension::Type::NONE:
            return true;
    }
    // default
    return true;
}

Status CommonVerifier::verifyRootCACert(const pckparser::CertStore &rootCa) const
{

    if(rootCa.expired())
    {
        return STATUS_SGX_ROOT_CA_INVALID;
    }

    if(!checkStandardExtensions(rootCa.getExtensions(), constants::ROOT_CA_REQUIRED_EXTENSIONS))
    {
        return STATUS_SGX_ROOT_CA_INVALID_EXTENSIONS;
    }

    if(rootCa.getIssuer() != rootCa.getSubject()
        || !crypto::verifySignature(rootCa, rootCa.getPubKey()))
    {
        return STATUS_SGX_ROOT_CA_INVALID_ISSUER;
    }

    return STATUS_OK;
}

Status CommonVerifier::verifyIntermediate(const pckparser::CertStore &intermediate, const pckparser::CertStore &root) const
{
    if(intermediate.expired())
    {
        return STATUS_SGX_INTERMEDIATE_CA_INVALID;
    }

    if(!checkStandardExtensions(intermediate.getExtensions(), constants::INTERMEDIATE_REQUIRED_EXTENSIONS))
    {
        return STATUS_SGX_INTERMEDIATE_CA_INVALID_EXTENSIONS;
    }

    if(intermediate.getIssuer() != root.getSubject()
        || !crypto::verifySignature(intermediate, root.getPubKey()))
    {
        return STATUS_SGX_INTERMEDIATE_CA_INVALID_ISSUER;
    }

    return STATUS_OK;
}

bool CommonVerifier::checkSignature(const pckparser::CertStore &pckCert, const pckparser::CertStore &intermediate) const
{
    return crypto::verifySignature(pckCert, intermediate.getPubKey());
}

bool CommonVerifier::checkSignature(const pckparser::CrlStore &crl, const pckparser::CertStore &crlIssuer) const
{
    return crypto::verifySignature(crl, crlIssuer.getPubKey());
}

bool CommonVerifier::checkSha256EcdsaSignature(const Bytes &signature, const std::vector<uint8_t> &message,
                                               const EC_KEY &publicKey) const {
    return crypto::verifySha256EcdsaSignature(signature, message, publicKey);
}

}}} // namespace intel { namespace sgx { namespace qvl {

