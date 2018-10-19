/*
* Copyright (c) 2018, Intel Corporation
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

#ifndef SGXECDSAATTESTATION_SGXEXTENSION_H
#define SGXECDSAATTESTATION_SGXEXTENSION_H


#include <OpensslHelpers/Bytes.h>
#include <OpensslHelpers/OpensslTypes.h>
#include <openssl/asn1.h>

namespace intel { namespace sgx { namespace qvl { namespace pckparser {

class SgxExtension
{
public:
    enum class Type : int
    {
        NONE = -1,
        PPID = 0,
        CPUSVN,
        PCESVN,
        PCEID,
        FMSPC,
        SGX_TYPE,
        DYNAMIC_PLATFORM,
        CACHED_KEYS,
        TCB,
        SGX_TCB_COMP01_SVN,
        SGX_TCB_COMP02_SVN,
        SGX_TCB_COMP03_SVN,
        SGX_TCB_COMP04_SVN,
        SGX_TCB_COMP05_SVN,
        SGX_TCB_COMP06_SVN,
        SGX_TCB_COMP07_SVN,
        SGX_TCB_COMP08_SVN,
        SGX_TCB_COMP09_SVN,
        SGX_TCB_COMP10_SVN,
        SGX_TCB_COMP11_SVN,
        SGX_TCB_COMP12_SVN,
        SGX_TCB_COMP13_SVN,
        SGX_TCB_COMP14_SVN,
        SGX_TCB_COMP15_SVN,
        SGX_TCB_COMP16_SVN
    };

    SgxExtension();
    SgxExtension(const SgxExtension&);
    SgxExtension(SgxExtension&&) noexcept;
    SgxExtension(qvl::pckparser::SgxExtension::Type type,
                 std::vector<uint8_t> data,
                 const ASN1_TYPE& asn1Data,
                 std::vector<qvl::pckparser::SgxExtension> subsequence,
                 std::string oidStr);
    explicit SgxExtension(crypto::ASN1_TYPE_uptr asn1Object);

    static SgxExtension createFromRawSequence(const ASN1_TYPE& asn1Object, std::string oid);

    size_t size() const;
    bool empty() const;
    bool isSequence() const;
    Bytes asOctetString() const;
    bool asBool() const;
    uint64_t asUInt() const;
    int64_t asInt() const;
    const std::vector<SgxExtension>& asSequence() const;

    SgxExtension& operator=(const SgxExtension&);
    bool operator==(const SgxExtension&) const;
    bool operator!=(const SgxExtension&) const;

    Type type = Type::NONE;

private:
    static Bytes asn1TypeToBytes(const ASN1_TYPE& val);
    static std::vector<SgxExtension> sgxExtensionsFromSequence(const ASN1_TYPE& sequence);
    static std::vector<SgxExtension> getSGXExtensionSubsequence(const Type type, const ASN1_TYPE& sequence);
    static Bytes getSGXExtensionData(const Type &expectedType, const ASN1_TYPE& valueAsn1Type);
    static std::string getSGXExtensionsOID(const ASN1_TYPE& oidAsn1Type);

    std::vector<uint8_t> bytes {};
    crypto::ASN1_INTEGER_uptr asn1Integer = crypto::make_unique(ASN1_INTEGER_new());
    std::vector<SgxExtension> sequence {};
    std::string oidString {};
};


}}}} // namespace intel { namespace sgx { namespace qvl { namespace pckparser {

#endif //SGXECDSAATTESTATION_SGXEXTENSION_H
