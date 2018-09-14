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

#include <map>
#include <algorithm>
#include <sstream>
#include <OpensslHelpers/OpensslTypes.h>
#include "SgxExtension.h"
#include "FormatException.h"
#include "PckParserUtils.h"

namespace intel { namespace sgx { namespace qvl { namespace pckparser {



SgxExtension::SgxExtension()
{}

SgxExtension::SgxExtension(qvl::pckparser::SgxExtension::Type type,
                           std::vector<uint8_t> data,
                           const ASN1_TYPE& asn1Data,
                           std::vector<qvl::pckparser::SgxExtension> subsequence,
                           std::string oidStr)
        : type(type),  bytes(std::move(data)), asn1Data(asn1Data), sequence(std::move(subsequence)), oidString(std::move(oidStr))
{}

SgxExtension::SgxExtension(const ASN1_TYPE& asn1Object)
{
    if(asn1Object.type != V_ASN1_SEQUENCE)
    {
        std::stringstream ss;
        ss << "Unexpected type, expected [" << V_ASN1_SEQUENCE << "] given [" << asn1Object.type << "]";
        throw FormatException(ss.str());
    }

    const unsigned char *data = asn1Object.value.sequence->data;
    const auto stack = crypto::make_unique(
            d2i_ASN1_SEQUENCE_ANY(nullptr, &data, asn1Object.value.sequence->length));

    if(!stack)
    {
        throw FormatException("d2i_ASN1_SEQUENCE_ANY failed " + getLastError());
    }

    const auto stackEntries = sk_ASN1_TYPE_num(stack.get());
    if(stackEntries != 2)
    {
        std::stringstream ss;
        ss << "Invalid num of entries expected [2] given [" << stackEntries << "]";
        throw FormatException(ss.str());
    }

    const auto oidAsn1Type = sk_ASN1_TYPE_value(stack.get(), 0);

    oidString = getSGXExtensionsOID(*oidAsn1Type);
    type = oids::str2Type(oidString);
    if(type != SgxExtension::Type::NONE)
    {
        asn1Data = *sk_ASN1_TYPE_value(stack.get(), 1);
        bytes = getSGXExtensionData(type, asn1Data);
        sequence = getSGXExtensionSubsequence(type, asn1Data);
    }
}

SgxExtension SgxExtension::createFromRawSequence(const ASN1_TYPE& asn1Object, std::string oid)
{
    return SgxExtension(
            oids::str2Type(oid),
            asn1TypeToBytes(asn1Object),
            asn1Object,
            sgxExtensionsFromSequence(asn1Object),
            oid
    );
}

bool SgxExtension::operator==(const SgxExtension& other) const
{
    return
            type == other.type
            && oidString == other.oidString
            && bytes == other.bytes;
}

bool SgxExtension::operator!=(const SgxExtension& other) const
{
    return !(*this == other);
}

size_t SgxExtension::size() const
{
    return isSequence() ? sequence.size() : bytes.size();
}

bool SgxExtension::empty() const
{
    return bytes.empty();
}

bool SgxExtension::isSequence() const
{
    return !sequence.empty();
}

Bytes SgxExtension::asOctetString() const
{
    return bytes;
}

bool SgxExtension::asBool() const
{
    return bytes.at(0) != 0;
}

uint64_t SgxExtension::asUInt() const
{
    uint64_t retVal {};
    auto result = ASN1_INTEGER_get_uint64(&retVal, asn1Data.value.integer);
    if(result == 1)
    {
        return retVal;
    }
    throw FormatException("ASN1 integer conversion failed: " + getLastError());
}

int64_t SgxExtension::asInt() const
{
    int64_t retVal {};
    auto result = ASN1_INTEGER_get_int64(&retVal, asn1Data.value.integer);
    if(result == 1)
    {
        return retVal;
    }
    throw FormatException("ASN1 integer conversion failed: " + getLastError());
}

const std::vector<SgxExtension>& SgxExtension::asSequence() const
{
    return sequence;
}

std::string SgxExtension::getSGXExtensionsOID(const ASN1_TYPE& oidAsn1Type)
{
    if(oidAsn1Type.type != V_ASN1_OBJECT)
    {
        std::stringstream ss;
        ss << "Unexpected type of first value in sequence."
           << " Expected [" << V_ASN1_OBJECT << "] Given [" << oidAsn1Type.type << "]";

        throw FormatException(ss.str());
    }

    const std::string oidStr = obj2Str(oidAsn1Type.value.object);
    if(!oids::isCustomPckOid(oidStr))
    {
        const std::string str("Parsed OID [" + oidStr + "] does not match to any known SGX OID");
        throw FormatException(str);
    }
    return oidStr;
}

Bytes SgxExtension::asn1TypeToBytes(const ASN1_TYPE& val)
{
    Bytes data(static_cast<size_t>(val.value.octet_string->length));
    std::copy_n(
            val.value.octet_string->data,
            val.value.octet_string->length,
            data.begin());

    return data;
}

std::vector<SgxExtension> SgxExtension::sgxExtensionsFromSequence(const ASN1_TYPE& sequence)
{
    const unsigned char *data = sequence.value.sequence->data;
    const auto stack = crypto::make_unique(
            d2i_ASN1_SEQUENCE_ANY(nullptr, &data, sequence.value.sequence->length));

    if (!stack)
    {
        throw FormatException("d2i_ASN1_SEQUENCE_ANY failed to create stack" + getLastError());
    }

    const auto stackEntries = sk_ASN1_TYPE_num(stack.get());

    if (stackEntries == 0)
    {
        return {};
    }

    if (stackEntries < 0)
    {
        throw FormatException(getLastError());
    }


    std::vector<SgxExtension> subsequence(static_cast<size_t>(stackEntries));
    std::generate(subsequence.begin(), subsequence.end(),
                  [&stack]() { return SgxExtension(*sk_ASN1_TYPE_pop(stack.get())); });
    return subsequence;
}

std::vector<SgxExtension> SgxExtension::getSGXExtensionSubsequence(const Type type, const ASN1_TYPE& sequence)
{
    if(type == SgxExtension::Type::TCB)
    {
        return sgxExtensionsFromSequence(sequence);
    }
    return {};
}

Bytes SgxExtension::getSGXExtensionData(const Type& expectedType, const ASN1_TYPE& valueAsn1Type)
{
    // Second value in sequence should be of type:
    // OCTET_STRING for PPID, CPUSVN, PCEID, FMSPC
    // BOOLEAN      for DYNAMIC_PLATFORM, CHACHED_KEYS
    // ENUM         for SGX_TYPE
    // SEQUENCE     for TCB
    // INTEGER      for TCB_COMPXX_SVN, PCESVN

    if(expectedType == Type::PPID
       || expectedType == Type::CPUSVN
       || expectedType == Type::PCEID
       || expectedType == Type::FMSPC)
    {
        if(valueAsn1Type.type != V_ASN1_OCTET_STRING)
        {
            std::stringstream ss;
            ss  << oids::type2Description(expectedType) << " type expected [" << V_ASN1_OCTET_STRING
                << "] given [" << valueAsn1Type.type << "]";

            throw FormatException(ss.str());
        }
        return asn1TypeToBytes(valueAsn1Type);

    }
    else if(expectedType == Type::DYNAMIC_PLATFORM
            || expectedType == Type::CACHED_KEYS)
    {
        if(valueAsn1Type.type != V_ASN1_BOOLEAN)
        {
            std::stringstream ss;
            ss << oids::type2Description(expectedType) << " type expected [" << V_ASN1_BOOLEAN << "] given [" << valueAsn1Type.type << "]";

            throw FormatException(ss.str());
        }
        Bytes ret;
        ret.push_back(static_cast<uint8_t>(valueAsn1Type.value.boolean));
        return ret;
    }
    else if(expectedType == Type::SGX_TYPE)
    {
        if(valueAsn1Type.type != V_ASN1_ENUMERATED)
        {
            std::stringstream ss;
            ss << oids::type2Description(expectedType) << " type expected [" << V_ASN1_ENUMERATED
               << "] given [" << valueAsn1Type.type << "]";

            throw FormatException(ss.str());
        }
        return asn1TypeToBytes(valueAsn1Type);
    }
    else if(expectedType == Type::SGX_TCB_COMP01_SVN
            || expectedType == Type::SGX_TCB_COMP02_SVN
            || expectedType == Type::SGX_TCB_COMP03_SVN
            || expectedType == Type::SGX_TCB_COMP04_SVN
            || expectedType == Type::SGX_TCB_COMP05_SVN
            || expectedType == Type::SGX_TCB_COMP06_SVN
            || expectedType == Type::SGX_TCB_COMP07_SVN
            || expectedType == Type::SGX_TCB_COMP08_SVN
            || expectedType == Type::SGX_TCB_COMP09_SVN
            || expectedType == Type::SGX_TCB_COMP10_SVN
            || expectedType == Type::SGX_TCB_COMP11_SVN
            || expectedType == Type::SGX_TCB_COMP12_SVN
            || expectedType == Type::SGX_TCB_COMP13_SVN
            || expectedType == Type::SGX_TCB_COMP14_SVN
            || expectedType == Type::SGX_TCB_COMP15_SVN
            || expectedType == Type::SGX_TCB_COMP16_SVN
            || expectedType == Type::PCESVN)
    {
        if(valueAsn1Type.type != V_ASN1_INTEGER)
        {
            std::stringstream ss;
            ss << oids::type2Description(expectedType) << " type expected [" << V_ASN1_INTEGER
               << "] given [" << valueAsn1Type.type << "]";

            throw FormatException(ss.str());
        }
        return asn1TypeToBytes(valueAsn1Type);
    }
    else if(expectedType == Type::TCB)
    {
        if(valueAsn1Type.type != V_ASN1_SEQUENCE)
        {
            std::stringstream ss;
            ss << oids::type2Description(expectedType) << " type expected [" << V_ASN1_SEQUENCE
               << "] given [" << valueAsn1Type.type << "]";

            throw FormatException(ss.str());
        }
        return asn1TypeToBytes(valueAsn1Type);
    }

    // we want to get data of type we do not support
    // not really an error, just incorrect usage of internal function
    return {};
}

}}}} // namespace intel { namespace sgx { namespace qvl { namespace pckparser {
