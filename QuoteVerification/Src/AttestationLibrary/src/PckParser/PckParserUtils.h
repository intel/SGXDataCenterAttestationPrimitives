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

#ifndef SGXECDSAATTESTATION_PCKPARSERUTILS_H
#define SGXECDSAATTESTATION_PCKPARSERUTILS_H

#include <cstring>
#include <string>
#include <openssl/ossl_typ.h>
#include <map>
#include "SgxExtension.h"

namespace intel { namespace sgx { namespace qvl { namespace pckparser {

std::string obj2Str(const ASN1_OBJECT* obj);
std::string getLastError();

namespace oids
{

const std::string SGX_EXTENSION = "1.2.840.113741.1.13.1";
const std::string TCB = SGX_EXTENSION + ".2";
const std::string PPID = SGX_EXTENSION + ".1";
const std::string SGX_TCB_COMP01_SVN = TCB + ".1";
const std::string SGX_TCB_COMP02_SVN = TCB + ".2";
const std::string SGX_TCB_COMP03_SVN = TCB + ".3";
const std::string SGX_TCB_COMP04_SVN = TCB + ".4";
const std::string SGX_TCB_COMP05_SVN = TCB + ".5";
const std::string SGX_TCB_COMP06_SVN = TCB + ".6";
const std::string SGX_TCB_COMP07_SVN = TCB + ".7";
const std::string SGX_TCB_COMP08_SVN = TCB + ".8";
const std::string SGX_TCB_COMP09_SVN = TCB + ".9";
const std::string SGX_TCB_COMP10_SVN = TCB + ".10";
const std::string SGX_TCB_COMP11_SVN = TCB + ".11";
const std::string SGX_TCB_COMP12_SVN = TCB + ".12";
const std::string SGX_TCB_COMP13_SVN = TCB + ".13";
const std::string SGX_TCB_COMP14_SVN = TCB + ".14";
const std::string SGX_TCB_COMP15_SVN = TCB + ".15";
const std::string SGX_TCB_COMP16_SVN = TCB + ".16";
const std::string PCESVN = TCB + ".17";
const std::string CPUSVN = TCB + ".18";
const std::string PCEID = SGX_EXTENSION + ".3";
const std::string FMSPC = SGX_EXTENSION + ".4";
const std::string SGX_TYPE = SGX_EXTENSION + ".5"; // ASN1 Enumerated
const std::string DYNAMIC_PLATFORM = SGX_EXTENSION + ".6"; // ASN1 Boolean
const std::string CACHED_KEYS = SGX_EXTENSION + ".7"; // ASN1 Boolean

static const std::map<std::string, std::string> oidToDesc = {
        {SGX_EXTENSION,      "SGX_EXTENSION"},
        {PPID,               "PPID"},
        {CPUSVN,             "CPUSVN"},
        {PCESVN,             "PCESVN"},
        {PCEID,              "PCEID"},
        {FMSPC,              "FMSPC"},
        {SGX_TYPE,           "SGX_TYPE"},
        {DYNAMIC_PLATFORM,   "DYNAMIC_PLATFORM"},
        {CACHED_KEYS,        "CACHED_KEYS"},
        {TCB,                "TCB"},
        {SGX_TCB_COMP01_SVN, "SGX_TCB_COMP01_SVN"},
        {SGX_TCB_COMP02_SVN, "SGX_TCB_COMP02_SVN"},
        {SGX_TCB_COMP03_SVN, "SGX_TCB_COMP03_SVN"},
        {SGX_TCB_COMP04_SVN, "SGX_TCB_COMP04_SVN"},
        {SGX_TCB_COMP05_SVN, "SGX_TCB_COMP05_SVN"},
        {SGX_TCB_COMP06_SVN, "SGX_TCB_COMP06_SVN"},
        {SGX_TCB_COMP07_SVN, "SGX_TCB_COMP07_SVN"},
        {SGX_TCB_COMP08_SVN, "SGX_TCB_COMP08_SVN"},
        {SGX_TCB_COMP09_SVN, "SGX_TCB_COMP09_SVN"},
        {SGX_TCB_COMP10_SVN, "SGX_TCB_COMP10_SVN"},
        {SGX_TCB_COMP11_SVN, "SGX_TCB_COMP11_SVN"},
        {SGX_TCB_COMP12_SVN, "SGX_TCB_COMP12_SVN"},
        {SGX_TCB_COMP13_SVN, "SGX_TCB_COMP13_SVN"},
        {SGX_TCB_COMP14_SVN, "SGX_TCB_COMP14_SVN"},
        {SGX_TCB_COMP15_SVN, "SGX_TCB_COMP15_SVN"},
        {SGX_TCB_COMP16_SVN, "SGX_TCB_COMP16_SVN"}
};

static const std::map<std::string, SgxExtension::Type> oidStrToEnum = {
        {SGX_EXTENSION,      SgxExtension::Type::NONE},
        {PPID,               SgxExtension::Type::PPID},
        {CPUSVN,             SgxExtension::Type::CPUSVN},
        {PCESVN,             SgxExtension::Type::PCESVN},
        {PCEID,              SgxExtension::Type::PCEID},
        {FMSPC,              SgxExtension::Type::FMSPC},
        {SGX_TYPE,           SgxExtension::Type::SGX_TYPE},
        {DYNAMIC_PLATFORM,   SgxExtension::Type::DYNAMIC_PLATFORM},
        {CACHED_KEYS,        SgxExtension::Type::CACHED_KEYS},
        {TCB,                SgxExtension::Type::TCB},
        {SGX_TCB_COMP01_SVN, SgxExtension::Type::SGX_TCB_COMP01_SVN},
        {SGX_TCB_COMP02_SVN, SgxExtension::Type::SGX_TCB_COMP02_SVN},
        {SGX_TCB_COMP03_SVN, SgxExtension::Type::SGX_TCB_COMP03_SVN},
        {SGX_TCB_COMP04_SVN, SgxExtension::Type::SGX_TCB_COMP04_SVN},
        {SGX_TCB_COMP05_SVN, SgxExtension::Type::SGX_TCB_COMP05_SVN},
        {SGX_TCB_COMP06_SVN, SgxExtension::Type::SGX_TCB_COMP06_SVN},
        {SGX_TCB_COMP07_SVN, SgxExtension::Type::SGX_TCB_COMP07_SVN},
        {SGX_TCB_COMP08_SVN, SgxExtension::Type::SGX_TCB_COMP08_SVN},
        {SGX_TCB_COMP09_SVN, SgxExtension::Type::SGX_TCB_COMP09_SVN},
        {SGX_TCB_COMP10_SVN, SgxExtension::Type::SGX_TCB_COMP10_SVN},
        {SGX_TCB_COMP11_SVN, SgxExtension::Type::SGX_TCB_COMP11_SVN},
        {SGX_TCB_COMP12_SVN, SgxExtension::Type::SGX_TCB_COMP12_SVN},
        {SGX_TCB_COMP13_SVN, SgxExtension::Type::SGX_TCB_COMP13_SVN},
        {SGX_TCB_COMP14_SVN, SgxExtension::Type::SGX_TCB_COMP14_SVN},
        {SGX_TCB_COMP15_SVN, SgxExtension::Type::SGX_TCB_COMP15_SVN},
        {SGX_TCB_COMP16_SVN, SgxExtension::Type::SGX_TCB_COMP16_SVN}
};

static const std::map<SgxExtension::Type, std::string> oidEnumToDescription = {
        {SgxExtension::Type::NONE,               "NONE"},
        {SgxExtension::Type::PPID,               "PPID"},
        {SgxExtension::Type::CPUSVN,             "CPUSVN"},
        {SgxExtension::Type::PCESVN,             "PCESVN"},
        {SgxExtension::Type::PCEID,              "PCEID"},
        {SgxExtension::Type::FMSPC,              "FMSPC"},
        {SgxExtension::Type::SGX_TYPE,           "SGX_TYPE"},
        {SgxExtension::Type::DYNAMIC_PLATFORM,   "DYNAMIC_PLATFORM"},
        {SgxExtension::Type::CACHED_KEYS,        "CACHED_KEYS"},
        {SgxExtension::Type::TCB,                "TCB"},
        {SgxExtension::Type::SGX_TCB_COMP01_SVN, "SGX_TCB_COMP01_SVN"},
        {SgxExtension::Type::SGX_TCB_COMP02_SVN, "SGX_TCB_COMP02_SVN"},
        {SgxExtension::Type::SGX_TCB_COMP03_SVN, "SGX_TCB_COMP03_SVN"},
        {SgxExtension::Type::SGX_TCB_COMP04_SVN, "SGX_TCB_COMP04_SVN"},
        {SgxExtension::Type::SGX_TCB_COMP05_SVN, "SGX_TCB_COMP05_SVN"},
        {SgxExtension::Type::SGX_TCB_COMP06_SVN, "SGX_TCB_COMP06_SVN"},
        {SgxExtension::Type::SGX_TCB_COMP07_SVN, "SGX_TCB_COMP07_SVN"},
        {SgxExtension::Type::SGX_TCB_COMP08_SVN, "SGX_TCB_COMP08_SVN"},
        {SgxExtension::Type::SGX_TCB_COMP09_SVN, "SGX_TCB_COMP09_SVN"},
        {SgxExtension::Type::SGX_TCB_COMP10_SVN, "SGX_TCB_COMP10_SVN"},
        {SgxExtension::Type::SGX_TCB_COMP11_SVN, "SGX_TCB_COMP11_SVN"},
        {SgxExtension::Type::SGX_TCB_COMP12_SVN, "SGX_TCB_COMP12_SVN"},
        {SgxExtension::Type::SGX_TCB_COMP13_SVN, "SGX_TCB_COMP13_SVN"},
        {SgxExtension::Type::SGX_TCB_COMP14_SVN, "SGX_TCB_COMP14_SVN"},
        {SgxExtension::Type::SGX_TCB_COMP15_SVN, "SGX_TCB_COMP15_SVN"},
        {SgxExtension::Type::SGX_TCB_COMP16_SVN, "SGX_TCB_COMP16_SVN"}
};

inline bool isCustomPckOid(const std::string& oid)
{
    return oidStrToEnum.find(oid) != oidStrToEnum.end();
}

inline SgxExtension::Type str2Type(const std::string& oid)
{
    return oidStrToEnum.at(oid);
}

inline std::string type2Description(const SgxExtension::Type& type)
{
    return oidEnumToDescription.at(type);
}

}; //namespace oids

}}}} // namespace intel { namespace sgx { namespace qvl { namespace pckparser {

#endif //SGXECDSAATTESTATION_PCKPARSERUTILS_H
