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

#ifndef SGXECDSAATTESTATION_TCBINFO_JSON_VERIFIER_H
#define SGXECDSAATTESTATION_TCBINFO_JSON_VERIFIER_H

#include <rapidjson/fwd.h>

#include <string>
#include <vector>

#include <SgxEcdsaAttestation/QuoteVerification.h>
#include <set>
#include <Utils/JsonParser.h>

namespace intel { namespace sgx { namespace qvl {

class TCBInfoJsonVerifier {
public:
    struct TcbLevel
    {
        const std::vector<uint8_t> cpusvn;
        const unsigned int pcesvn;
        const std::string status;

        bool operator>(const TcbLevel& other) const
        {
            if(cpusvn == other.cpusvn)
            {
                return pcesvn > other.pcesvn;
            }
            return isGreater(other.cpusvn);
        }

        bool isGreater(const std::vector<uint8_t>& other) const
        {
            for (int i = 0; i < cpusvn.size(); ++i)
            {
                if (other[i] < cpusvn[i])
                {
                    // if other has at least one lower value then other is lower
                    return true;
                }
            }
            return false;
        }
    };

    TCBInfoJsonVerifier() = default;
    virtual ~TCBInfoJsonVerifier() = default;

    TCBInfoJsonVerifier(const TCBInfoJsonVerifier&) = default;
    TCBInfoJsonVerifier(TCBInfoJsonVerifier&&) = default;

    TCBInfoJsonVerifier& operator=(const TCBInfoJsonVerifier&) = default;
    TCBInfoJsonVerifier& operator=(TCBInfoJsonVerifier&&) = default;

    virtual Status parse(const std::string& tcbInfo);

    virtual const std::vector<uint8_t>& getInfoBody() const;
    virtual const std::vector<uint8_t>& getSignature() const;

    virtual const std::vector<uint8_t>& getFmspc() const;
    virtual const std::vector<uint8_t>& getPceId() const;
    virtual const std::set<TCBInfoJsonVerifier::TcbLevel, std::greater<>>& getTcbLevels() const;

private:
    Status parseTCBInfo(const ::rapidjson::Value& tcbInfo);
    bool parseFmspc(const ::rapidjson::Value& tcbInfo);
    bool parsePceId(const ::rapidjson::Value& tcbInfo);
    bool checkVersion(const ::rapidjson::Value& tcbInfo) const;
    bool parseTcbLevels(const ::rapidjson::Value& tcbInfo);
    bool parseTcbLevel(const ::rapidjson::Value& tcbLevel);
    std::string extractTcbLevelStatus(const ::rapidjson::Value& tcbLevel) const;
    std::vector<uint8_t> extractTcbLevelCpusvn(const ::rapidjson::Value& tcb) const;

    JsonParser jsonParser;
    std::vector<uint8_t> tcbInfoBody;
    std::vector<uint8_t> tcbInfoSignature;
    std::vector<uint8_t> fmspc;
    std::vector<uint8_t> pceId;
    std::set<TcbLevel, std::greater<>> tcbs;

};

}}} // namespace intel { namespace sgx { namespace qvl {

#endif //SGXECDSAATTESTATION_TCBINFO_JSON_VERIFIER_H
