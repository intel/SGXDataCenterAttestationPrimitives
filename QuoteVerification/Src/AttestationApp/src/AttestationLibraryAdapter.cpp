/*
* Copyright (c) 2017, Intel Corporation
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

#include "AttestationLibraryAdapter.h"

#include <array>

namespace intel { namespace sgx { namespace qvl {
std::string AttestationLibraryAdapter::getVersion() const
{
    return ::sgxAttestationGetVersion();
}

Status AttestationLibraryAdapter::verifyQuote(const std::vector<uint8_t>& quote, const std::string& pckCertChain,
    const std::string& pckCrl, const std::string& tcbInfo) const
{
    return ::sgxAttestationVerifyQuote(quote.data(), quote.size(), pckCertChain.c_str(), pckCrl.c_str(), tcbInfo.c_str());
}

Status AttestationLibraryAdapter::verifyPCKCertificate(const std::string& pemCertChain, const std::string& pemRootCaCRL,
    const std::string& intermediateCaCRL, const std::string& pemTrustedRootCaCertificate) const
{
    const std::array<const char*, 2> crls{{pemRootCaCRL.data(), intermediateCaCRL.data()}};
    return ::sgxAttestationVerifyPCKCertificate(pemCertChain.c_str(), crls.data(), pemTrustedRootCaCertificate.c_str());
}

Status AttestationLibraryAdapter::verifyTCBInfo(const std::string& tcbInfo, const std::string& pemSigningChain,
    const std::string& pemRootCaCrl, const std::string& pemTrustedRootCaCertificate) const
{
    return ::sgxAttestationVerifyTCBInfo(tcbInfo.c_str(), pemSigningChain.c_str(), pemRootCaCrl.c_str(), pemTrustedRootCaCertificate.c_str());
}
}}}
