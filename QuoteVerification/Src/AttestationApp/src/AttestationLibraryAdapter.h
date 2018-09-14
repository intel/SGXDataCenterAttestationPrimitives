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

#ifndef SGXECDSAATTESTATION_ATTESTATIONLIBRARYADAPTER_H
#define SGXECDSAATTESTATION_ATTESTATIONLIBRARYADAPTER_H

#include "IAttestationLibraryAdapter.h"

namespace intel { namespace sgx { namespace qvl {

class AttestationLibraryAdapter : public IAttestationLibraryAdapter
{
public:
    std::string getVersion() const override;
    Status verifyQuote(const std::vector<uint8_t>& quote, const std::string& pckCertChain, const std::string& pckCrl,
        const std::string& tcbInfo) const override;
    Status verifyPCKCertificate(const std::string& pemCertChain, const std::string& pemRootCaCRL, const std::string& intermediateCaCRL,
        const std::string& pemTrustedRootCaCertificate) const override;
    Status verifyTCBInfo(const std::string& tcbInfo, const std::string& pemSigningChain, const std::string& pemRootCaCrl,
        const std::string& pemtrustedRpemTrustedRootCaCertificateootCaCertificate) const override;
};

}}}

#endif //SGXECDSAATTESTATION_ATTESTATIONLIBRARYADAPTER_H
