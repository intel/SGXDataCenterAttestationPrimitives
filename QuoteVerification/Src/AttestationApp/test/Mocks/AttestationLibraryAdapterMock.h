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

#ifndef SGXECDSAATTESTATION_ATTESTATIONLIBRARYADAPTERMOCK_H
#define SGXECDSAATTESTATION_ATTESTATIONLIBRARYADAPTERMOCK_H

#include <IAttestationLibraryAdapter.h>
#include <gmock/gmock.h>

namespace intel { namespace sgx { namespace qvl { namespace test {

class AttestationLibraryAdapterMock : public qvl::IAttestationLibraryAdapter
{
public:
    MOCK_CONST_METHOD0(getVersion, std::string());
    MOCK_CONST_METHOD4(verifyQuote, Status(const std::vector<uint8_t>&, const std::string&, const std::string&, const std::string&));
    MOCK_CONST_METHOD4(verifyPCKCertificate, Status(const std::string&, const std::string&, const std::string&, const std::string&));
    MOCK_CONST_METHOD4(verifyTCBInfo, Status(const std::string&, const std::string&, const std::string&, const std::string&));
};
}}}}

#endif //SGXECDSAATTESTATION_ATTESTATIONLIBRARYADAPTERMOCK_H
