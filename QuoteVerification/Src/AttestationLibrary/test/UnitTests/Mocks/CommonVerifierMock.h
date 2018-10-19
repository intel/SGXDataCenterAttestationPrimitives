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

#ifndef INTEL_SGX_QVL_TEST_COMMON_VERIFIER_H_
#define INTEL_SGX_QVL_TEST_COMMON_VERIFIER_H_

#include <gmock/gmock.h>
#include <Verifiers/CommonVerifier.h>

namespace intel { namespace sgx { namespace qvl { namespace test {

class CommonVerifierMock : public qvl::CommonVerifier
{
public:
    MOCK_CONST_METHOD1(verifyRootCACert, Status(const pckparser::CertStore&));
   
    MOCK_CONST_METHOD2(verifyIntermediate, Status(
                const pckparser::CertStore&,
                const pckparser::CertStore&));
   
    MOCK_CONST_METHOD2(checkStandardExtensions, bool(
                const std::vector<pckparser::Extension>&,
                const std::vector<int>&));

    MOCK_CONST_METHOD2(checkSGXExtensions, bool(
            const std::vector<pckparser::SgxExtension>&,
            const std::vector<pckparser::SgxExtension::Type>&));

    MOCK_CONST_METHOD2(checkSignature, bool(
            const pckparser::CertStore&,
            const pckparser::CertStore&));

    MOCK_CONST_METHOD2(checkSignature, bool(
            const pckparser::CrlStore&,
            const pckparser::CertStore&));

    MOCK_CONST_METHOD3(checkSha256EcdsaSignature, bool(
            const Bytes&,
            const std::vector<uint8_t>&,
            const EC_KEY&));


};

}}}}// namespace intel { namespace sgx { namespace qvl { namespace test {

#endif
