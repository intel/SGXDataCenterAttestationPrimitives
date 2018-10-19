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


#ifndef INTEL_SGX_QVL_TEST_CERTCRLMOCKS_H_
#define INTEL_SGX_QVL_TEST_CERTCRLMOCKS_H_

#include <gmock/gmock.h>
#include <Constants/X509TestConstants.h>

#include <PckParser/CertStore.h>
#include <PckParser/CrlStore.h>
#include <PckParser/PckParser.h>
#include <OpensslHelpers/OpensslTypes.h>
#include <CertVerification/CertificateChain.h>

// Gmock will try to print these out and fail, as the implementation is within OpenSSL internal headers.
static void PrintTo(const x509_st &x, ::std::ostream *os)      { *os << "x509_st at [" << std::hex << &x << std::dec << "]";     }
static void PrintTo(const X509_crl_st &x, ::std::ostream *os)  { *os << "X509_crl_st at [" << std::hex << &x << std::dec << "]"; }
static void PrintTo(const ec_key_st &x, ::std::ostream *os)    { *os << "ec_key_st at [" << std::hex << &x << std::dec << "]";   }

namespace intel { namespace sgx { namespace qvl { namespace test {

class CertStoreMock: public qvl::pckparser::CertStore
{
public:
    MOCK_METHOD1(parse, bool(const std::string&));
    
    MOCK_CONST_METHOD0(expired, bool());
    MOCK_CONST_METHOD0(getSubject, const qvl::pckparser::Subject&());
    MOCK_CONST_METHOD0(getIssuer, const qvl::pckparser::Issuer&());
    MOCK_CONST_METHOD0(getSerialNumber, const std::vector<uint8_t>&());
    MOCK_CONST_METHOD0(getSignature, const qvl::pckparser::Signature&());
    MOCK_CONST_METHOD0(getExtensions, const std::vector<qvl::pckparser::Extension>&());
    MOCK_CONST_METHOD0(getSGXExtensions, const std::vector<qvl::pckparser::SgxExtension>&());

    MOCK_CONST_METHOD0(getCert, X509&());
    MOCK_CONST_METHOD0(getPubKey, EC_KEY&());
};

class CrlStoreMock: public qvl::pckparser::CrlStore
{
public:
    MOCK_METHOD1(parse, bool(const std::string&));

    MOCK_CONST_METHOD0(expired, bool());
    MOCK_CONST_METHOD0(getIssuer, const qvl::pckparser::Issuer&());
    MOCK_CONST_METHOD0(getSignature, const qvl::pckparser::Signature&());
    MOCK_CONST_METHOD0(getExtensions, const std::vector<qvl::pckparser::Extension>&());
    MOCK_CONST_METHOD0(getRevoked, const std::vector<qvl::pckparser::Revoked>&());
    MOCK_CONST_METHOD1(isRevoked, bool(const qvl::pckparser::CertStore&));
    MOCK_CONST_METHOD0(getCrl, X509_CRL&());
};

class CertificateChainMock: public qvl::CertificateChain
{
public:
    MOCK_METHOD1(parse, bool(const std::string&));

    MOCK_CONST_METHOD0(length, unsigned long());
    MOCK_CONST_METHOD1(get, std::shared_ptr<const pckparser::CertStore>(const qvl::pckparser::Subject&));
    MOCK_CONST_METHOD0(getRootCert, std::shared_ptr<const pckparser::CertStore>());
    MOCK_CONST_METHOD0(getIntermediateCert, std::shared_ptr<const pckparser::CertStore>());
    MOCK_CONST_METHOD0(getTopmostCert, std::shared_ptr<const pckparser::CertStore>());
};

}}}} // namespace intel { namespace sgx { namespace qvl { namespace test {

#endif //INTEL_SGX_QVL_TEST_CERTCRLMOCKS_H_
