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


#ifndef SGX_INTEL_QVL_CERTSTORE_H_
#define SGX_INTEL_QVL_CERTSTORE_H_

#include "PckParser.h"

#include <OpensslHelpers/OpensslTypes.h>

namespace intel { namespace sgx { namespace qvl { namespace pckparser {

class CertStore
{
public:
    CertStore();
    CertStore(const CertStore&) = delete;
    CertStore(CertStore&&) = default;
    virtual ~CertStore() = default;

    CertStore& operator=(const CertStore&) = delete;
    CertStore& operator=(CertStore&&) = default;
    bool operator==(const CertStore& other) const;
    bool operator!=(const CertStore& other) const;

    virtual bool parse(const std::string& pemCert);

    virtual bool expired() const;
    virtual const std::vector<uint8_t>& getSerialNumber() const;
    virtual const Subject& getSubject() const;
    virtual const Issuer& getIssuer() const;
    virtual const Validity& getValidity() const;
    virtual const std::vector<Extension>& getExtensions() const;
    virtual const std::vector<SgxExtension>& getSGXExtensions() const;
    virtual const Signature& getSignature() const;
    virtual const EC_KEY& getPubKey() const;
    virtual const X509& getCert() const;

private:
    crypto::X509_uptr _x509;
    crypto::EC_KEY_uptr _pubKey;

    Subject _subject;
    Issuer _issuer;
    Validity _validity;
    std::vector<uint8_t> _serialNumber;
    std::vector<Extension> _extensions;
    std::vector<SgxExtension> _sgxExtensions;
    Signature _signature;  
};

}}}} // namespace intel { namespace sgx { namespace qvl { namespace pckparser {

#endif // SGX_INTEL_QVL_CERTSTORE_H_
