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


#include "CertStore.h"
#include "FormatException.h"
#include <OpensslHelpers/Assert.h>

namespace intel { namespace sgx { namespace qvl { namespace pckparser {

CertStore::CertStore()
    : _x509{crypto::make_unique(X509_new())},
      _pubKey{crypto::make_unique(EC_KEY_new())},
      _subject{},
      _issuer{},
      _validity{},
      _extensions{},
      _sgxExtensions{},
      _signature{}
{
}

bool CertStore::operator==(const CertStore& other) const
{
    return (X509_cmp(&getCert(), &other.getCert()) == 0);
}

bool CertStore::operator!=(const CertStore& other) const
{
    return !(*this == other);
}

bool CertStore::parse(const std::string& pemCert)
{
    try
    {
        _x509 = pemBuffCert2X509(pemCert);
        QVL_ASSERT(_x509);
       
        _serialNumber = pckparser::getSerialNumber(*_x509);
        _pubKey = pckparser::getPubKey(*_x509);
        _subject = pckparser::getSubject(*_x509);
        _issuer = pckparser::getIssuer(*_x509);
        _validity = pckparser::getValidity(*_x509);
        _extensions = pckparser::getExtensions(*_x509);
        _sgxExtensions = pckparser::getSGXExtensions(_extensions);
        _signature = pckparser::getSignature(*_x509);
    }
    catch(const FormatException&)
    {
        return false;
    }

    return true;
}

bool CertStore::expired() const
{
    return not _validity.isValid();
}

const Subject& CertStore::getSubject() const
{
    return _subject;
}

const Issuer& CertStore::getIssuer() const
{
    return _issuer;
}

const Validity& CertStore::getValidity() const
{
    return _validity;
}

const std::vector<Extension>& CertStore::getExtensions() const
{
    return _extensions;
}

const std::vector<SgxExtension>& CertStore::getSGXExtensions() const
{
    return _sgxExtensions;
}

const Signature& CertStore::getSignature() const
{
    return _signature;
}

const std::vector<uint8_t>& CertStore::getSerialNumber() const
{
    return _serialNumber;
}

const EC_KEY& CertStore::getPubKey() const
{
    QVL_ASSERT(_pubKey);
    return *_pubKey;
}

const X509& CertStore::getCert() const
{
    QVL_ASSERT(_x509);
    return *_x509;
}

}}}} // namespace intel { namespace sgx { namespace qvl { namespace pckparser {
