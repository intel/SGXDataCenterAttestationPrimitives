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


#ifndef SGX_INTEL_PCKLIB_PCKPARSER_H_
#define SGX_INTEL_PCKLIB_PCKPARSER_H_

#include <string>
#include <utility>
#include <vector>
#include <sstream>
#include <ctime>
#include <chrono>

#include <OpensslHelpers/OpensslTypes.h>
#include <OpensslHelpers/Bytes.h>
#include <iostream>
#include "SgxExtension.h"

namespace intel { namespace sgx { namespace qvl { namespace pckparser {

struct Subject;
struct Issuer
{
    std::string raw;
    std::string commonName;
    std::string countryName;
    std::string organizationName;
    std::string locationName;
    std::string stateName;

    bool operator ==(const Issuer& other) const;
    bool operator !=(const Issuer& other) const;

    bool operator ==(const Subject& subject) const;
    bool operator !=(const Subject& subject) const;
};

struct Subject
{
    std::string raw;
    std::string commonName;
    std::string countryName;
    std::string organizationName;
    std::string locationName;
    std::string stateName;

    bool operator ==(const Subject& other) const;
    bool operator !=(const Subject& other) const;

    bool operator ==(const Issuer& issuer) const;
    bool operator !=(const Issuer& issuer) const;
};

struct Validity
{
    bool isValid() const;
    bool operator ==(const Validity& other) const;

    std::time_t notBeforeTime;
    std::time_t notAfterTime;
};

struct Extension
{
    int opensslNid;
    std::string name;
    std::vector<uint8_t> value;

    bool operator==(const Extension&) const;
    bool operator!=(const Extension&) const;
};

struct Signature
{
    std::vector<uint8_t> rawDer;
    std::vector<uint8_t> r;
    std::vector<uint8_t> s;
};

struct Revoked
{
    std::string dateStr;
    std::vector<uint8_t> serialNumber;
    
    bool operator==(const Revoked&) const;
    bool operator!=(const Revoked&) const; 

    // revoked elements can have their own extensions
    // but at the time of writing this lib no extensions
    // were defined in spec 
    // std::vector<Extension> extensions;
};

// OpenSSL initialization/cleanup functions.
// init* to be called once at the beginning of execution.
// clean* to be called one at the end of execution
// You do not need to call these if you already have OpenSSL initialized
// by different code.
// THESE FUNCTIONS PERFORM MINIMAL INITIALIZATION
void initOpenSSL();
void cleanUpOpenSSL();

////////////////////////////////////////////////////////////////////////////
//
//      PCK Certificate parsing functions
//
////////////////////////////////////////////////////////////////////////////

// Functions group to load certificate for file or from memory.
// PCK certs will be most likely DER encoded, but PEM converters
// are included as well.

// On error nullptr is returned.
// If there will be problem with file access nullptr will be returned
// but getLastError* won't be set. Thus ensure file is accessible before
// using this function.
crypto::X509_uptr derFileCert2X509(const std::string& derFilePath);
// On error nullptr is returned.
crypto::X509_uptr pemFileCert2X509(const std::string& pemFilePath);

crypto::X509_uptr pemBuffCert2X509(const std::string& pemBuff);

// Main meat of library, functions to extract info from certificate.
// Names are self explanatory, values returned on error stated in comments.
// To minimize dependencies I didn't use boost::optional despite it was
// very itchy to do so. In a result, prepare yourself for some nullptr's

// returns -1 on error 
long getVersion(const X509& x509);
// returns empty vector on error
std::vector<uint8_t> getSerialNumber(X509& x509);
// return empty string on error
Subject getSubject(const X509& x509);
// returns Issuer with empty values on error
Issuer getIssuer(const X509& x509);
// returns Validity with empty values on error
Validity getValidity(const X509& x509);
// returns nullptr on error
crypto::EC_KEY_uptr getPubKey(const X509& x509);
// returns less than 0 in case of error
int getExtensionCount(const X509& x509);
// returns empty vector in case of error
std::vector<Extension> getExtensions(const X509& x509);
// Returns raw, DER signature as well as parsed ECDSA R and S if possible.
// When running against PCK certificates having empty R or S
// should be considered as error.
// returns empty vectors in case of error.
Signature getSignature(const X509& x509);


////////////////////////////////////////////////////////////////////////////
//
//      PCK Certificate revocation list functions
//
////////////////////////////////////////////////////////////////////////////

crypto::X509_CRL_uptr derFileCRL2X509Crl(const std::string& filePath);
crypto::X509_CRL_uptr pemBuff2X509Crl(const std::string& data);
long getVersion(const X509_CRL& crl);
Issuer getIssuer(const X509_CRL& crl);
int getExtensionCount(const X509_CRL& crl);
std::vector<Extension> getExtensions(const X509_CRL& crl);
Signature getSignature(const X509_CRL& crl);
Validity getValidity(const X509_CRL& crl);

int getRevokedCount(X509_CRL& crl);
std::vector<Revoked> getRevoked(X509_CRL& crl);

////////////////////////////////////////////////////////////////////////////
//
//      Helper functions
//      
////////////////////////////////////////////////////////////////////////////

// Return raw bytes which represents EC POINT. It returns compressed
// or uncompressed representation which depends on argument structure state.
// If first byte == 0x04 then it's uncompressed encoding.
// If first byte == 0x02 or 0x03 then it's compressed encoding.
// (For additional info check RFC5480)
// In PCK case we shall expect {0x04, x, y} as simple concatenation where
// x and y have 32 bytes.
// returns empty vector on error
std::vector<uint8_t> getPubKeyBytes(const EC_KEY& ecPubKey);
std::vector<SgxExtension> getSGXExtensions(const std::vector<Extension>& extensions);

}}}} // namespace intel { namespace sgx { namespace qvl { namespace pckparser {

#endif // SGX_INTEL_PCKLIB_PCKPARSER_H_
