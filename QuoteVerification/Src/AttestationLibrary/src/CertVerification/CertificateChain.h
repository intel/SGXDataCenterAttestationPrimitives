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

#ifndef SGX_ECDSA_CERTIFICATECHAIN_H_
#define SGX_ECDSA_CERTIFICATECHAIN_H_

#include <string>
#include <vector>
#include <memory>
#include <PckParser/CertStore.h>
#include <PckParser/PckParser.h>

namespace intel { namespace sgx { namespace qvl {

class CertificateChain
{
public:

    virtual ~CertificateChain() = default;
    CertificateChain() = default;
    CertificateChain(const CertificateChain&) = delete;
    CertificateChain(CertificateChain&&) = default;
    

    CertificateChain& operator=(const CertificateChain&) = delete;
    CertificateChain& operator=(CertificateChain&&) = default;

    /**
    * Parse certificate chain.
    * Check if there is at least on valid x.509 certificate in the chain.
    *
    * @param pemCertChain - string of concatenated PEM certificates
    * @return true if chain has been successfully parsed
    */
    virtual bool parse(const std::string& pemCertChain);

    /**
    * Get length of the parsed chain
    * @return chain length.
    */
    virtual unsigned long length() const;

    /**
    * Get nth certificate from chain
    *
    * @param subject - certificate subject to get
    * @return shared pointer to certificate store
    */
    virtual std::shared_ptr<const pckparser::CertStore> get(const pckparser::Subject &subject) const;

    /**
    * Get root certificate from chain (position 0)
    *
    * @return shared pointer to certificate store
    */
    virtual std::shared_ptr<const pckparser::CertStore> getRootCert() const;

    /**
    * Get topmost certificate from chain (last position)
    *
    * @return shared pointer to certificate store
    */
    virtual std::shared_ptr<const pckparser::CertStore> getTopmostCert() const;
private:
    std::vector<std::string> splitChain(const std::string &pemChain) const;

    std::vector<std::shared_ptr<const pckparser::CertStore>> certs{};
    std::shared_ptr<const pckparser::CertStore> rootCert{};
    std::shared_ptr<const pckparser::CertStore> topmostCert{};
};

}}} // namespace intel { namespace sgx { namespace qvl {

#endif //SGX_ECDSA_CERTIFICATECHAIN_H_
