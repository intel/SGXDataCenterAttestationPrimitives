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

#include "CertificateChain.h"
#include <algorithm>

namespace intel { namespace sgx { namespace qvl {


bool CertificateChain::parse(const std::string& pemCertChain)
{
    const auto certStrs = splitChain(pemCertChain);

    certs.reserve(certStrs.size());
    for(const auto& cert : certStrs)
    {
        auto certStore = std::make_shared<pckparser::CertStore>();
        if(!certStore->parse(cert))
        {
            // any cert in chain has wrong format
            // then whole chain should be considered invalid
            return false;
        }

        if(certStore->getSubject() == certStore->getIssuer())
        {
            // if cert is self signed, we assume that its the root cert
            rootCert = certStore;
        }

        certs.emplace_back(certStore);
    }

    // find topmost cert, this will be the cert that is not used to sign any of the certificates in the chain
    for(auto const &cert: certs)
    {
        auto signedCertIter = std::find_if(certs.cbegin(), certs.cend(), [](const std::shared_ptr<const pckparser::CertStore> &cert)
        {
            return cert->getSubject() != cert->getSubject()
                   && cert->getIssuer() == cert->getSubject();
        });
        if(signedCertIter == certs.cend())
        {
            topmostCert = cert;
        }
    }

    return length() != 0;
}

unsigned long CertificateChain::length() const
{
    return certs.size();
}

std::shared_ptr<const pckparser::CertStore> CertificateChain::get(const pckparser::Subject &subject) const
{
    auto it = std::find_if(certs.cbegin(), certs.cend(), [&subject](const std::shared_ptr<const pckparser::CertStore> &cert)
    {
        return cert->getSubject() == subject;
    });
    if(it == certs.end())
    {
        return nullptr;
    }
    return *it;
}

std::shared_ptr<const pckparser::CertStore> CertificateChain::getRootCert() const
{
    return rootCert;
}

std::shared_ptr<const pckparser::CertStore> CertificateChain::getTopmostCert() const
{
    return topmostCert;
}

std::vector<std::string> CertificateChain::splitChain(const std::string &pemChain) const
{
    if(pemChain.empty())
    {
        return {};
    }

    const std::string begCert = "-----BEGIN CERTIFICATE-----";
    const std::string endCert = "-----END CERTIFICATE-----";

    const size_t begPos = pemChain.find(begCert);
    const size_t endPos = pemChain.find(endCert);

    if(begPos == std::string::npos || endPos == std::string::npos)
    {
        return {};
    }

    std::vector<std::string> ret;
    size_t newStartPos = begPos;
    size_t foundEndPos = endPos;
    while(foundEndPos != std::string::npos)
    {
        // second loop to be evenatually run in second and
        // further iteration
        // we could ommit this loop by simply newStartPos = newEndPos + 1;
        // at the end of main loop if we were sure new line would be simple '\n'
        // since it's more portable to assume it could be \r\n as well then here it is
        while(pemChain.at(newStartPos) != '-') ++newStartPos;

        const size_t newEndPos = foundEndPos + endCert.size();
        const std::string cert = pemChain.substr(newStartPos, newEndPos - newStartPos);

        // we do not check for this in second and further iteration
        // and it's cheaper to check on shorter string
        if(cert.find(begCert) != std::string::npos)
        {
            ret.push_back(cert);
        }

        newStartPos = newEndPos;
        foundEndPos = pemChain.find(endCert, newStartPos);
    }

    return ret;
}

}}}
