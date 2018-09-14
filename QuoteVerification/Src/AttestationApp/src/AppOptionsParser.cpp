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

#include "AppOptionsParser.h"
#include "ColorUtils.h"

namespace intel { namespace sgx { namespace qvl {

namespace {
    static const std::string quoteDefaultPath = "quote.dat";
    static const std::string trustedRootDefaultPath = "trustedRootCaCert.pem";
    static const std::string pckCertDefaultPath = "pckCert.pem";
    static const std::string pckSigningChainDefaultPath = "pckSignChain.pem";
    static const std::string tcbSignChainDefaultPath = "tcbSignChain.pem";
    static const std::string tcbInfoDefaultPath = "tcbInfo.json";
    static const std::string rootCaCrlDefaultPath = "rootCaCrl.pem";
    static const std::string intermediateCaCrlDefaultPath = "intermediateCaCrl.pem";
}

AppOptionsParser::AppOptionsParser()
{
    // 1st argument is long name
    // 2nd argument is short name (no short name if '\0' specified)
    // 3rd argument is description
    // 4th argument is mandatory (optional. default is false)
    // 5th argument is default value  (optional. it used when mandatory is false)
    _parser.add("trustedRootCaCert", '\0', "Trusted root CA Certificate file path, PEM format", false, trustedRootDefaultPath);
    _parser.add("pckSignChain", '\0', "PCK Signing Certificate chain file path, PEM format", false, pckSigningChainDefaultPath);
    _parser.add("pckCert", '\0', "PCK Certificate file path, PEM format", false, pckCertDefaultPath);
    _parser.add("tcbSignChain", '\0', "TCB Signing Certificate chain file path, PEM format", false, tcbSignChainDefaultPath);
    _parser.add("tcbInfo", '\0', "TCB Info file path, JSON format", false, tcbInfoDefaultPath);
    _parser.add("rootCaCrl", '\0', "Root Ca CRL file path, PEM format", false, rootCaCrlDefaultPath);
    _parser.add("intermediateCaCrl", '\0', "Intermediate Ca CRL file path, PEM format", false, intermediateCaCrlDefaultPath);
    _parser.add("quote", '\0', "Quote file path, binary format", false, quoteDefaultPath);
    _parser.add("help", 'h', "print this message");
}

std::unique_ptr<AppOptions> AppOptionsParser::parse(int argc, char **argv, std::ostream& logger)
{
    if(!_parser.parse(argc, const_cast<const char* const*>(argv)))
    {
        if(!_parser.error_full().empty())
        {
            logger << term::color::fg::red << _parser.error_full() << term::color::fg::reset << std::endl;
        }
        logger << _parser.usage();
        return nullptr;
    }
    if(_parser.exist("help"))
    {
        logger << _parser.usage();
        return nullptr;
    }

    auto options = std::unique_ptr<AppOptions>(new AppOptions());
    options->trustedRootCACertificateFile = _parser.get<std::string>("trustedRootCaCert");
    options->pckSigningChainFile = _parser.get<std::string>("pckSignChain");
    options->pckCertificateFile = _parser.get<std::string>("pckCert");
    options->tcbSigningChainFile = _parser.get<std::string>("tcbSignChain");
    options->tcbInfoFile = _parser.get<std::string>("tcbInfo");
    options->rootCaCrlFile = _parser.get<std::string>("rootCaCrl");
    options->intermediateCaCrlFile = _parser.get<std::string>("intermediateCaCrl");
    options->quoteFile = _parser.get<std::string>("quote");
    return options;
}

}}}

