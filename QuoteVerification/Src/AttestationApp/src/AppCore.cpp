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

#include <fstream>
#include <sstream>
#include "ColorUtils.h"
#include "AppCore.h"
#include "AppOptions.h"
#include "IAttestationLibraryAdapter.h"
#include "StatusPrinter.h"


namespace intel { namespace sgx { namespace qvl {

namespace {
void outputResult(const std::string& step, Status status, std::ostream& logger)
{
    if (status != STATUS_OK)
    {
        logger << term::color::fg::red << step << " verification failed with status: " << status <<term::color::fg::reset << "\n";
    }
    else
    {
        logger << term::color::fg::green << step << " verification OK!" << term::color::fg::reset <<"\n";
    }
}
}

AppCore::AppCore(std::shared_ptr<IAttestationLibraryAdapter> libAdapter, std::shared_ptr<IFileReader> reader)
    : attestationLib(libAdapter), fileReader(reader)
{
}

std::string AppCore::version() const
{
    return attestationLib->getVersion();
}

bool AppCore::runVerification(const AppOptions& options, std::ostream& logger) const
{
    try
    {
        const auto pckCert = fileReader->readContent(options.pckCertificateFile);
        const auto pckSigningChain = fileReader->readContent(options.pckSigningChainFile);
        const auto pckCertChain = pckSigningChain + pckCert;
        const auto rootCaCrl = fileReader->readContent(options.rootCaCrlFile);
        const auto intermediateCaCrl = fileReader->readContent(options.intermediateCaCrlFile);
        const auto trustedRootCACert = fileReader->readContent(options.trustedRootCACertificateFile);
        const auto pckStatus = attestationLib->verifyPCKCertificate(pckCertChain, rootCaCrl, intermediateCaCrl, trustedRootCACert);
        outputResult("PCK certificate chain", pckStatus, logger);

        const auto tcbInfo = fileReader->readContent(options.tcbInfoFile);
        const auto tcbSigningCert = fileReader->readContent(options.tcbSigningChainFile);
        const auto tcbStatus = attestationLib->verifyTCBInfo(tcbInfo, tcbSigningCert, rootCaCrl, trustedRootCACert);
        outputResult("TCB info", tcbStatus, logger);

        const auto quote = fileReader->readBinaryContent(options.quoteFile);
        const auto quoteStatus = attestationLib->verifyQuote(quote, pckCert, intermediateCaCrl, tcbInfo);
        outputResult("Quote", quoteStatus, logger);
        return pckStatus == STATUS_OK && tcbStatus == STATUS_OK && quoteStatus == STATUS_OK;
    }
    catch (const IFileReader::ReadFileException& e)
    {
        logger << term::color::fg::red << "ERROR while trying to read input files: " << e.what() << term::color::fg::reset;
        return false;
    }
}

}}}
