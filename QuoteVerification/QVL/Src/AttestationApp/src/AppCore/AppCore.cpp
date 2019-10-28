/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <fstream>
#include <sstream>
#include "AppCore.h"
#include "AppOptions.h"
#include "IAttestationLibraryAdapter.h"
#include "StatusPrinter.h"
#include <ctime>
#include <chrono>

namespace intel { namespace sgx { namespace qvl {

namespace {
void outputResult(const std::string& step, Status status, std::ostream& logger)
{
    if (status != STATUS_OK)
    {
        logger << step << " verification failed with status: " << status << std::endl;
    }
    else
    {
        logger << step << " verification OK!" << std::endl;
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
        const auto expirationDate = options.expirationDate;
        const auto pckCert = fileReader->readContent(options.pckCertificateFile);
        const auto pckSigningChain = fileReader->readContent(options.pckSigningChainFile);
        const auto pckCertChain = pckSigningChain + pckCert;
        const auto rootCaCrl = fileReader->readContent(options.rootCaCrlFile);
        const auto intermediateCaCrl = fileReader->readContent(options.intermediateCaCrlFile);
        const auto trustedRootCACert = fileReader->readContent(options.trustedRootCACertificateFile);
        const auto pckVerifyStatus = attestationLib->verifyPCKCertificate(pckCertChain, rootCaCrl, intermediateCaCrl, trustedRootCACert, expirationDate);
        outputResult("PCK certificate chain", pckVerifyStatus, logger);

        const auto tcbInfo = fileReader->readContent(options.tcbInfoFile);
        const auto tcbSigningCert = fileReader->readContent(options.tcbSigningChainFile);
        const auto tcbVerifyStatus = attestationLib->verifyTCBInfo(tcbInfo, tcbSigningCert, rootCaCrl, trustedRootCACert, expirationDate);
        outputResult("TCB info", tcbVerifyStatus, logger);

        const auto qeIdentityPresent = !options.qeIdentityFile.empty();
        std::string qeIdentity = std::string{};
        Status qeIdentityVerifyStatus = STATUS_OK;
        if (qeIdentityPresent)
        {
            qeIdentity = fileReader->readContent(options.qeIdentityFile);
            qeIdentityVerifyStatus = attestationLib->verifyQeIdentity(qeIdentity, tcbSigningCert, rootCaCrl, trustedRootCACert, expirationDate);
            outputResult("QeIdentity", qeIdentityVerifyStatus, logger);
        }

        const auto quote = fileReader->readBinaryContent(options.quoteFile);
        const auto quoteVerifyStatus = attestationLib->verifyQuote(quote, pckCert, intermediateCaCrl, tcbInfo, qeIdentity);
        outputResult("Quote", quoteVerifyStatus, logger);

        return (pckVerifyStatus == STATUS_OK) && (tcbVerifyStatus == STATUS_OK) && (quoteVerifyStatus == STATUS_OK) && (qeIdentityVerifyStatus == STATUS_OK);
    }
    catch (const IFileReader::ReadFileException& e)
    {
        logger << "ERROR while trying to read input files: " << e.what();
        return false;
    }
}

}}}
