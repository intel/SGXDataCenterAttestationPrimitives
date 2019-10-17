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

#include "QuoteVerifier.h"
#include "EnclaveIdentity.h"

#include <algorithm>
#include <functional>

#include <CertVerification/X509Constants.h>
#include <QuoteVerification/QuoteConstants.h>
#include <OpensslHelpers/DigestUtils.h>
#include <OpensslHelpers/KeyUtils.h>
#include <OpensslHelpers/SignatureVerification.h>
#include <Verifiers/PckCertVerifier.h>

namespace intel { namespace sgx { namespace qvl {

namespace {

constexpr int CPUSVN_LOWER = false;
constexpr int CPUSVN_EQUAL_OR_HIGHER = true;

bool isCpuSvnHigherOrEqual(const dcap::parser::x509::PckCertificate& pckCert,
                           const dcap::parser::json::TcbLevel& tcbLevel)
{
    for(unsigned int index = 0; index < constants::CPUSVN_BYTE_LEN; ++index)
    {
        const auto componentValue = pckCert.getTcb().getSgxTcbComponentSvn(index);
        const auto otherComponentValue = tcbLevel.getSgxTcbComponentSvn(index);
        if(componentValue < otherComponentValue)
        {
            // If *ANY* CPUSVN component is lower then CPUSVN is considered lower
            return CPUSVN_LOWER;
        }
    }
    // but for CPUSVN to be considered higher it requires that *EVERY* CPUSVN component to be higher or equal
    return CPUSVN_EQUAL_OR_HIGHER;
}

const std::string& getMatchingTcbLevel(const std::set<dcap::parser::json::TcbLevel, std::greater<dcap::parser::json::TcbLevel>> &tcbs,
                                      const dcap::parser::x509::PckCertificate &pckCert)
{
    const auto certPceSvn = pckCert.getTcb().getPceSvn();

    for (const auto& tcb : tcbs)
    {
        if(isCpuSvnHigherOrEqual(pckCert, tcb) && certPceSvn >= tcb.getPceSvn())
        {
            return tcb.getStatus();
        }
    }

    throw std::runtime_error("Could not match PCK cert to provided TCB levels in TCB info");
}

Status checkTcbLevel(const dcap::parser::json::TcbInfo& tcbInfoJson, const dcap::parser::x509::PckCertificate& pckCert)
{
    try
    {
        const auto& tcbLevelStatus = getMatchingTcbLevel(tcbInfoJson.getTcbLevels(), pckCert);

        if (tcbLevelStatus == "OutOfDate")
        {
            return STATUS_TCB_OUT_OF_DATE;
        }

        if (tcbLevelStatus == "Revoked")
        {
            return STATUS_TCB_REVOKED;
        }

        if (tcbLevelStatus == "ConfigurationNeeded")
        {
            return STATUS_TCB_CONFIGURATION_NEEDED;
        }

        if (tcbLevelStatus == "UpToDate")
        {
            return STATUS_OK;
        }

        if(tcbInfoJson.getVersion() == 2 && tcbLevelStatus == "OutOfDateConfigurationNeeded")
        {
            return STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED;
        }
    }
    catch (const std::runtime_error &e)
    {
        return STATUS_TCB_NOT_SUPPORTED;
    }

    return STATUS_TCB_UNRECOGNIZED_STATUS;
}

Status convergeTcbstatus(Status tcbInfoStatus, Status qeIdentityStatus) {
    if (qeIdentityStatus == STATUS_OK) {
        return tcbInfoStatus;
    }
    if (qeIdentityStatus == STATUS_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE ||
        qeIdentityStatus == STATUS_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE ||
        qeIdentityStatus == STATUS_QE_IDENTITY_OUT_OF_DATE) {
        switch (tcbInfoStatus)
        {
        case STATUS_OK:
            return STATUS_TCB_OUT_OF_DATE;
        case STATUS_TCB_CONFIGURATION_NEEDED:
            return STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED;
        default:
            return tcbInfoStatus;
        }
    }
    return STATUS_INVALID_PARAMETER;
}

}//anonymous namespace

Status QuoteVerifier::verify(const Quote& quote,
                             const dcap::parser::x509::PckCertificate& pckCert,
                             const pckparser::CrlStore& crl,
                             const dcap::parser::json::TcbInfo& tcbInfoJson,
                             const EnclaveIdentity *enclaveIdentity,
                             const EnclaveReportVerifier& enclaveReportVerifier)
{
    Status qeIdentityStatus = STATUS_QE_IDENTITY_MISMATCH;
    Status convergedTcbStatus = STATUS_TCB_NOT_SUPPORTED;

    if(!_baseVerififer.commonNameContains(pckCert.getSubject(), constants::SGX_PCK_CN_PHRASE))
    {
        return STATUS_INVALID_PCK_CERT;
    }

    if(!PckCrlVerifier{}.checkIssuer(crl) || crl.getIssuer().raw != pckCert.getIssuer().getRaw())
    {
        return STATUS_INVALID_PCK_CRL;
    }

    if(crl.isRevoked(pckCert))
    {
        return STATUS_PCK_REVOKED;
    }

    if(pckCert.getFmspc() != tcbInfoJson.getFmspc())
    {
        return STATUS_TCB_INFO_MISMATCH;
    }

    if(pckCert.getPceId() != tcbInfoJson.getPceId())
    {
        return STATUS_TCB_INFO_MISMATCH;
    }

    const auto qeCertData = quote.getQuoteAuthData().qeCertData;
    auto qeCertDataVerificationStatus = verifyQeCertData(qeCertData);
    if(qeCertDataVerificationStatus != STATUS_OK)
    {
        return qeCertDataVerificationStatus;
    }

    if(!crypto::verifySha256EcdsaSignature(quote.getQuoteAuthData().qeReportSignature.signature,
                                           quote.getQuoteAuthData().qeReport.rawBlob(),
                                           *crypto::rawToP256PubKey(pckCert.getPubKey())))
    {
        return STATUS_INVALID_QE_REPORT_SIGNATURE;
    }

    const auto hashedConcatOfAttestKeyAndQeReportData = [&]() -> std::vector<uint8_t>
    {
        const auto attestKeyData = quote.getQuoteAuthData().ecdsaAttestationKey.pubKey;
        const auto qeAuthData = quote.getQuoteAuthData().qeAuthData.data;
        std::vector<uint8_t> ret;
        ret.reserve(attestKeyData.size() + qeAuthData.size());
        std::copy(attestKeyData.begin(), attestKeyData.end(), std::back_inserter(ret));
        std::copy(qeAuthData.begin(), qeAuthData.end(), std::back_inserter(ret));

        return crypto::sha256Digest(ret);
    }();

    if(hashedConcatOfAttestKeyAndQeReportData.empty() || !std::equal(hashedConcatOfAttestKeyAndQeReportData.begin(),
                   hashedConcatOfAttestKeyAndQeReportData.end(),
                   quote.getQuoteAuthData().qeReport.reportData.begin()))
    {
        return STATUS_INVALID_QE_REPORT_DATA;
    }

    const auto attestKey = crypto::rawToP256PubKey(quote.getQuoteAuthData().ecdsaAttestationKey.pubKey);
    if(!attestKey)
    {
        return STATUS_UNSUPPORTED_QUOTE_FORMAT;
    }

    if (!crypto::verifySha256EcdsaSignature(quote.getQuoteAuthData().ecdsa256BitSignature.signature,
        quote.getSignedData(),
        *attestKey))
    {
        return STATUS_INVALID_QUOTE_SIGNATURE;
    }

    if (enclaveIdentity && enclaveIdentity->getStatus() == STATUS_OK)
    {
        qeIdentityStatus = verifyQeIdentity(quote, enclaveIdentity, enclaveReportVerifier);
        if (STATUS_OK != qeIdentityStatus && 
            STATUS_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE != qeIdentityStatus)
        {
            //will return STATUS_TCB_REVOKED or STATUS_QE_IDENTITY_MISMATCH
            return qeIdentityStatus;
        }
    }

    try
    {
        const auto tcbLevelStatus = checkTcbLevel(tcbInfoJson, pckCert);
        convergedTcbStatus = convergeTcbstatus(tcbLevelStatus, qeIdentityStatus);
    }
    catch (const dcap::parser::FormatException &e)
    {
        return STATUS_UNSUPPORTED_TCB_INFO_FORMAT;
    }

    return convergedTcbStatus;
}

Status QuoteVerifier::verifyQeCertData(const Quote::QeCertData& qeCertData) const
{
    if(qeCertData.parsedDataSize != qeCertData.data.size())
    {
        return STATUS_UNSUPPORTED_QUOTE_FORMAT;
    }
    return STATUS_OK;
}

Status QuoteVerifier::verifyQeIdentity(const Quote& quote, const EnclaveIdentity *qeIdentityJson, const EnclaveReportVerifier& enclaveReportVerifier)
{
    Status status = enclaveReportVerifier.verify(qeIdentityJson, quote.getQuoteAuthData().qeReport);

    if(status != STATUS_OK &&
        status != STATUS_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE &&
        status != STATUS_TCB_REVOKED)
    {
        return STATUS_QE_IDENTITY_MISMATCH;
    }
    return status;
}

}}} // namespace intel { namespace sgx { namespace qvl {
