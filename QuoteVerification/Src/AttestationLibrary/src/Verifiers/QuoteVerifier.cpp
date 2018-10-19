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

#include "QuoteVerifier.h"
#include "EnclaveReportVerifier.h"
#include "PckParser/FormatException.h"

#include <OpensslHelpers/DigestUtils.h>
#include <OpensslHelpers/SignatureVerification.h>
#include <OpensslHelpers/KeyUtils.h>
#include <CertVerification/X509Constants.h>
#include <Verifiers/PckCertVerifier.h>

#include <algorithm>
#include <functional>

namespace intel { namespace sgx { namespace qvl {

namespace{

pckparser::SgxExtension extension(pckparser::SgxExtension::Type type, const std::vector<pckparser::SgxExtension>& ext)
{
    const auto ret = std::find_if(
            ext.cbegin(),
            ext.cend(), [&](const pckparser::SgxExtension& ext){
                return ext.type == type;
            });

    if(ret == ext.cend())
    {
        return {};
    }

    return *ret;
}

pckparser::SgxExtension fmspc(const pckparser::CertStore& pck)
{
    return extension(pckparser::SgxExtension::Type::FMSPC, pck.getSGXExtensions());
}

pckparser::SgxExtension pcesvn(const pckparser::CertStore& pck)
{
    return extension(pckparser::SgxExtension::Type::PCESVN, extension(pckparser::SgxExtension::Type::TCB, pck.getSGXExtensions()).asSequence());
}

pckparser::SgxExtension tcbSvnComponent(const pckparser::CertStore& pck, size_t index)
{
    const auto componentId = [index]()
    {
        switch(index)
        {
            case 0:
                return pckparser::SgxExtension::Type::SGX_TCB_COMP01_SVN;
            case 1:
                return pckparser::SgxExtension::Type::SGX_TCB_COMP02_SVN;
            case 2:
                return pckparser::SgxExtension::Type::SGX_TCB_COMP03_SVN;
            case 3:
                return pckparser::SgxExtension::Type::SGX_TCB_COMP04_SVN;
            case 4:
                return pckparser::SgxExtension::Type::SGX_TCB_COMP05_SVN;
            case 5:
                return pckparser::SgxExtension::Type::SGX_TCB_COMP06_SVN;
            case 6:
                return pckparser::SgxExtension::Type::SGX_TCB_COMP07_SVN;
            case 7:
                return pckparser::SgxExtension::Type::SGX_TCB_COMP08_SVN;
            case 8:
                return pckparser::SgxExtension::Type::SGX_TCB_COMP09_SVN;
            case 9:
                return pckparser::SgxExtension::Type::SGX_TCB_COMP10_SVN;
            case 10:
                return pckparser::SgxExtension::Type::SGX_TCB_COMP11_SVN;
            case 11:
                return pckparser::SgxExtension::Type::SGX_TCB_COMP12_SVN;
            case 12:
                return pckparser::SgxExtension::Type::SGX_TCB_COMP13_SVN;
            case 13:
                return pckparser::SgxExtension::Type::SGX_TCB_COMP14_SVN;
            case 14:
                return pckparser::SgxExtension::Type::SGX_TCB_COMP15_SVN;
            case 15:
                return pckparser::SgxExtension::Type::SGX_TCB_COMP16_SVN;
            default:
                return pckparser::SgxExtension::Type::NONE;
        }
    }();
    return extension(componentId, extension(pckparser::SgxExtension::Type::TCB, pck.getSGXExtensions()).asSequence());
}

constexpr int CPUSVN_LOWER = false;
constexpr int CPUSVN_EQUAL_OR_HIGHER = true;

bool isCpuSvnHigherOrEqual(const pckparser::CertStore& pckCert, const Bytes& cpusvnToCompare)
{
    for(size_t index = 0; index < cpusvnToCompare.size(); ++index)
    {
        const auto componentValue = tcbSvnComponent(pckCert, index).asUInt();
        const auto otherComponentValue = cpusvnToCompare.at(index);
        if(componentValue < otherComponentValue)
        {
            // If *ANY* CPUSVN component is lower then CPUSVN is considered lower
            return CPUSVN_LOWER;
        }
    }
    // but for CPUSVN to be considered higher it requires that *EVERY* CPUSVN component to be higher or equal
    return CPUSVN_EQUAL_OR_HIGHER;
}

const std::string getMatchingTcbLevel(const std::set<TCBInfoJsonVerifier::TcbLevel, std::greater<>> &tcbs,
                                      const pckparser::CertStore &pckCert)
{
    const auto certPceSvn = pcesvn(pckCert);

    for (const auto& tcb : tcbs)
    {
        if (tcb.cpusvn.size() != constants::CPUSVN_BYTE_LEN)
        {
            throw pckparser::FormatException("Invalid size of CPUSVN in TCB Info");
        }

        if(isCpuSvnHigherOrEqual(pckCert, tcb.cpusvn) && certPceSvn.asUInt() >= tcb.pcesvn)
        {
            return tcb.status;
        }
    }

    throw std::runtime_error("Could not match PCK cert to provided TCB levels in TCB info");
}

Status checkTcbLevel(const TCBInfoJsonVerifier& tcbInfoJson, const pckparser::CertStore& pckCert)
{
    try
    {
        const auto tcbLevelStatus = getMatchingTcbLevel(tcbInfoJson.getTcbLevels(), pckCert);

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
    }
    catch (const std::runtime_error &e)
    {
        return STATUS_TCB_NOT_SUPPORTED;
    }

    return STATUS_TCB_UNRECOGNIZED_STATUS;
}

}//anonymous namespace

Status QuoteVerifier::verify(const Quote& quote, const pckparser::CertStore& pckCert, const pckparser::CrlStore& crl, const TCBInfoJsonVerifier& tcbInfoJson, const QEIdentityJsonVerifier& qeIdentityJson, const EnclaveReportVerifier& enclaveReportVerifier)
{

    if(STATUS_OK != PckCertVerifier{}.verifyPCKCert(pckCert) || !_baseVerififer.commonNameContains(pckCert.getSubject(), constants::SGX_PCK_CN_PHRASE))
    {
        return STATUS_INVALID_PCK_CERT;
    }

    if(!PckCrlVerifier{}.checkValidityPeriodAndIssuer(crl) || crl.getIssuer() != pckCert.getIssuer())
    {
        return STATUS_INVALID_PCK_CRL;
    }

    if(crl.isRevoked(pckCert))
    {
        return STATUS_PCK_REVOKED;
    }

    if(fmspc(pckCert).asOctetString() != tcbInfoJson.getFmspc())
    {
        return STATUS_TCB_INFO_MISMATCH;
    }

    try
    {
        const auto tcbLevelStatus = checkTcbLevel(tcbInfoJson, pckCert);
        if(STATUS_OK != tcbLevelStatus)
        {
            return tcbLevelStatus;
        }
    }
    catch (const pckparser::FormatException &e)
    {
        return STATUS_UNSUPPORTED_TCB_INFO_FORMAT;
    }

    const auto qeCertData = quote.getQuoteAuthData().qeCertData;
    if(std::find(qvl::constants::SUPPORTED_PCK_IDS.cbegin(), qvl::constants::SUPPORTED_PCK_IDS.cend(), qeCertData.type) == qvl::constants::SUPPORTED_PCK_IDS.cend())
    {
        return STATUS_UNSUPPORTED_QE_CERTIFICATION;
    }

    auto qeCertDataVerificationStatus = verifyQeCertData(qeCertData);
    if(qeCertDataVerificationStatus != STATUS_OK)
    {
        return qeCertDataVerificationStatus;
    }

    if(!crypto::verifySha256EcdsaSignature(quote.getQuoteAuthData().qeReportSignature.signature,
                                           quote.getQuoteAuthData().qeReport.rawBlob(),
                                           pckCert.getPubKey()))
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

    if(!std::equal(hashedConcatOfAttestKeyAndQeReportData.begin(),
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


    if(STATUS_OK == qeIdentityJson.getStatus())
    {
        Status qeIdentityStatus = verifyQeIdentity(quote, qeIdentityJson, enclaveReportVerifier);
        if(STATUS_OK != qeIdentityStatus)
        {
            return qeIdentityStatus;
        }
    }

    if(!crypto::verifySha256EcdsaSignature(quote.getQuoteAuthData().ecdsa256BitSignature.signature,
                                           quote.getSignedData(),
                                           *attestKey))
    {
        return STATUS_INVALID_QUOTE_SIGNATURE;
    }

    return STATUS_OK;
}

Status QuoteVerifier::verifyQeCertData(const Quote::QeCertData& qeCertData) const
{
    if(qeCertData.parsedDataSize != qeCertData.data.size())
    {
        return STATUS_UNSUPPORTED_QUOTE_FORMAT;
    }
    return STATUS_OK;
}

Status QuoteVerifier::verifyQeIdentity(const Quote& quote, const QEIdentityJsonVerifier& qeIdentityJson, const EnclaveReportVerifier& enclaveReportVerifier)
{
    Status status = enclaveReportVerifier.verify(qeIdentityJson, quote.getQuoteAuthData().qeReport);
    if(status == STATUS_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE)
    {
        return STATUS_QE_IDENTITY_OUT_OF_DATE;
    }

    if(status == STATUS_SGX_ENCLAVE_REPORT_MISCSELECT_MISMATCH
        || status == STATUS_SGX_ENCLAVE_REPORT_ATTRIBUTES_MISMATCH
        || status == STATUS_SGX_ENCLAVE_REPORT_MRENCLAVE_MISMATCH
        || status == STATUS_SGX_ENCLAVE_REPORT_MRSIGNER_MISMATCH
        || status == STATUS_SGX_ENCLAVE_REPORT_ISVPRODID_MISMATCH
        || status == STATUS_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE)
    {
        return STATUS_QE_IDENTITY_MISMATCH;
    }
    return status;
};

}}} // namespace intel { namespace sgx { namespace qvl {
