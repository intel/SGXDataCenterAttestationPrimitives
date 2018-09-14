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

constexpr int CPUSVN_LOWER = -1;
constexpr int CPUSVN_HIGHER = 1;
constexpr int CPUSVN_EQUAL = 0;

int compareCpusvn(const pckparser::CertStore& pckCert, const Bytes& cpusvnToCompare)
{
    for(size_t index = 0; index < cpusvnToCompare.size(); ++index)
    {
        const auto componentValue = tcbSvnComponent(pckCert, index).asUInt();
        const auto otherComponentValue = cpusvnToCompare.at(index);
        if(componentValue < otherComponentValue)
        {
            return CPUSVN_LOWER;
        }
        if(componentValue > otherComponentValue)
        {
            return CPUSVN_HIGHER;
        }
    }
    return CPUSVN_EQUAL;
}

bool isCpusvnLower(const pckparser::CertStore& pckCert, const Bytes& cpusvnToCompare)
{
    return compareCpusvn(pckCert, cpusvnToCompare) == CPUSVN_LOWER;
}

bool isCpusvnHigher(const pckparser::CertStore& pckCert, const Bytes& cpusvnToCompare)
{
    return compareCpusvn(pckCert, cpusvnToCompare) == CPUSVN_HIGHER;
}

Status checkRevocation(const TCBInfoJsonVerifier& tcbInfoJson, const pckparser::CertStore& pckCert)
{
    if(tcbInfoJson.getRevokedCpusvn().empty())
    { 
        return STATUS_OK;  
    }
    
    if(tcbInfoJson.getRevokedCpusvn().size() != constants::CPUSVN_BYTE_LEN)
    {
        return STATUS_UNSUPPORTED_TCB_INFO_FORMAT;
    }

    const auto certPceSvn = pcesvn(pckCert);


    if(certPceSvn.asUInt() <= tcbInfoJson.getRevokedPcesvn() &&
       !isCpusvnHigher(pckCert, tcbInfoJson.getRevokedCpusvn()))
    {
        return STATUS_TCB_REVOKED;
    }

    return STATUS_OK;
}

Status areLatestElementsOutOfDate(const TCBInfoJsonVerifier& tcbInfoJson, const pckparser::CertStore& pckCert)
{
    if(tcbInfoJson.getLatestCpusvn().size() != constants::CPUSVN_BYTE_LEN)
    {
        return STATUS_UNSUPPORTED_TCB_INFO_FORMAT;
    }

    const auto certPceSvn = pcesvn(pckCert);

    if(certPceSvn.asUInt() < tcbInfoJson.getLatestPcesvn() ||
       isCpusvnLower(pckCert, tcbInfoJson.getLatestCpusvn()))
    {
        return STATUS_TCB_OUT_OF_DATE;
    }

    return STATUS_OK;
}

}//anonymous namespace

Status QuoteVerifier::verify(const Quote& quote, const pckparser::CertStore& pckCert, const pckparser::CrlStore& crl, const TCBInfoJsonVerifier& tcbInfoJson)
{
    
    if(STATUS_OK != PckCertVerifier{}.verifyPCKCert(pckCert))
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

    const auto revocationStatus = checkRevocation(tcbInfoJson, pckCert);
    if(STATUS_OK != revocationStatus)
    {
        return revocationStatus;
    }

    const auto outOfDateStatus = areLatestElementsOutOfDate(tcbInfoJson, pckCert);
    if(STATUS_OK != outOfDateStatus)
    {
        return outOfDateStatus;
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

}}} // namespace intel { namespace sgx { namespace qvl {
