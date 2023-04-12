/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
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
#include "EnclaveIdentityV2.h"
#include "Utils/RuntimeException.h"
#include "Utils/Logger.h"

#include <algorithm>
#include <functional>

#include <CertVerification/X509Constants.h>
#include <QuoteVerification/QuoteConstants.h>
#include <OpensslHelpers/DigestUtils.h>
#include <OpensslHelpers/KeyUtils.h>
#include <OpensslHelpers/SignatureVerification.h>
#include <OpensslHelpers/Bytes.h>
#include <Verifiers/PckCertVerifier.h>

namespace intel { namespace sgx { namespace dcap {

namespace {

constexpr int CPUSVN_LOWER = false;
constexpr int CPUSVN_EQUAL_OR_HIGHER = true;

bool isCpuSvnHigherOrEqual(const dcap::parser::x509::PckCertificate& pckCert,
                           const dcap::parser::json::TcbLevel& tcbLevel)
{
    for(uint32_t index = 0; index < constants::CPUSVN_BYTE_LEN; ++index)
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

bool isTdxTcbHigherOrEqual(const Quote& quote,
                           const dcap::parser::json::TcbLevel& tcbLevel)
{
    const auto& teeTcbSvn = quote.getTeeTcbSvn();
    uint32_t index = 0;
    if (quote.getHeader().version > constants::QUOTE_VERSION_3 && teeTcbSvn[1] > 0)
    {
        index = 2;
    }
    for(; index < constants::CPUSVN_BYTE_LEN; ++index)
    {
        const auto componentValue = teeTcbSvn[index];
        const auto& otherComponentValue = tcbLevel.getTdxTcbComponent(index);
        if(componentValue < otherComponentValue.getSvn())
        {
            // If *ANY* SVN is lower then TCB level is considered lower
            return false;
        }
    }
    // but for TCB level to be considered higher it requires *EVERY* SVN to be higher or equal
    return true;
}
const parser::json::TcbLevel& getMatchingTcbLevel(const dcap::parser::json::TcbInfo &tcbInfo,
                                       const dcap::parser::x509::PckCertificate &pckCert,
                                       const Quote &quote)
{
    const auto &tcbs = tcbInfo.getTcbLevels();
    const auto &pckTcb = pckCert.getTcb();
    const auto certPceSvn = pckTcb.getPceSvn();

    for (const auto& tcb : tcbs)
    {
        /// 4.1.2.4.17.1 & 4.1.2.4.17.2
        if(isCpuSvnHigherOrEqual(pckCert, tcb) && certPceSvn >= tcb.getPceSvn())
        {
            if (tcbInfo.getVersion() >= 3 &&
                tcbInfo.getId() == parser::json::TcbInfo::TDX_ID &&
                quote.getHeader().teeType == constants::TEE_TYPE_TDX)
            {
                /// 4.1.2.4.17.3
                if (isTdxTcbHigherOrEqual(quote, tcb))
                {
                    return tcb;
                }
            }
            else
            {
                return tcb;
            }
        }
    }

    /// 4.1.2.4.17.5
    LOG_ERROR("TCB Level has not been selected");
    throw RuntimeException(STATUS_TCB_NOT_SUPPORTED);
}

Status checkTdxModuleTcbStatus(const parser::json::TcbInfo &tcbInfoJson,
                               const Quote &quote)
{
    /// 4.1.2.4.17.4
    const auto &tdxModuleVersion = quote.getTeeTcbSvn()[1];
    const auto &tdxModuleIsvSvn = quote.getTeeTcbSvn()[0];

    if (quote.getHeader().version > constants::QUOTE_VERSION_3 && tdxModuleVersion == 0)
    {
        return STATUS_OK;
    }

    const std::string tdxModuleIdentityId = "TDX_" + bytesToHexString({ tdxModuleVersion });

    const auto &found = std::find_if(tcbInfoJson.getTdxModuleIdentities().begin(),
                                     tcbInfoJson.getTdxModuleIdentities().end(),
                                     [&](const auto &tdxModuleIdentity)
                                     {
                                         std::string id = tdxModuleIdentity.getId();
                                         std::transform(id.begin(), id.end(), id.begin(),
                                                        ::toupper); // convert to uppercase
                                         return (id == tdxModuleIdentityId);
                                     });
    if (found == std::end(tcbInfoJson.getTdxModuleIdentities())) {
        LOG_ERROR("Missing matching TDX Module Identity ({}) for given TEE TDX version ({})",
                  tdxModuleIdentityId, tdxModuleVersion);
        return STATUS_TDX_MODULE_MISMATCH;
    }
    const auto &foundTdxModuleTcbLevel = std::find_if(found->getTcbLevels().begin(),
                                                      found->getTcbLevels().end(),
                                                      [&](const auto &tdxModuleTcbLevel)
                                                      {
                                                          return tdxModuleIsvSvn >= tdxModuleTcbLevel.getTcb().getIsvSvn();
                                                      });
    if (foundTdxModuleTcbLevel == std::end(found->getTcbLevels()))
    {
        LOG_ERROR("Missing matching TDX Module Identity TCB Level (ISVSVN: {})", tdxModuleIsvSvn);
        return STATUS_TCB_NOT_SUPPORTED;
    }
    LOG_INFO("Matched to TDX Module Identity TCB Level with ISVSVN({}) from ID({})", foundTdxModuleTcbLevel->getTcb().getIsvSvn(), found->getId());
    const auto tcbLevelStatus = foundTdxModuleTcbLevel->getStatus();
    if (tcbLevelStatus == "UpToDate")
    {
        return STATUS_OK;
    }
    if (tcbLevelStatus == "OutOfDate")
    {
        return STATUS_TCB_OUT_OF_DATE;
    }
    if (tcbLevelStatus == "Revoked")
    {
        return STATUS_TCB_REVOKED;
    }
    LOG_ERROR("TDX Module TCB Level error status is unrecognized");
    throw RuntimeException(STATUS_TCB_UNRECOGNIZED_STATUS);
}

Status stringToTcbStatus(const dcap::parser::json::TcbInfo& tcbInfo, const std::string& tcbLevelStatus)
{
    if (tcbLevelStatus == "OutOfDate")
    {
        LOG_INFO("TCB Level status is \"OutOfDate\"");
        return STATUS_TCB_OUT_OF_DATE;
    }

    if (tcbLevelStatus == "Revoked")
    {
        LOG_INFO("TCB Level status is \"Revoked\"");
        return STATUS_TCB_REVOKED;
    }

    if (tcbLevelStatus == "ConfigurationNeeded")
    {
        LOG_INFO("TCB Level status is \"ConfigurationNeeded\"");
        return STATUS_TCB_CONFIGURATION_NEEDED;
    }

    if (tcbLevelStatus == "ConfigurationAndSWHardeningNeeded")
    {
        LOG_INFO("TCB Level status is \"ConfigurationAndSWHardeningNeeded\"");
        return STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED;
    }

    if (tcbLevelStatus == "UpToDate")
    {
        return STATUS_OK;
    }

    if (tcbLevelStatus == "SWHardeningNeeded")
    {
        LOG_INFO("TCB Level status is \"SWHardeningNeeded\"");
        return STATUS_TCB_SW_HARDENING_NEEDED;
    }

    if(tcbInfo.getVersion() > 1 && tcbLevelStatus == "OutOfDateConfigurationNeeded")
    {
        LOG_INFO("TCB Level status is \"OutOfDateConfigurationNeeded\"");
        return STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED;
    }

    LOG_ERROR("TCB Level error status is unrecognized");
    throw RuntimeException(STATUS_TCB_UNRECOGNIZED_STATUS);
}

Status convergeTcbStatusWithTdxModuleStatus(Status tcbLevelStatus, Status tdxModuleStatus)
{
    if (tdxModuleStatus == STATUS_TCB_OUT_OF_DATE)
    {
        LOG_INFO("TDX Module TCB status is \"OutOfDate\" and TCB Level status is \"{}\"",
                 tcbLevelStatus);
        if (tcbLevelStatus == STATUS_OK ||
            tcbLevelStatus == STATUS_TCB_SW_HARDENING_NEEDED)
        {
            return STATUS_TCB_OUT_OF_DATE;
        }
        if (tcbLevelStatus == STATUS_TCB_CONFIGURATION_NEEDED ||
            tcbLevelStatus == STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED)
        {
            return STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED;
        }
    }
    if (tdxModuleStatus == STATUS_TCB_REVOKED)
    {
        LOG_INFO("TDX Module TCB status is \"Revoked\"");
        return STATUS_TCB_REVOKED;
    }

    switch (tcbLevelStatus)
    {
        case STATUS_TCB_OUT_OF_DATE:
        case STATUS_TCB_REVOKED:
        case STATUS_TCB_CONFIGURATION_NEEDED:
        case STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED:
        case STATUS_TCB_SW_HARDENING_NEEDED:
        case STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED:
        case STATUS_OK:
            return tcbLevelStatus;
        default:
            return STATUS_TCB_UNRECOGNIZED_STATUS;
    }
}

Status convergeTcbStatusWithQeTcbStatus(Status tcbLevelStatus, Status qeTcbStatus)
{
    if (qeTcbStatus == STATUS_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE)
    {
        LOG_INFO("QE TCB status is \"OutOfDate\" and TCB Level status is \"{}\"",
                 tcbLevelStatus);
        if (tcbLevelStatus == STATUS_OK ||
            tcbLevelStatus == STATUS_TCB_SW_HARDENING_NEEDED)
        {
            return STATUS_TCB_OUT_OF_DATE;
        }
        if (tcbLevelStatus == STATUS_TCB_CONFIGURATION_NEEDED ||
            tcbLevelStatus == STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED)
        {
            return STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED;
        }
    }
    if (qeTcbStatus == STATUS_SGX_ENCLAVE_REPORT_ISVSVN_REVOKED)
    {
        LOG_INFO("QE TCB status is \"Revoked\"");
        return STATUS_TCB_REVOKED;
    }

    switch (tcbLevelStatus)
    {
        case STATUS_TCB_OUT_OF_DATE:
        case STATUS_TCB_REVOKED:
        case STATUS_TCB_CONFIGURATION_NEEDED:
        case STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED:
        case STATUS_TCB_SW_HARDENING_NEEDED:
        case STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED:
        case STATUS_OK:
            return tcbLevelStatus;
        default:
            /// 4.1.2.4.16.4
            return STATUS_TCB_UNRECOGNIZED_STATUS;
    }
}

Status checkTcbLevel(const dcap::parser::json::TcbInfo& tcbInfoJson, const dcap::parser::x509::PckCertificate& pckCert,
                     const Quote& quote)
{
    const auto& tcbLevel = getMatchingTcbLevel(tcbInfoJson, pckCert, quote);
    const auto tcbLevelStatus = tcbLevel.getStatus();

    if (tcbInfoJson.getVersion() >= 3 && tcbInfoJson.getId() == parser::json::TcbInfo::TDX_ID)
    {
        const auto tdxModuleTcbStatus = checkTdxModuleTcbStatus(tcbInfoJson, quote);
        if (tdxModuleTcbStatus == STATUS_TCB_NOT_SUPPORTED || tdxModuleTcbStatus == STATUS_TDX_MODULE_MISMATCH)
        {
            return tdxModuleTcbStatus;
        }

        const auto tdxComponents = tcbLevel.getTdxTcbComponents();
        std::vector<uint8_t>tdxTcbComponentsSvnsVec;
        for (const auto& component : tdxComponents)
        {
            tdxTcbComponentsSvnsVec.push_back(component.getSvn());
        }

        LOG_INFO("Selected TCB Level - sgx: {}, tdx: {}, pceSvn: {}, status: {},\n"
                 "PCK TCB - cpuSvn: {}, pceSvn: {}\n"
                 "TD Report - TdxSvn: {}",
                 bytesToHexString(tcbLevel.getCpuSvn()),
                 bytesToHexString(tdxTcbComponentsSvnsVec),
                 tcbLevel.getPceSvn(),
                 tcbLevelStatus,
                 bytesToHexString(pckCert.getTcb().getCpuSvn()),
                 pckCert.getTcb().getPceSvn(),
                 bytesToHexString(std::vector<uint8_t>(begin(quote.getTeeTcbSvn()), end(quote.getTeeTcbSvn()))));

        return convergeTcbStatusWithTdxModuleStatus(stringToTcbStatus(tcbInfoJson, tcbLevelStatus), tdxModuleTcbStatus);
    }
    else // deprecated
    {
        LOG_INFO("Selected TCB Level - sgx: {}, pceSvn: {}, status: {},\n"
                 "PCK TCB - cpuSvn: {}, pceSvn: {}",
                 bytesToHexString(tcbLevel.getCpuSvn()),
                 tcbLevel.getPceSvn(),
                 tcbLevelStatus,
                 bytesToHexString(pckCert.getTcb().getCpuSvn()),
                 pckCert.getTcb().getPceSvn());
    }

    return stringToTcbStatus(tcbInfoJson, tcbLevelStatus);
}

}//anonymous namespace

Status QuoteVerifier::verify(const Quote& quote,
                             const dcap::parser::x509::PckCertificate& pckCert,
                             const pckparser::CrlStore& crl,
                             const dcap::parser::json::TcbInfo& tcbInfoJson,
                             const EnclaveIdentityV2 *enclaveIdentity,
                             const EnclaveReportVerifier& enclaveReportVerifier)
{
    Status qeIdentityStatus = STATUS_QE_IDENTITY_MISMATCH;

    /// 4.1.2.4.4
    if (!_baseVerififer.commonNameContains(pckCert.getSubject(), constants::SGX_PCK_CN_PHRASE)) {
        LOG_ERROR("PCK Certificate. CN in Subject field does not contain \"SGX PCK Certificate\" phrase");
        return STATUS_INVALID_PCK_CERT;
    }

    /// 4.1.2.4.6
    if(!PckCrlVerifier{}.checkIssuer(crl))
    {
        LOG_ERROR("PCK Revocation List. CN in Issuer field does not contain \"CA\" phrase");
        return STATUS_INVALID_PCK_CRL;
    }

    const auto crlIssuerRaw = crl.getIssuer().raw;
    const auto pckCertIssuerRaw = pckCert.getIssuer().getRaw();
    if(crlIssuerRaw != pckCertIssuerRaw)
    {
        LOG_ERROR("Issuers in PCK revocation List and PCK Certificate are not the same. RL: {}, Cert: {}",
                  crlIssuerRaw, pckCertIssuerRaw);
        return STATUS_INVALID_PCK_CRL;
    }

    /// 4.1.2.4.7
    if(crl.isRevoked(pckCert))
    {
        LOG_ERROR("PCK Certificate is revoked by PCK Revocation List");
        return STATUS_PCK_REVOKED;
    }

    /// 4.1.2.4.9
    if(tcbInfoJson.getVersion() >= 3)
    {
        if(tcbInfoJson.getId() == parser::json::TcbInfo::TDX_ID && quote.getHeader().teeType != dcap::constants::TEE_TYPE_TDX)
        {
            LOG_ERROR("TcbInfo is generated for TDX and does not match Quote's TEE");
            return STATUS_TCB_INFO_MISMATCH;
        }
        if(tcbInfoJson.getId() == parser::json::TcbInfo::SGX_ID && quote.getHeader().teeType != dcap::constants::TEE_TYPE_SGX)
        {
            LOG_ERROR("TcbInfo is generated for SGX and does not match Quote's TEE");
            return STATUS_TCB_INFO_MISMATCH;
        }
    }
    else // deprecated
    {
        if(quote.getHeader().teeType == dcap::constants::TEE_TYPE_TDX)
        {
            LOG_ERROR("TcbInfo version {} is invalid for TDX TEE", tcbInfoJson.getVersion());
            return STATUS_TCB_INFO_MISMATCH;
        }
    }

    /// 4.1.2.4.10
    if(pckCert.getFmspc() != tcbInfoJson.getFmspc())
    {
        LOG_ERROR("FMSPC value from TcbInfo ({}) and SGX Extension in PCK Cert ({}) do not match",
                  bytesToHexString(tcbInfoJson.getFmspc()), bytesToHexString(pckCert.getFmspc()));
        return STATUS_TCB_INFO_MISMATCH;
    }

    if(pckCert.getPceId() != tcbInfoJson.getPceId())
    {
        LOG_ERROR("PCEID value from TcbInfo ({}) and SGX Extension in PCK Cert ({}) do not match",
                  bytesToHexString(tcbInfoJson.getPceId()), bytesToHexString(pckCert.getPceId()));
        return STATUS_TCB_INFO_MISMATCH;
    }

    const auto certificationDataVerificationStatus = verifyCertificationData(quote.getCertificationData());
    if(certificationDataVerificationStatus != STATUS_OK)
    {
        return certificationDataVerificationStatus;
    }

    auto pubKey = crypto::rawToP256PubKey(pckCert.getPubKey());
    if (pubKey == nullptr)
    {
        LOG_ERROR("Public key parsing error. PCK Certificate is invalid");
        return STATUS_INVALID_PCK_CERT; // if there were issues with parsing public key it means cert was invalid.
                                        // Probably it will never happen because parsing cert should fail earlier.
    }

    if (tcbInfoJson.getVersion() >= 3 && tcbInfoJson.getId() == parser::json::TcbInfo::TDX_ID)
    {
        /// 4.1.2.4.11
        const auto& tdxModule = tcbInfoJson.getTdxModule();
        const auto& quoteMrSignerSeam = quote.getMrSignerSeam();
        const auto& quoteSeamAttributes = quote.getSeamAttributes();

        const auto& tdxModuleVersion = quote.getTeeTcbSvn()[1];
        auto tdxModuleMrSigner = tdxModule.getMrSigner(); // can be overwritten by value from TDX Module Identity
        auto tdxModuleAttributes = tdxModule.getAttributes(); // can be overwritten by value from TDX Module Identity
        auto tdxModuleAttributesMask = tdxModule.getAttributesMask(); // can be overwritten by value from TDX Module Identity

        if (quote.getHeader().version > constants::QUOTE_VERSION_3 && tdxModuleVersion > 0)
        {
            try
            {
                tcbInfoJson.getTdxModuleIdentities();
            }
            catch (const parser::FormatException& ex)
            {
                LOG_ERROR("TDX Module version is {} but TCB Info structure returned: {}", tdxModuleVersion, ex.what());
                return STATUS_TCB_INFO_MISMATCH;
            }

            const std::string tdxModuleIdentityId = "TDX_" + bytesToHexString({ tdxModuleVersion });

            const auto& found = std::find_if(tcbInfoJson.getTdxModuleIdentities().begin(),
                                             tcbInfoJson.getTdxModuleIdentities().end(),
            [&](const auto &tdxModuleIdentity)
            {
                std::string id = tdxModuleIdentity.getId();
                std::transform(id.begin(), id.end(), id.begin(), ::toupper); // convert to uppercase
                return (id == tdxModuleIdentityId);
            });
            if (found == std::end(tcbInfoJson.getTdxModuleIdentities()))
            {
                LOG_ERROR("Missing matching TDX Module Identity ({}) for given TEE TDX version ({})", tdxModuleIdentityId, tdxModuleVersion);
                return STATUS_TDX_MODULE_MISMATCH;
            }
            tdxModuleMrSigner = found->getMrSigner();
            tdxModuleAttributes = found->getAttributes();
            tdxModuleAttributesMask = found->getAttributesMask();
        }

        /// 4.1.2.4.11.1
        if (quoteMrSignerSeam.size() != tdxModuleMrSigner.size())
        {
            LOG_ERROR("MRSIGNERSEAM value size from TdReport in Quote ({}) and MRSIGNER value size from TcbInfo ({}) are not the same",
                      quoteMrSignerSeam.size(), tdxModuleMrSigner.size());
            return STATUS_TDX_MODULE_MISMATCH;
        }

        for(uint32_t i = 0; i < tdxModuleMrSigner.size(); i++)
        {
            if (tdxModuleMrSigner[i] != quoteMrSignerSeam[i])
            {
                LOG_ERROR("MRSIGNERSEAM value from TdReport in Quote ({}) and MRSIGNER value from TcbInfo ({}) are not the same",
                          bytesToHexString(std::vector<uint8_t>(begin(quoteMrSignerSeam), end(quoteMrSignerSeam))),
                          bytesToHexString(std::vector<uint8_t>(begin(tdxModuleMrSigner), end(tdxModuleMrSigner))));
                return STATUS_TDX_MODULE_MISMATCH;
            }
        }

        /// 4.1.2.4.11.2
        if (quoteSeamAttributes.size() != tdxModuleAttributes.size())
        {
            LOG_ERROR("SEAMATTRIBUTES value size from TdReport in Quote ({}) and TDXMODULEATTRIBUTES value size from TcbInfo ({}) are not the same",
                      quoteMrSignerSeam.size(), tdxModuleMrSigner.size());
            return STATUS_TDX_MODULE_MISMATCH;
        }

        for (uint32_t i = 0; i < quoteSeamAttributes.size(); i++)
        {
            if (quoteSeamAttributes[i] != 0 || quoteSeamAttributes[i] != tdxModuleAttributes[i])
            {
                LOG_ERROR("SEAMATTRIBUTES values from TdReport in Quote ({}) and TDXMODULEATTRIBUTES from TcbInfo ({}) are not the same or not zeroed",
                          bytesToHexString(Bytes(quoteSeamAttributes.begin(), quoteSeamAttributes.end())),
                          bytesToHexString(tdxModuleAttributes));
                return STATUS_TDX_MODULE_MISMATCH;
            }
        }
    }

    /// 4.1.2.4.12
    if (!crypto::verifySha256EcdsaSignature(quote.getQeReportSignature(), quote.getQeReport().rawBlob(), *pubKey))
    {
        LOG_ERROR("QE Report Signature extracted from quote ({}) cannot be verified with the Public Key extracted from PCK Certificate ({})",
                  bytesToHexString(std::vector<uint8_t>(begin(quote.getQeReportSignature()), end(quote.getQeReportSignature()))),
                  bytesToHexString(pckCert.getPubKey()));
        return STATUS_INVALID_QE_REPORT_SIGNATURE;
    }

    /// 4.1.2.4.13
    const auto hashedConcatOfAttestKeyAndQeReportData = [&]() -> std::vector<uint8_t>
    {
        std::vector<uint8_t> ret;
        ret.reserve(quote.getAttestKeyData().size() + quote.getQeAuthData().size());
        std::copy(quote.getAttestKeyData().begin(), quote.getAttestKeyData().end(), std::back_inserter(ret));
        std::copy(quote.getQeAuthData().begin(), quote.getQeAuthData().end(), std::back_inserter(ret));

        return crypto::sha256Digest(ret);
    }();

    if(hashedConcatOfAttestKeyAndQeReportData.empty() || !std::equal(hashedConcatOfAttestKeyAndQeReportData.begin(),
                                                                     hashedConcatOfAttestKeyAndQeReportData.end(),
                                                                     quote.getQeReport().reportData.begin()))
    {
        LOG_ERROR("Report Data value extracted from QE Report in Quote ({}) and the value of SHA256 calculated over the concatenation of ECDSA Attestation Key and QE Authenticated Data extracted from Quote ({}) are not the same",
                  bytesToHexString(std::vector<uint8_t>(begin(quote.getQeReport().reportData), end(quote.getQeReport().reportData))),
                  bytesToHexString(hashedConcatOfAttestKeyAndQeReportData));
        return STATUS_INVALID_QE_REPORT_DATA;
    }

    if (enclaveIdentity)
    {
        /// 4.1.2.4.14
        if(quote.getHeader().teeType == dcap::constants::TEE_TYPE_TDX)
        {
            if(enclaveIdentity->getVersion() == 1)
            {
                LOG_ERROR("Enclave Identity version 1 is invalid for TDX TEE");
                return STATUS_QE_IDENTITY_MISMATCH;
            }
            else if(enclaveIdentity->getVersion() == 2)
            {
                if(enclaveIdentity->getID() != EnclaveID::TD_QE)
                {
                    LOG_ERROR("Enclave Identity is not generated for TDX and does not match Quote's TEE");
                    return STATUS_QE_IDENTITY_MISMATCH;
                }
            }
        }
        else if(quote.getHeader().teeType == dcap::constants::TEE_TYPE_SGX)
        {
            if(enclaveIdentity->getID() != EnclaveID::QE)
            {
                LOG_ERROR("Enclave Identity is not generated for SGX and does not match Quote's TEE");
                return STATUS_QE_IDENTITY_MISMATCH;
            }
        }
        else
        {
            LOG_ERROR("Unknown Quote's TEE. Enclave Identity cannot be valid");
            return STATUS_QE_IDENTITY_MISMATCH;
        }

        /// 4.1.2.4.15
        qeIdentityStatus = enclaveReportVerifier.verify(enclaveIdentity, quote.getQeReport());
        switch(qeIdentityStatus) {
            case STATUS_SGX_ENCLAVE_REPORT_UNSUPPORTED_FORMAT:
                return STATUS_UNSUPPORTED_QUOTE_FORMAT;
            case STATUS_SGX_ENCLAVE_IDENTITY_UNSUPPORTED_FORMAT:
            case STATUS_SGX_ENCLAVE_IDENTITY_INVALID:
            case STATUS_SGX_ENCLAVE_IDENTITY_UNSUPPORTED_VERSION:
                return STATUS_UNSUPPORTED_QE_IDENTITY_FORMAT;
            case STATUS_SGX_ENCLAVE_REPORT_MISCSELECT_MISMATCH:
            case STATUS_SGX_ENCLAVE_REPORT_ATTRIBUTES_MISMATCH:
            case STATUS_SGX_ENCLAVE_REPORT_MRSIGNER_MISMATCH:
            case STATUS_SGX_ENCLAVE_REPORT_ISVPRODID_MISMATCH:
                return STATUS_QE_IDENTITY_MISMATCH;
            case STATUS_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE:
            case STATUS_SGX_ENCLAVE_REPORT_ISVSVN_REVOKED:
            default:
                break;
        }
    }

    const auto attestKey = crypto::rawToP256PubKey(quote.getAttestKeyData());
    if(!attestKey)
    {
        return STATUS_UNSUPPORTED_QUOTE_FORMAT;
    }

    /// 4.1.2.4.16
    if (!crypto::verifySha256EcdsaSignature(quote.getQuoteSignature(),
                                            quote.getSignedData(),
                                            *attestKey))
    {
        LOG_ERROR("Quote Signature ({}) cannot be verified with ECDSA Attestation Key ({})",
                  bytesToHexString(std::vector<uint8_t>(begin(quote.getQuoteSignature()), end(quote.getQuoteSignature()))),
                  bytesToHexString(std::vector<uint8_t>(begin(quote.getAttestKeyData()), end(quote.getAttestKeyData()))));
        return STATUS_INVALID_QUOTE_SIGNATURE;
    }

    try
    {
        /// 4.1.2.4.17
        const auto tcbLevelStatus = checkTcbLevel(tcbInfoJson, pckCert, quote);

        if (tcbLevelStatus == STATUS_TCB_INFO_MISMATCH)
        {
            return STATUS_TCB_INFO_MISMATCH;
        }

        if (enclaveIdentity)
        {
            return convergeTcbStatusWithQeTcbStatus(tcbLevelStatus, qeIdentityStatus);
        }

        return tcbLevelStatus;
    }
    catch (const RuntimeException &ex)
    {
        return ex.getStatus();
    }
}

Status QuoteVerifier::verifyCertificationData(const CertificationData& certificationData) const
{
    if (certificationData.parsedDataSize != certificationData.data.size())
    {
        LOG_ERROR("Unexpected parsed data size, expected: {}, actual: {}",
                  certificationData.data.size(), certificationData.parsedDataSize);
        return STATUS_UNSUPPORTED_QUOTE_FORMAT;
    }

    return STATUS_OK;
}

}}} // namespace intel { namespace sgx { namespace dcap {
