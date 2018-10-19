/*
* Copyright (c) 2018, Intel Corporation
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
*    * Redistributions of source code must retain the above copyright notice,
*      this list of conditions and the following disclaimer.
*    * Redistributions in binary form must reproduce the above copyright
*      notice, this list of conditions and the following disclaimer in the
*      documentation and/or other materials provided with the distribution.
*    * Neither the name of Intel Corporation nor the names of its contributors
*      may be used to endorse or promote products derived from this software
*      without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "QEIdentityVerifier.h"
#include "TCBSigningChain.h"

#include <CertVerification/X509Constants.h>
#include <OpensslHelpers/SignatureVerification.h>

namespace intel { namespace sgx { namespace qvl {

QEIdentityVerifier::QEIdentityVerifier()
        : _commonVerifier(new CommonVerifier()),
          tcbSigningChain(new TCBSigningChain())
{
}

QEIdentityVerifier::QEIdentityVerifier(std::unique_ptr<CommonVerifier>&& _commonVerifier,
                                 std::unique_ptr<TCBSigningChain>&& tcbSigningChain)
        : _commonVerifier(std::move(_commonVerifier)), tcbSigningChain(std::move(tcbSigningChain))
{
}

Status QEIdentityVerifier::verify(
            const QEIdentityJsonVerifier &qeIdentityJson,
            const CertificateChain &chain,
            const pckparser::CrlStore &rootCaCrl,
            const pckparser::CertStore &trustedRoot) const
{
    const auto status = tcbSigningChain->verify(chain, rootCaCrl, trustedRoot);
    if (status != STATUS_OK)
    {
        return status;
    }

    const auto tcbSigningCert = chain.get(constants::TCB_SUBJECT);
    if(!_commonVerifier->checkSha256EcdsaSignature(
            qeIdentityJson.getSignature(), qeIdentityJson.getQeIdentityBody(), tcbSigningCert->getPubKey()))
    {
        return STATUS_SGX_QE_IDENTITY_INVALID_SIGNATURE;
    }

    return STATUS_OK;
}

}}} // namespace intel { namespace sgx { namespace qvl {
