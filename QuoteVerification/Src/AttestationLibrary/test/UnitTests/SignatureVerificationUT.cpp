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

#include <OpensslHelpers/SignatureVerification.h>
#include <gtest/gtest.h>

#include "TestUtils/DigestUtils.h"
#include "TestUtils/KeyHelpers.h"

using namespace intel::sgx;

namespace{

std::array<uint8_t,64> getRawSig(const std::vector<uint8_t>& derSig)
{
    const long COMP_SIZE = 32;
    auto ecdsaSig = qvl::crypto::make_unique(ECDSA_SIG_new());
    auto sigPtr = ecdsaSig.get();
    auto it = derSig.data();

    d2i_ECDSA_SIG(&sigPtr, &it, static_cast<long>(derSig.size()));

    // internal pointers
    const BIGNUM *r,*s;
    ECDSA_SIG_get0(ecdsaSig.get(), &r, &s);

    auto bn2Vec = [&](const BIGNUM* bn) -> std::vector<uint8_t>{
        const int bnLen = BN_num_bytes(bn);
        if(bnLen <= 0)
        {
            return {};
        }
        std::vector<uint8_t> ret(static_cast<size_t>(bnLen));
        BN_bn2bin(bn, ret.data());
        return ret;
    };

    const auto rVec = bn2Vec(r);
    const auto sVec = bn2Vec(s);

    std::array<uint8_t, 64> ret;
    std::fill(ret.begin(), ret.end(), 0x00);
    const auto rOffset = static_cast<long>(COMP_SIZE - rVec.size());
    const auto sOffset = static_cast<long>(COMP_SIZE - sVec.size());

    std::copy_n(rVec.begin(), COMP_SIZE - rOffset, std::next(ret.begin(), rOffset));
    std::copy_n(sVec.begin(), COMP_SIZE - sOffset, std::next(ret.begin(), COMP_SIZE + sOffset));

    return ret;
}

}//anonymous namepsace

TEST(signatureVerification, shouldVerifyRawEcdsaSignature)
{
    // GIVEN
    auto prv = qvl::test::priv(qvl::test::PEM_PRV);
    auto evp = qvl::crypto::make_unique(EVP_PKEY_new());
    ASSERT_TRUE(1 == EVP_PKEY_set1_EC_KEY(evp.get(), prv.get()));
    auto pb = qvl::test::pub(qvl::test::PEM_PUB);
    ASSERT_TRUE(1 == EC_KEY_check_key(pb.get()));
    
    std::vector<uint8_t> data(150);
    std::fill(data.begin(), data.end(), 0xff);
    const auto sig = qvl::DigestUtils::signMessageSha256(data, *evp);
    ASSERT_TRUE(!sig.empty());
    ASSERT_TRUE(qvl::DigestUtils::verifySig(sig, data, *pb));

    // At this point we have valid keys and signature
    // Now we convert signature to raw bytes, convert bytes
    // to proper DER structure and it should be verified succesfully
    
    const auto rawSig = getRawSig(sig);

    // WHEN
    const auto convertedBackSignature = qvl::crypto::rawEcdsaSignatureToDER(rawSig);

    // THEN
    EXPECT_TRUE(qvl::DigestUtils::verifySig(convertedBackSignature, data, *pb));
}
