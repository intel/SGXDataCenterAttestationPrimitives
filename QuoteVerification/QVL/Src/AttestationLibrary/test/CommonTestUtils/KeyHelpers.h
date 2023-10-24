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

#ifndef INTEL_SGX_QVL_TEST_KEY_HELPERS_H_
#define INTEL_SGX_QVL_TEST_KEY_HELPERS_H_

#include <OpensslHelpers/OpensslTypes.h>
#include <array>
#include <vector>
#include <algorithm>

namespace intel { namespace sgx { namespace dcap { namespace test {

const std::string PEM_PRV = R"prv(
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINn0dPTHfFM1ljlBoyd6mV7dV9ukg3SpSHfpk0v13qSPoAoGCCqGSM49
AwEHoUQDQgAE3NtBLIzwdKqHMPGSiwIGYfpY1JI0hrxYu3ssRADj5pHfONfVB5uT
U4bF72+tHNCCy39Xk+iAJy0tU0VUH5TuDw==
-----END EC PRIVATE KEY-----
)prv";

const std::string PEM_PUB = R"pub(
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3NtBLIzwdKqHMPGSiwIGYfpY1JI0
hrxYu3ssRADj5pHfONfVB5uTU4bF72+tHNCCy39Xk+iAJy0tU0VUH5TuDw==
-----END PUBLIC KEY-----
)pub";

inline dcap::crypto::EVP_PKEY_uptr priv(const std::string& pem)
{
    auto bio = dcap::crypto::make_unique(BIO_new_mem_buf(static_cast<void*>(const_cast<char*>(pem.c_str())), static_cast<int>(pem.length())));
    return crypto::make_unique(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
}

inline dcap::crypto::EVP_PKEY_uptr pub(const std::string& pem)
{
    auto bio = dcap::crypto::make_unique(BIO_new_mem_buf(static_cast<void*>(const_cast<char*>(pem.c_str())), static_cast<int>(pem.length())));
    return crypto::make_unique(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
}

inline std::vector<uint8_t> getVectorPub(const EVP_PKEY& ecPubKey)
{
    auto pKeyLen = static_cast<size_t>(i2d_PublicKey(&ecPubKey, nullptr));
    auto pubKey = std::vector<uint8_t>(pKeyLen);
    auto data = pubKey.data();
    i2d_PublicKey(&ecPubKey, &data);

    return pubKey;
}

inline std::array<uint8_t,64> getRawPub(const EVP_PKEY& ecPubKey)
{
    std::vector<uint8_t> tmp = getVectorPub(ecPubKey);

    std::array<uint8_t,64> ret{};
    std::copy_n(tmp.begin() + 1, 64, ret.begin()); // omit header byte
    return ret;
}

}}}} //namespace intel { namespace sgx { namespace dcap { namespace test {

#endif
