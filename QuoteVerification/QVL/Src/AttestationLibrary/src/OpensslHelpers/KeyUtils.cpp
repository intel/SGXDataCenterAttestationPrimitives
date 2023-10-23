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

#include "KeyUtils.h"

#include <openssl/param_build.h>

#include <algorithm>
#include <array>
#include <iterator>

namespace intel::sgx::dcap::crypto {

crypto::EVP_PKEY_uptr rawToP256PubKey(const std::array<uint8_t, 64>& rawKey)
{
    // prepare key structs
    EVP_PKEY *pubKey = nullptr;
    auto pkey = crypto::make_unique<EVP_PKEY>(nullptr);
    // prepare public key raw data
    auto data = std::vector<uint8_t>();
    data.reserve(rawKey.size() + 1);
    data.insert(data.begin(), POINT_CONVERSION_UNCOMPRESSED);
    std::copy(rawKey.begin(), rawKey.end(), std::back_inserter(data));
    // prepare OSSL params
    OSSL_PARAM_BLD_uptr param_bld = crypto::make_unique<OSSL_PARAM_BLD>(OSSL_PARAM_BLD_new());
    if (param_bld.get() == nullptr
        || OSSL_PARAM_BLD_push_utf8_string(param_bld.get(), "group",SN_X9_62_prime256v1, 0) != 1)
    {
        return pkey; // empty key
    }
    OSSL_PARAM_uptr params = crypto::make_unique<OSSL_PARAM>(OSSL_PARAM_BLD_to_param(param_bld.get()));
    EVP_PKEY_CTX_uptr ctx = crypto::make_unique<EVP_PKEY_CTX>(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (ctx.get() == nullptr
        || params.get() == nullptr
        || EVP_PKEY_fromdata_init(ctx.get()) <= 0
        || EVP_PKEY_fromdata(ctx.get(), &pubKey, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, params.get()) <= 0)
    {
        return pkey; // empty key
    }
    pkey.reset(pubKey);
    if (pkey.get() == nullptr)
    {
        return pkey; // empty key
    }
    const auto *pp = data.data();
    auto ret = d2i_PublicKey(EVP_PKEY_EC, &pubKey, &pp, static_cast<long>(data.size()));
    if (ret == nullptr)
    {
        return crypto::make_unique<EVP_PKEY>(nullptr); // empty key
    }
    return pkey; // valid key
}

crypto::EVP_PKEY_uptr rawToP256PubKey(const std::vector<uint8_t>& rawKey)
{
    std::array<uint8_t, 64> raw{};
    std::copy_n(rawKey.begin() + 1, raw.size(), raw.begin()); // skip header byte

    return rawToP256PubKey(raw);
}

} // intel::sgx::dcap::crypto
