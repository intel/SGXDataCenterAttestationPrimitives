/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
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

#include "OpensslInit.h"
#include "OpensslTypes.h"

#ifdef OPENSSL_THREADS
	#define OPENSSL_THREADS_SUPPORT_CHECK true
#else
	#define OPENSSL_THREADS_SUPPORT_CHECK false
#endif

namespace intel { namespace sgx { namespace qvl { namespace crypto {

static bool initialized = false;

bool init()
{
    static_assert(OPENSSL_THREADS_SUPPORT_CHECK == true, "OpenSSL report no thread support");
    
    if(initialized)
    {
        return true;
    }

    // they do not return error codes, but
    // they can fail if memory allocation will fail
    // not a big deal in practice but nevertheless
    // we should handle this here somehow and return false
#ifndef SGX_TRUSTED
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
#endif
    // as we're using openssl 1.1.0 we do not need to pass
    // locking callback for thread safety
    // openssl will recognize on which platform we're currently on
    // and will create proper locks

    initialized = true;
    return true;
}

void clear()
{
#ifndef SGX_TRUSTED
    if(initialized)
	{					
		EVP_cleanup();
		CRYPTO_cleanup_all_ex_data();
		ERR_free_strings();

		initialized = false;
	}
#endif
}

}}}} // namespace intel { namespace sgx { namespace qvl { namespace crypto {
