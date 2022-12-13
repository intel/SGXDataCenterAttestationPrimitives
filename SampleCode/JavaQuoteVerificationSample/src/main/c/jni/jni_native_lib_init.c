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


#include "jni_native_lib_init.h"
#include <dlfcn.h>
#include <sgx_dcap_quoteverify.h>
#include <stdio.h>
#include <stdlib.h>
static void *lib_handle = NULL;

static char *lib_name = "libsgx_dcap_quoteverify.so";
sgx_qv_free_qve_identity_t qvl_sgx_qv_free_qve_identity = NULL;
sgx_qv_get_quote_supplemental_data_size_t
    qvl_sgx_qv_get_quote_supplemental_data_size = NULL;
sgx_qv_get_qve_identity_t qvl_sgx_qv_get_qve_identity = NULL;
sgx_qv_set_enclave_load_policy_t qvl_sgx_qv_set_enclave_load_policy = NULL;
sgx_qv_set_path_t qvl_sgx_qv_set_path = NULL;
sgx_qv_verify_quote_t qvl_sgx_qv_verify_quote = NULL;
tee_qv_get_collateral_t qvl_tee_qv_get_collateral = NULL;
tee_qv_free_collateral_t qvl_tee_qv_free_collateral = NULL;
tee_get_supplemental_data_version_and_size_t qvl_tee_get_supplemental_data_version_and_size = NULL;
tee_tee_verify_quote_t qvl_tee_verify_quote = NULL;

static char const *const sym_names[] = {
    [0] = "sgx_qv_free_qve_identity",
    [1] = "sgx_qv_get_quote_supplemental_data_size",
    [2] = "sgx_qv_get_qve_identity",
    [3] = "sgx_qv_set_enclave_load_policy",
    [4] = "sgx_qv_set_path",
    [5] = "sgx_qv_verify_quote",
    [6] = "tee_qv_get_collateral",
    [7] = "tee_qv_free_collateral",
    [8] = "tee_get_supplemental_data_version_and_size",
    [9] = "tee_verify_quote",
};
#define CHECK(cond, fmt, ...)                                                  \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "libsgx_dcap_quoteverify.so.1: " fmt "\n",               \
              ##__VA_ARGS__);                                                  \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
    dlerror();                                                                 \
  } while (0)

__attribute__((constructor))
int load_lib() {
  lib_handle = dlopen(lib_name, RTLD_LAZY | RTLD_GLOBAL);
  CHECK(lib_handle, "failed to load library via dlopen: %s", dlerror());

  qvl_sgx_qv_free_qve_identity =
      (sgx_qv_free_qve_identity_t)dlsym(lib_handle, sym_names[0]);
  CHECK(qvl_sgx_qv_free_qve_identity, "failed to resolve symbol '%s'",
        sym_names[0]);

  qvl_sgx_qv_get_quote_supplemental_data_size =
      (sgx_qv_get_quote_supplemental_data_size_t)dlsym(lib_handle,
                                                       sym_names[1]);
  CHECK(qvl_sgx_qv_get_quote_supplemental_data_size,
        "failed to resolve symbol '%s'", sym_names[1]);

  qvl_sgx_qv_get_qve_identity =
      (sgx_qv_get_qve_identity_t)dlsym(lib_handle, sym_names[2]);
  CHECK(qvl_sgx_qv_get_qve_identity,
        "failed to resolve symbol '%s'", sym_names[2]);

  qvl_sgx_qv_set_enclave_load_policy =
      (sgx_qv_set_enclave_load_policy_t)dlsym(lib_handle, sym_names[3]);
  CHECK(qvl_sgx_qv_set_enclave_load_policy, "failed to resolve symbol '%s'",
        sym_names[3]);

  qvl_sgx_qv_set_path =
      (sgx_qv_set_path_t)dlsym(lib_handle,sym_names[4]);
  CHECK(qvl_sgx_qv_set_path, "failed to resolve symbol '%s'",
        sym_names[4]);

  qvl_sgx_qv_verify_quote =
      (sgx_qv_verify_quote_t)dlsym(lib_handle, sym_names[5]);
  CHECK(qvl_sgx_qv_verify_quote, "failed to resolve symbol '%s'", sym_names[5]);

  qvl_tee_qv_get_collateral = (tee_qv_get_collateral_t)dlsym(lib_handle, sym_names[6]);
  CHECK(qvl_tee_qv_get_collateral, "failed to resolve symbol '%s'", sym_names[6]);

  qvl_tee_qv_free_collateral = (tee_qv_free_collateral_t)dlsym(lib_handle, sym_names[7]);
  CHECK(qvl_tee_qv_free_collateral, "failed to resolve symbol '%s'", sym_names[7]);
  
  qvl_tee_get_supplemental_data_version_and_size = (tee_get_supplemental_data_version_and_size_t)dlsym(lib_handle, sym_names[8]);
  CHECK(qvl_tee_get_supplemental_data_version_and_size, "failed to resolve symbol '%s'", sym_names[8]);

  qvl_tee_verify_quote = (tee_tee_verify_quote_t)dlsym(lib_handle, sym_names[9]);
  CHECK(qvl_tee_verify_quote, "failed to resolve symbol '%s'", sym_names[9]);
  return 0;
}

__attribute__((destructor))
void unload_lib() {
  if (NULL != lib_handle) {
    dlclose(lib_handle);
  }
}