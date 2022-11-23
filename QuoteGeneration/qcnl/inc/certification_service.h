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
/** File: certification_service.h
 *
 * Description: Header file of CertificationService class
 *
 */
#ifndef CERTIFICATIONSERVICE_H_
#define CERTIFICATIONSERVICE_H_
#pragma once

#include "certification_provider.h"
#include "network_wrapper.h"
#include "sgx_default_qcnl_wrapper.h"
#include <string>
#include <vector>

using namespace std;

class CertificationService {
private:
    string custom_param_;

protected:
    string get_custom_param_string();
    sgx_qcnl_error_t build_pckcert_options(const sgx_ql_pck_cert_id_t *p_pck_cert_id,
                                           http_header_map &header_map,
                                           string &query_string);
    sgx_qcnl_error_t build_pckcrl_options(const char *ca,
                                          uint16_t ca_size,
                                          http_header_map &header_map,
                                          string &query_string);
    sgx_qcnl_error_t build_tcbinfo_options(const char *fmspc,
                                           uint16_t fmspc_size,
                                           http_header_map &header_map,
                                           string &query_string);
    sgx_qcnl_error_t build_qeidentity_options(http_header_map &header_map, string &query_string);
    sgx_qcnl_error_t build_qveidentity_options(http_header_map &header_map, string &query_string);
    sgx_qcnl_error_t build_root_ca_crl_options(const char *root_ca_cdp_url, http_header_map &header_map, string &query_string);
    sgx_qcnl_error_t resp_obj_to_pck_certchain(PccsResponseObject *pccs_resp_obj,
                                               sgx_ql_config_t **pp_quote_config);
    sgx_qcnl_error_t resp_obj_to_pck_crl(PccsResponseObject *pccs_resp_obj,
                                         uint8_t **pp_crl_chain,
                                         uint16_t *p_crl_chain_size);
    sgx_qcnl_error_t resp_obj_to_tcbinfo(PccsResponseObject *pccs_resp_obj,
                                         uint8_t **pp_tcbinfo,
                                         uint16_t *p_tcbinfo_size);
    sgx_qcnl_error_t resp_obj_to_qe_identity(PccsResponseObject *pccs_resp_obj,
                                             uint8_t **pp_qe_identity,
                                             uint16_t *p_qe_identity_size);
    sgx_qcnl_error_t resp_obj_to_qve_identity(PccsResponseObject *pccs_resp_obj,
                                              char **pp_qve_identity,
                                              uint32_t *p_qve_identity_size,
                                              char **pp_qve_identity_issuer_chain,
                                              uint32_t *p_qve_identity_issuer_chain_size);
    sgx_qcnl_error_t resp_obj_to_root_ca_crl(PccsResponseObject *pccs_resp_obj,
                                             uint8_t **pp_root_ca_crl,
                                             uint16_t *p_root_ca_crl_size);

public:
    CertificationService();
    CertificationService(const char *custom_param);
    ~CertificationService();

    sgx_qcnl_error_t get_pck_cert_chain(const sgx_ql_pck_cert_id_t *p_pck_cert_id,
                                        sgx_ql_config_t **pp_quote_config);
    sgx_qcnl_error_t get_pck_crl_chain(const char *ca,
                                       uint16_t ca_size,
                                       uint8_t **pp_crl_chain,
                                       uint16_t *p_crl_chain_size);
    sgx_qcnl_error_t get_tcbinfo(sgx_prod_type_t prod_type,
                                 const char *fmspc,
                                 uint16_t fmspc_size,
                                 uint8_t **pp_tcbinfo,
                                 uint16_t *p_tcbinfo_size);
    sgx_qcnl_error_t get_qe_identity(sgx_qe_type_t qe_type,
                                     uint8_t **pp_qe_identity,
                                     uint16_t *p_qe_identity_size);
    sgx_qcnl_error_t get_qve_identity(char **pp_qve_identity,
                                      uint32_t *p_qve_identity_size,
                                      char **pp_qve_identity_issuer_chain,
                                      uint32_t *p_qve_identity_issuer_chain_size);
    sgx_qcnl_error_t get_root_ca_crl(const char *root_ca_cdp_url,
                                     uint8_t **pp_root_ca_crl,
                                     uint16_t *p_root_ca_crl_size);
};
#endif // CERTIFICATIONSERVICE_H_
