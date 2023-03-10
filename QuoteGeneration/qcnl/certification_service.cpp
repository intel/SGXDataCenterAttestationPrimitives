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
/**
 * File: certification_service.cpp
 *
 * Description: CertificationService class
 *
 */
#include "certification_service.h"
#include "qcnl_config.h"
#include "qcnl_util.h"
#include "se_memcpy.h"
#include "sgx_ql_lib_common.h"
#include <regex>

CertificationService::CertificationService() {
}

CertificationService::CertificationService(const char *custom_param) {
    if (custom_param)
        custom_param_ = custom_param;
}

CertificationService::~CertificationService() {
}

string CertificationService::get_custom_param_string() {
    if (custom_param_.empty())
        return "";

    // custom_param_ is BASE64 encoded string, so we need to escape '+','/','='
    string s = custom_param_;
    s = regex_replace(s, regex("\\+"), "%2B");
    s = regex_replace(s, regex("\\/"), "%2F");
    s = regex_replace(s, regex("\\="), "%3D");
    return "customParameter=" + s;
}

sgx_qcnl_error_t CertificationService::build_pckcert_options(const sgx_ql_pck_cert_id_t *p_pck_cert_id,
                                                             http_header_map &header_map,
                                                             string &query_string) {
    sgx_qcnl_error_t ret = SGX_QCNL_UNEXPECTED_ERROR;

    // Append QE ID
    query_string.append("pckcert?qeid=");
    if (!concat_string_with_hex_buf(query_string, p_pck_cert_id->p_qe3_id, p_pck_cert_id->qe3_id_size)) {
        return ret;
    }

    // Append encrypted PPID
    query_string.append("&encrypted_ppid=");
    if (p_pck_cert_id->p_encrypted_ppid == NULL) {
        uint8_t enc_ppid_unused[consts::ENC_PPID_SIZE] = {0};
        if (!concat_string_with_hex_buf(query_string, (const uint8_t *)&enc_ppid_unused, sizeof(enc_ppid_unused))) {
            return ret;
        }
    } else {
        if (!concat_string_with_hex_buf(query_string, p_pck_cert_id->p_encrypted_ppid, p_pck_cert_id->encrypted_ppid_size)) {
            return ret;
        }
    }

    // Append cpusvn
    query_string.append("&cpusvn=");
    if (!concat_string_with_hex_buf(query_string, reinterpret_cast<const uint8_t *>(p_pck_cert_id->p_platform_cpu_svn), sizeof(sgx_cpu_svn_t))) {
        return ret;
    }

    // Append pcesvn
    query_string.append("&pcesvn=");
    if (!concat_string_with_hex_buf(query_string, reinterpret_cast<const uint8_t *>(p_pck_cert_id->p_platform_pce_isv_svn), sizeof(sgx_isv_svn_t))) {
        return ret;
    }

    // Append pceid
    query_string.append("&pceid=");
    if (!concat_string_with_hex_buf(query_string, reinterpret_cast<const uint8_t *>(&p_pck_cert_id->pce_id), sizeof(p_pck_cert_id->pce_id))) {
        return ret;
    }

    // Custom request options
    Document &custom_options = QcnlConfig::Instance()->getCustomRequestOptions();
    if (!custom_options.IsNull() && custom_options.HasMember("get_cert") && custom_options["get_cert"].IsObject()) {
        // Custom parameters in JSON config
        if (custom_options["get_cert"].HasMember("params")) {
            Value &params = custom_options["get_cert"]["params"];
            if (params.IsObject()) {
                Value::ConstMemberIterator it = params.MemberBegin();
                while (it != params.MemberEnd()) {
                    if (it->value.IsString()) {
                        string key = it->name.GetString();
                        string value = it->value.GetString();
                        query_string.append("&").append(key).append("=").append(value);
                    }
                    it++;
                }
            }
        }
        // Custom headers in JSON config
        if (custom_options["get_cert"].HasMember("headers")) {
            Value &headers = custom_options["get_cert"]["headers"];
            if (headers.IsObject()) {
                Value::ConstMemberIterator it = headers.MemberBegin();
                while (it != headers.MemberEnd()) {
                    if (it->value.IsString()) {
                        string key = it->name.GetString();
                        string value = it->value.GetString();
                        header_map.insert(pair<string, string>(key, value));
                    }
                    it++;
                }
            }
        }
    }

    return SGX_QCNL_SUCCESS;
}

sgx_qcnl_error_t CertificationService::build_pckcrl_options(const char *ca,
                                                            uint16_t ca_size,
                                                            http_header_map &header_map,
                                                            string &query_string) {
    (void)header_map; // currently no custom headers for fetching pck crl
    (void)ca_size;

    // Append ca and encoding
    query_string.append("pckcrl?ca=").append(ca);
    if (is_collateral_service_pcs() || QcnlConfig::Instance()->getCollateralVersion() == "3.1") {
        query_string.append("&encoding=der");
    }
    if (!custom_param_.empty()) {
        query_string.append("&").append(get_custom_param_string());
    }

    return SGX_QCNL_SUCCESS;
}

sgx_qcnl_error_t CertificationService::build_tcbinfo_options(const char *fmspc,
                                                             uint16_t fmspc_size,
                                                             http_header_map &header_map,
                                                             string &query_string) {
    (void)header_map;

    // Append fmspc
    query_string.append("tcb?fmspc=");
    if (!concat_string_with_hex_buf(query_string, reinterpret_cast<const uint8_t *>(fmspc), fmspc_size)) {
        return SGX_QCNL_UNEXPECTED_ERROR;
    }
    if (!custom_param_.empty()) {
        query_string.append("&").append(get_custom_param_string());
    }

    return SGX_QCNL_SUCCESS;
}

sgx_qcnl_error_t CertificationService::build_qeidentity_options(http_header_map &header_map, string &query_string) {
    (void)header_map;

    query_string.append("qe/identity");
    if (!custom_param_.empty()) {
        query_string.append("?").append(get_custom_param_string());
    }

    return SGX_QCNL_SUCCESS;
}

sgx_qcnl_error_t CertificationService::build_qveidentity_options(http_header_map &header_map, string &query_string) {
    (void)header_map;

    query_string.append("qve/identity");
    if (!custom_param_.empty()) {
        query_string.append("?").append(get_custom_param_string());
    }

    return SGX_QCNL_SUCCESS;
}

sgx_qcnl_error_t CertificationService::build_root_ca_crl_options(const char *root_ca_cdp_url, http_header_map &header_map, string &query_string) {
    (void)header_map;

    if (!is_collateral_service_pcs()) {
        if (QcnlConfig::Instance()->getCollateralVersion() == "3.0") {
            // For PCCS API version 3.0, will call API /rootcacrl, and it will return HEX encoded CRL
            query_string.append("rootcacrl");
            if (!custom_param_.empty()) {
                query_string.append("?").append(get_custom_param_string());
            }
        } else if (QcnlConfig::Instance()->getCollateralVersion() == "3.1") {
            // For PCCS API version 3.0, will call API /crl, and it will return raw DER buffer
            query_string.append("crl?uri=").append(root_ca_cdp_url);
            if (!custom_param_.empty()) {
                query_string.append("&").append(get_custom_param_string());
            }
        } else {
            return SGX_QCNL_INVALID_CONFIG;
        }
    }

    return SGX_QCNL_SUCCESS;
}

sgx_qcnl_error_t CertificationService::resp_obj_to_pck_certchain(PccsResponseObject *pccs_resp_obj,
                                                                 sgx_ql_config_t **pp_quote_config) {
    sgx_qcnl_error_t ret = SGX_QCNL_UNEXPECTED_ERROR;

    PckCertResponseObject *pckcert_resp_obj = (PckCertResponseObject *)pccs_resp_obj;

    do {
        // Get TCBm , Issuer Chain, PCK certificate from response
        string tcbm = pckcert_resp_obj->get_tcbm();
        string certchain = pckcert_resp_obj->get_pckcert_issuer_chain();
        string pck_cert = pckcert_resp_obj->get_pckcert();
        if (tcbm.size() != (consts::CPUSVN_SIZE + consts::PCESVN_SIZE) * 2 || certchain.empty() || pck_cert.empty()) {
            qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Response message error. \n");
            ret = SGX_QCNL_MSG_ERROR;
            break;
        }

        certchain = unescape(certchain);

        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] sgx-Tcbm: %s \n", tcbm.c_str());
        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] pckCert: %s \n", pck_cert.c_str());
        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] sgx-Pck-Certificate-Issuer-Chain: %s \n", certchain.c_str());

        // allocate output buffer
        *pp_quote_config = (sgx_ql_config_t *)malloc(sizeof(sgx_ql_config_t));
        if (*pp_quote_config == NULL) {
            qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Out of memory. \n");
            ret = SGX_QCNL_OUT_OF_MEMORY;
            break;
        }
        memset(*pp_quote_config, 0, sizeof(sgx_ql_config_t));

        // set version
        (*pp_quote_config)->version = SGX_QL_CONFIG_VERSION_1;

        // set tcbm
        if (!hex_string_to_byte_array(reinterpret_cast<const uint8_t *>(tcbm.data()),
                                      consts::CPUSVN_SIZE * 2,
                                      reinterpret_cast<uint8_t *>(&(*pp_quote_config)->cert_cpu_svn),
                                      sizeof(sgx_cpu_svn_t))) {
            qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Failed to parse cpu svn. \n");
            ret = SGX_QCNL_MSG_ERROR;
            break;
        }
        if (!hex_string_to_byte_array(reinterpret_cast<const uint8_t *>(tcbm.data() + consts::CPUSVN_SIZE * 2),
                                      consts::PCESVN_SIZE * 2,
                                      reinterpret_cast<uint8_t *>(&(*pp_quote_config)->cert_pce_isv_svn),
                                      sizeof(sgx_isv_svn_t))) {
            qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Failed to parse pce svn. \n");
            ret = SGX_QCNL_MSG_ERROR;
            break;
        }

        // set certchain (leaf cert || intermediateCA || root CA || '\0')
        (*pp_quote_config)->cert_data_size = (uint32_t)(certchain.size() + pck_cert.size() + 1);
        (*pp_quote_config)->p_cert_data = (uint8_t *)malloc((*pp_quote_config)->cert_data_size);
        if (!(*pp_quote_config)->p_cert_data) {
            qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Out of memory. \n");
            ret = SGX_QCNL_OUT_OF_MEMORY;
            break;
        }
        if (memcpy_s((*pp_quote_config)->p_cert_data, (*pp_quote_config)->cert_data_size, pck_cert.data(), pck_cert.size()) != 0) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }
        if (memcpy_s((*pp_quote_config)->p_cert_data + pck_cert.size(), certchain.size(), certchain.data(), certchain.size()) != 0) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }
        (*pp_quote_config)->p_cert_data[(*pp_quote_config)->cert_data_size - 1] = 0;    // NULL terminator

        ret = SGX_QCNL_SUCCESS;
    } while (0);

    if (ret != SGX_QCNL_SUCCESS) {
        sgx_qcnl_free_pck_cert_chain(*pp_quote_config);
    }

    return ret;
}
sgx_qcnl_error_t CertificationService::resp_obj_to_pck_crl(PccsResponseObject *pccs_resp_obj,
                                                           uint8_t **pp_crl_chain,
                                                           uint16_t *p_crl_chain_size) {
    sgx_qcnl_error_t ret = SGX_QCNL_UNEXPECTED_ERROR;
    PckCrlResponseObject *pckcrl_resp_obj = (PckCrlResponseObject *)pccs_resp_obj;

    do {
        string certchain = pckcrl_resp_obj->get_pckcrl_issuer_chain();
        string crl = pckcrl_resp_obj->get_pckcrl();
        if (certchain.empty() || crl.empty()) {
            qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Response message error. \n");
            ret = SGX_QCNL_MSG_ERROR;
            break;
        }

        certchain = unescape(certchain);

        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] sgx-pck-crl-issuer-chain: %s \n", certchain.c_str());

        // Always append a NULL terminator to CRL and certchain
        *p_crl_chain_size = (uint16_t)(certchain.size() + crl.size() + 2);
        *pp_crl_chain = (uint8_t *)malloc(*p_crl_chain_size);
        if (*pp_crl_chain == NULL) {
            qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Out of memory. \n");
            ret = SGX_QCNL_OUT_OF_MEMORY;
            break;
        }

        // set certchain (crl || ('\0) || intermediateCA || root CA || '\0')
        uint8_t *ptr = *pp_crl_chain;
        if (memcpy_s(ptr, crl.size(), crl.data(), crl.size()) != 0) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }
        ptr += crl.size();
        *ptr++ = '\0'; // add NULL terminator

        if (memcpy_s(ptr, certchain.size(), certchain.data(), certchain.size()) != 0) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }
        ptr += certchain.size();
        *ptr = '\0'; // add NULL terminator

        ret = SGX_QCNL_SUCCESS;
    } while (0);

    if (ret != SGX_QCNL_SUCCESS) {
        sgx_qcnl_free_pck_crl_chain(*pp_crl_chain);
    }

    return ret;
}

sgx_qcnl_error_t CertificationService::resp_obj_to_tcbinfo(PccsResponseObject *pccs_resp_obj,
                                                           uint8_t **pp_tcbinfo,
                                                           uint16_t *p_tcbinfo_size) {
    sgx_qcnl_error_t ret = SGX_QCNL_UNEXPECTED_ERROR;
    TcbInfoResponseObject *tcbinfo_resp_obj = (TcbInfoResponseObject *)pccs_resp_obj;

    do {
        string certchain = tcbinfo_resp_obj->get_tcbinfo_issuer_chain();
        string tcbinfo = tcbinfo_resp_obj->get_tcbinfo();
        if (certchain.empty() || tcbinfo.empty()) {
            qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Response message error. \n");
            ret = SGX_QCNL_MSG_ERROR;
            break;
        }

        certchain = unescape(certchain);

        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] tcbinfo: %s \n", tcbinfo.c_str());
        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] tcb-info-issuer-chain: %s \n", tcbinfo.c_str());

        *p_tcbinfo_size = (uint16_t)(certchain.size() + tcbinfo.size() + 2);
        *pp_tcbinfo = (uint8_t *)malloc(*p_tcbinfo_size);
        if (*pp_tcbinfo == NULL) {
            qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Out of memory. \n");
            ret = SGX_QCNL_OUT_OF_MEMORY;
            break;
        }

        // set certchain (tcbinfo || '\0' || signingCA || root CA || '\0')
        if (memcpy_s(*pp_tcbinfo, *p_tcbinfo_size, tcbinfo.data(), tcbinfo.size()) != 0) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }
        (*pp_tcbinfo)[tcbinfo.size()] = '\0'; // add NULL terminator
        if (memcpy_s(*pp_tcbinfo + tcbinfo.size() + 1, certchain.size(), certchain.data(), certchain.size()) != 0) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }
        (*pp_tcbinfo)[*p_tcbinfo_size - 1] = '\0'; // add NULL terminator

        ret = SGX_QCNL_SUCCESS;
    } while (0);

    if (ret != SGX_QCNL_SUCCESS) {
        sgx_qcnl_free_tcbinfo(*pp_tcbinfo);
    }

    return ret;
}

sgx_qcnl_error_t CertificationService::resp_obj_to_qe_identity(PccsResponseObject *pccs_resp_obj,
                                                               uint8_t **pp_qe_identity,
                                                               uint16_t *p_qe_identity_size) {
    sgx_qcnl_error_t ret = SGX_QCNL_UNEXPECTED_ERROR;
    QeIdentityResponseObject *qe_identity_resp_obj = (QeIdentityResponseObject *)pccs_resp_obj;

    do {
        string certchain = qe_identity_resp_obj->get_enclave_id_issuer_chain();
        string qeidentity = qe_identity_resp_obj->get_qeidentity();
        if (certchain.empty() || qeidentity.empty()) {
            qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Response message error. \n");
            ret = SGX_QCNL_MSG_ERROR;
            break;
        }

        certchain = unescape(certchain);

        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] qe identity: %s \n", qeidentity.c_str());
        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] sgx-enclave-identity-issuer-chain: %s \n", certchain.c_str());

        *p_qe_identity_size = (uint16_t)(certchain.size() + qeidentity.size() + 2);
        *pp_qe_identity = (uint8_t *)malloc(*p_qe_identity_size);
        if (*pp_qe_identity == NULL) {
            qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Out of memory. \n");
            ret = SGX_QCNL_OUT_OF_MEMORY;
            break;
        }

        // set certchain (QE identity || '\0' || signingCA || root CA || '\0')
        if (memcpy_s(*pp_qe_identity, *p_qe_identity_size, qeidentity.data(), qeidentity.size()) != 0) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }
        (*pp_qe_identity)[qeidentity.size()] = '\0'; // add NULL terminator
        if (memcpy_s(*pp_qe_identity + qeidentity.size() + 1, certchain.size(), certchain.data(), certchain.size()) != 0) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }
        (*pp_qe_identity)[*p_qe_identity_size - 1] = '\0'; // add NULL terminator

        ret = SGX_QCNL_SUCCESS;
    } while (0);

    if (ret != SGX_QCNL_SUCCESS) {
        sgx_qcnl_free_qe_identity(*pp_qe_identity);
    }

    return ret;
}

sgx_qcnl_error_t CertificationService::resp_obj_to_qve_identity(PccsResponseObject *pccs_resp_obj,
                                                                char **pp_qve_identity,
                                                                uint32_t *p_qve_identity_size,
                                                                char **pp_qve_identity_issuer_chain,
                                                                uint32_t *p_qve_identity_issuer_chain_size) {
    sgx_qcnl_error_t ret = SGX_QCNL_UNEXPECTED_ERROR;
    QveIdentityResponseObject *qve_identity_resp_obj = (QveIdentityResponseObject *)pccs_resp_obj;

    do {
        string certchain = qve_identity_resp_obj->get_enclave_id_issuer_chain();
        string qveidentity = qve_identity_resp_obj->get_qveidentity();
        if (certchain.empty() || qveidentity.empty()) {
            qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Response message error. \n");
            ret = SGX_QCNL_MSG_ERROR;
            break;
        }

        certchain = unescape(certchain);

        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] qve identity: %s \n", qveidentity.c_str());
        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] sgx-enclave-identity-issuer-chain: %s \n", certchain.c_str());

        // allocate buffers
        *p_qve_identity_size = (uint32_t)qveidentity.size() + 1;
        *pp_qve_identity = (char *)malloc(*p_qve_identity_size);
        if (*pp_qve_identity == NULL) {
            qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Out of memory. \n");
            ret = SGX_QCNL_OUT_OF_MEMORY;
            break;
        }
        *p_qve_identity_issuer_chain_size = (uint32_t)(certchain.size() + 1);
        *pp_qve_identity_issuer_chain = (char *)malloc(*p_qve_identity_issuer_chain_size);
        if (*pp_qve_identity_issuer_chain == NULL) {
            qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Out of memory. \n");
            ret = SGX_QCNL_OUT_OF_MEMORY;
            break;
        }

        // set QvE identity
        if (memcpy_s(*pp_qve_identity, *p_qve_identity_size, qveidentity.data(), qveidentity.size()) != 0) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }
        (*pp_qve_identity)[*p_qve_identity_size - 1] = '\0'; // add NULL terminator

        // set certchain (signingCA || root CA)
        if (memcpy_s(*pp_qve_identity_issuer_chain, *p_qve_identity_issuer_chain_size, certchain.data(), certchain.size()) != 0) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }
        (*pp_qve_identity_issuer_chain)[*p_qve_identity_issuer_chain_size - 1] = '\0'; // add NULL terminator

        ret = SGX_QCNL_SUCCESS;
    } while (0);

    if (ret != SGX_QCNL_SUCCESS) {
        sgx_qcnl_free_qve_identity(*pp_qve_identity, *pp_qve_identity_issuer_chain);
    }

    return ret;
}

sgx_qcnl_error_t CertificationService::resp_obj_to_root_ca_crl(PccsResponseObject *pccs_resp_obj,
                                                               uint8_t **pp_root_ca_crl,
                                                               uint16_t *p_root_ca_crl_size) {
    sgx_qcnl_error_t ret = SGX_QCNL_UNEXPECTED_ERROR;

    do {
        string root_ca_crl = pccs_resp_obj->get_raw_body();

        *p_root_ca_crl_size = (uint16_t)(root_ca_crl.size() + 1);
        *pp_root_ca_crl = (uint8_t *)malloc(*p_root_ca_crl_size);
        if (*pp_root_ca_crl == NULL) {
            qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Out of memory. \n");
            ret = SGX_QCNL_OUT_OF_MEMORY;
            break;
        }

        // set Root CA CRL
        if (memcpy_s(*pp_root_ca_crl, *p_root_ca_crl_size, root_ca_crl.data(), root_ca_crl.size()) != 0) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }
        // Add NULL terminator
        (*pp_root_ca_crl)[(*p_root_ca_crl_size) - 1] = 0;

        ret = SGX_QCNL_SUCCESS;
    } while (0);

    if (ret != SGX_QCNL_SUCCESS) {
        sgx_qcnl_free_root_ca_crl(*pp_root_ca_crl);
    }

    return ret;
}

sgx_qcnl_error_t CertificationService::get_pck_cert_chain(const sgx_ql_pck_cert_id_t *p_pck_cert_id,
                                                          sgx_ql_config_t **pp_quote_config) {
    qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Getting pck certificate and chain. \n");

    sgx_qcnl_error_t ret = SGX_QCNL_SUCCESS;
    http_header_map header_map;
    string query_string;
    PccsResponseObject pccs_resp_obj;

    // build query options for getting pck certificate
    if ((ret = build_pckcert_options(p_pck_cert_id, header_map, query_string)) != SGX_QCNL_SUCCESS) {
        return ret;
    }

    // First try local service
    CertificationProvider localProvider(QcnlConfig::Instance()->getLocalPckUrl());
    if ((ret = localProvider.get_certification(header_map, query_string, &pccs_resp_obj)) == SGX_QCNL_SUCCESS) {
        qcnl_log(SGX_QL_LOG_INFO,
                 "[QCNL] Successfully fetched certificate from primary URL: '%s'. \n",
                 QcnlConfig::Instance()->getLocalPckUrl().c_str());
        return resp_obj_to_pck_certchain(&pccs_resp_obj, pp_quote_config);
    }

    // then try the cache. encrypted_ppid shouldn't be part of cache key because the caller will send
    // all 0 encrypted ppid sometimes
    string qs_without_ppid = regex_replace(query_string, regex("&encrypted_ppid=[0-9a-zA-Z]+&"), "&");
    CacheProvider cacheProvider(QcnlConfig::Instance()->getServerUrl());
    if ((ret = cacheProvider.get_certification(qs_without_ppid, &pccs_resp_obj)) == SGX_QCNL_SUCCESS) {
        return resp_obj_to_pck_certchain(&pccs_resp_obj, pp_quote_config);
    }

    // try the remote service at last
    qcnl_log(SGX_QL_LOG_INFO,
             "[QCNL] Certificate not found in local cache. Trying to fetch response from remote URL: '%s'. \n",
             QcnlConfig::Instance()->getServerUrl().c_str());
    CertificationProvider remoteProvider(QcnlConfig::Instance()->getServerUrl());
    if ((ret = remoteProvider.get_certification(header_map, query_string, &pccs_resp_obj)) == SGX_QCNL_SUCCESS) {
        qcnl_log(SGX_QL_LOG_INFO,
                 "[QCNL] Successfully fetched certificate from remote URL: '%s'. \n",
                 QcnlConfig::Instance()->getServerUrl().c_str());
        if ((ret = resp_obj_to_pck_certchain(&pccs_resp_obj, pp_quote_config)) == SGX_QCNL_SUCCESS) {
            // update cache
            ret = cacheProvider.set_certification((uint32_t)(QcnlConfig::Instance()->getCacheExpireHour() * 3600),
                                                  qs_without_ppid, &pccs_resp_obj);
        }
    }
    return ret;
}

sgx_qcnl_error_t CertificationService::get_pck_crl_chain(const char *ca,
                                                         uint16_t ca_size,
                                                         uint8_t **pp_crl_chain,
                                                         uint16_t *p_crl_chain_size) {
    qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Getting pck crl. \n");

    sgx_qcnl_error_t ret = SGX_QCNL_SUCCESS;
    http_header_map header_map;
    string query_string;
    PccsResponseObject pccs_resp_obj;

    // build query options for getting pck crl
    if ((ret = build_pckcrl_options(ca, ca_size, header_map, query_string)) != SGX_QCNL_SUCCESS) {
        return ret;
    }

    // First try local cache
    CacheProvider cacheProvider(QcnlConfig::Instance()->getCollateralServiceUrl());
    if ((ret = cacheProvider.get_certification(query_string, &pccs_resp_obj)) == SGX_QCNL_SUCCESS) {
        return resp_obj_to_pck_crl(&pccs_resp_obj, pp_crl_chain, p_crl_chain_size);
    }

    // Then try remote service
    CertificationProvider remoteProvider(QcnlConfig::Instance()->getCollateralServiceUrl());
    if ((ret = remoteProvider.get_certification(header_map, query_string, &pccs_resp_obj)) == SGX_QCNL_SUCCESS) {
        if ((ret = resp_obj_to_pck_crl(&pccs_resp_obj, pp_crl_chain, p_crl_chain_size)) == SGX_QCNL_SUCCESS) {
            // update cache
            ret = cacheProvider.set_certification((uint32_t)(QcnlConfig::Instance()->getVerifyCollateralExpireHour() * 3600),
                                                  query_string, &pccs_resp_obj);
        }
    }
    return ret;
}

sgx_qcnl_error_t CertificationService::get_tcbinfo(sgx_prod_type_t prod_type,
                                                   const char *fmspc,
                                                   uint16_t fmspc_size,
                                                   uint8_t **pp_tcbinfo,
                                                   uint16_t *p_tcbinfo_size) {
    qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Getting tcb info. \n");

    sgx_qcnl_error_t ret = SGX_QCNL_SUCCESS;
    http_header_map header_map;
    string query_string;
    PccsResponseObject pccs_resp_obj;

    string base_url = QcnlConfig::Instance()->getCollateralServiceUrl();
    if (prod_type == SGX_PROD_TYPE_TDX) {
        auto found = base_url.find("/sgx/");
        if (found != std::string::npos) {
            base_url = base_url.replace(found, 5, "/tdx/");
        } else {
            return SGX_QCNL_UNEXPECTED_ERROR;
        }
    }

    // build query options for getting tcbinfo
    if ((ret = build_tcbinfo_options(fmspc, fmspc_size, header_map, query_string)) != SGX_QCNL_SUCCESS) {
        return ret;
    }

    CacheProvider cacheProvider(base_url);
    if ((ret = cacheProvider.get_certification(query_string, &pccs_resp_obj)) == SGX_QCNL_SUCCESS) {
        return resp_obj_to_tcbinfo(&pccs_resp_obj, pp_tcbinfo, p_tcbinfo_size);
    }

    CertificationProvider remoteProvider(base_url);
    if ((ret = remoteProvider.get_certification(header_map, query_string, &pccs_resp_obj)) == SGX_QCNL_SUCCESS) {
        if ((ret = resp_obj_to_tcbinfo(&pccs_resp_obj, pp_tcbinfo, p_tcbinfo_size)) == SGX_QCNL_SUCCESS) {
            ret = cacheProvider.set_certification((uint32_t)(QcnlConfig::Instance()->getVerifyCollateralExpireHour() * 3600),
                                                  query_string, &pccs_resp_obj);
        }
    }
    return ret;
}

sgx_qcnl_error_t CertificationService::get_qe_identity(sgx_qe_type_t qe_type,
                                                       uint8_t **pp_qe_identity,
                                                       uint16_t *p_qe_identity_size) {
    qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Getting quote enclave identity. \n");

    sgx_qcnl_error_t ret = SGX_QCNL_SUCCESS;
    http_header_map header_map;
    string query_string;
    PccsResponseObject pccs_resp_obj;

    string base_url = QcnlConfig::Instance()->getCollateralServiceUrl();

    if (qe_type == SGX_QE_TYPE_TD) {
        auto found = base_url.find("/sgx/");
        if (found != std::string::npos) {
            base_url = base_url.replace(found, 5, "/tdx/");
        } else {
            return SGX_QCNL_UNEXPECTED_ERROR;
        }
    }

    if ((ret = build_qeidentity_options(header_map, query_string)) != SGX_QCNL_SUCCESS) {
        return ret;
    }

    CacheProvider cacheProvider(base_url);
    if ((ret = cacheProvider.get_certification(query_string, &pccs_resp_obj)) == SGX_QCNL_SUCCESS) {
        return resp_obj_to_qe_identity(&pccs_resp_obj, pp_qe_identity, p_qe_identity_size);
    }

    CertificationProvider remoteProvider(base_url);
    if ((ret = remoteProvider.get_certification(header_map, query_string, &pccs_resp_obj)) == SGX_QCNL_SUCCESS) {
        if ((ret = resp_obj_to_qe_identity(&pccs_resp_obj, pp_qe_identity, p_qe_identity_size)) == SGX_QCNL_SUCCESS) {
            ret = cacheProvider.set_certification((uint32_t)(QcnlConfig::Instance()->getVerifyCollateralExpireHour() * 3600),
                                                  query_string, &pccs_resp_obj);
        }
    }
    return ret;
}

sgx_qcnl_error_t CertificationService::get_qve_identity(char **pp_qve_identity,
                                                        uint32_t *p_qve_identity_size,
                                                        char **pp_qve_identity_issuer_chain,
                                                        uint32_t *p_qve_identity_issuer_chain_size) {
    qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Getting quote verification enclave identity. \n");

    sgx_qcnl_error_t ret = SGX_QCNL_SUCCESS;
    http_header_map header_map;
    string query_string;
    PccsResponseObject pccs_resp_obj;

    string base_url = QcnlConfig::Instance()->getCollateralServiceUrl();

    if ((ret = build_qveidentity_options(header_map, query_string)) != SGX_QCNL_SUCCESS) {
        return ret;
    }

    CacheProvider cacheProvider(base_url);
    if ((ret = cacheProvider.get_certification(query_string, &pccs_resp_obj)) == SGX_QCNL_SUCCESS) {
        return resp_obj_to_qve_identity(&pccs_resp_obj, pp_qve_identity, p_qve_identity_size,
                                        pp_qve_identity_issuer_chain, p_qve_identity_issuer_chain_size);
    }

    CertificationProvider remoteProvider(base_url);
    if ((ret = remoteProvider.get_certification(header_map, query_string, &pccs_resp_obj)) == SGX_QCNL_SUCCESS) {
        if ((ret = resp_obj_to_qve_identity(&pccs_resp_obj, pp_qve_identity, p_qve_identity_size,
                                            pp_qve_identity_issuer_chain, p_qve_identity_issuer_chain_size)) == SGX_QCNL_SUCCESS) {
            ret = cacheProvider.set_certification((uint32_t)(QcnlConfig::Instance()->getVerifyCollateralExpireHour() * 3600),
                                                  query_string, &pccs_resp_obj);
        }
    }
    return ret;
}

sgx_qcnl_error_t CertificationService::get_root_ca_crl(const char *root_ca_cdp_url,
                                                       uint8_t **pp_root_ca_crl,
                                                       uint16_t *p_root_ca_crl_size) {
    qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Getting root ca crl. \n");

    sgx_qcnl_error_t ret = SGX_QCNL_SUCCESS;
    http_header_map header_map;
    string query_string;
    PccsResponseObject pccs_resp_obj;

    string base_url = QcnlConfig::Instance()->getCollateralServiceUrl();
    if (is_collateral_service_pcs()) {
        base_url = root_ca_cdp_url;
    } else {
        ret = build_root_ca_crl_options(root_ca_cdp_url, header_map, query_string);
        if (ret != SGX_QCNL_SUCCESS) {
            return ret;
        }
    }

    CacheProvider cacheProvider(base_url);
    if ((ret = cacheProvider.get_certification(query_string, &pccs_resp_obj)) == SGX_QCNL_SUCCESS) {
        return resp_obj_to_root_ca_crl(&pccs_resp_obj, pp_root_ca_crl, p_root_ca_crl_size);
    }

    CertificationProvider remoteProvider(base_url);
    if ((ret = remoteProvider.get_certification(header_map, query_string, &pccs_resp_obj)) == SGX_QCNL_SUCCESS) {
        if ((ret = resp_obj_to_root_ca_crl(&pccs_resp_obj, pp_root_ca_crl, p_root_ca_crl_size)) == SGX_QCNL_SUCCESS) {
            ret = cacheProvider.set_certification((uint32_t)(QcnlConfig::Instance()->getVerifyCollateralExpireHour() * 3600),
                                                  query_string, &pccs_resp_obj);
        }
    }
    return ret;
}
