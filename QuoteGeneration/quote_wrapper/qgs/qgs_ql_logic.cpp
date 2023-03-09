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


#include "qgs_ql_logic.h"
#include "qgs_log.h"
#include "qgs_msg_lib.h"
#include "se_trace.h"
#include "sgx_ql_lib_common.h"
#include "td_ql_wrapper.h"
#include <boost/thread.hpp>
#include <boost/thread/detail/thread.hpp>
#include <boost/thread/tss.hpp>
#include <dlfcn.h>

typedef quote3_error_t (*get_collateral_func)(const uint8_t *fmspc,
                                              uint16_t fmspc_size, const char *pck_ca,
                                              tdx_ql_qve_collateral_t **pp_quote_collateral);
typedef quote3_error_t (*free_collateral_func)(tdx_ql_qve_collateral_t *p_quote_collateral);
extern "C" tee_att_error_t tee_att_get_qpl_handle(const tee_att_config_t *p_context, void **pp_qpl_handle);

void cleanup(tee_att_config_t *p_ctx) {
    QGS_LOG_INFO("About to delete ctx in cleanup\n");
    tee_att_free_context(p_ctx);
    return;
}

boost::thread_specific_ptr<tee_att_config_t> ptr(cleanup);

namespace intel { namespace sgx { namespace dcap { namespace qgs {

    data_buffer get_resp(uint8_t *p_req, uint32_t req_size) {

        tee_att_error_t tee_att_ret = TEE_ATT_SUCCESS;
        qgs_msg_error_t qgs_msg_error_ret = QGS_MSG_SUCCESS;
        uint8_t *p_resp = NULL;
        uint32_t resp_size = 0;
        uint32_t resp_error_code = QGS_MSG_ERROR_UNEXPECTED;

        QGS_LOG_INFO("enter prepare_response\n");
        if (ptr.get() == 0) {
            tee_att_error_t ret = TEE_ATT_SUCCESS;
            tee_att_config_t *p_ctx = NULL;
            QGS_LOG_INFO("call tee_att_create_context\n");
            ret = tee_att_create_context(NULL, NULL, &p_ctx);
            if (TEE_ATT_SUCCESS == ret) {
                std::ostringstream oss;
                oss << boost::this_thread::get_id();
                QGS_LOG_INFO("create context in thread[%s]\n",
                            oss.str().c_str());
                ptr.reset(p_ctx);
            } else {
                QGS_LOG_ERROR("Cannot create context\n");
                return {};
            }
        }

        uint32_t req_type = QGS_MSG_TYPE_MAX;
        if (QGS_MSG_SUCCESS != qgs_msg_get_type(p_req, req_size, &req_type)) {
            QGS_LOG_ERROR("Cannot get msg type\n");
            return {};
        }
        switch (req_type) {
        case GET_QUOTE_REQ: {
            uint32_t size = 0;

            const uint8_t *p_report;
            uint32_t report_size;
            const uint8_t *p_id_list;
            uint32_t id_list_size;

            data_buffer quote_buf;

            qgs_msg_error_ret = qgs_msg_inflate_get_quote_req(p_req,
                                                        req_size,
                                                        &p_report, &report_size,
                                                        &p_id_list, &id_list_size);
            if (QGS_MSG_SUCCESS != qgs_msg_error_ret) {
                // TODO: need to define the error code list for R3AAL
                resp_error_code = QGS_MSG_ERROR_UNEXPECTED;
                QGS_LOG_ERROR("qgs_msg_inflate_get_quote_req return error\n");
            } else {

                int retry = 1;

                do {
                    sgx_target_info_t qe_target_info;
                    uint8_t hash[32] = {0};
                    size_t hash_size = sizeof(hash);
                    QGS_LOG_INFO("call tee_att_init_quote\n");
                    tee_att_ret = tee_att_init_quote(ptr.get(), &qe_target_info, false,
                                                    &hash_size,
                                                    hash);
                    if (TEE_ATT_SUCCESS != tee_att_ret) {
                        resp_error_code = QGS_MSG_ERROR_UNEXPECTED;
                        QGS_LOG_ERROR("tee_att_init_quote return 0x%x\n", tee_att_ret);
                    } else if (TEE_ATT_SUCCESS != (tee_att_ret = tee_att_get_quote_size(ptr.get(), &size))) {
                        resp_error_code = QGS_MSG_ERROR_UNEXPECTED;
                        QGS_LOG_ERROR("tee_att_get_quote_size return 0x%x\n", tee_att_ret);
                    } else {
                        quote_buf.resize(size);
                        tee_att_ret = tee_att_get_quote(ptr.get(),
                                                        p_report,
                                                        report_size,
                                                        NULL,
                                                        quote_buf.data(),
                                                        size);
                        if (TEE_ATT_SUCCESS != tee_att_ret) {
                            resp_error_code = QGS_MSG_ERROR_UNEXPECTED;
                            QGS_LOG_ERROR("tee_att_get_quote return 0x%x\n", tee_att_ret);
                        } else {
                            resp_error_code = QGS_MSG_SUCCESS;
                            QGS_LOG_INFO("tee_att_get_quote return Success\n");
                        }
                    }
                    // Only retry once when the return code is TEE_ATT_ATT_KEY_NOT_INITIALIZED
                } while (TEE_ATT_ATT_KEY_NOT_INITIALIZED == tee_att_ret && retry--);
            }
            if (resp_error_code == QGS_MSG_SUCCESS) {
                qgs_msg_error_ret = qgs_msg_gen_get_quote_resp(NULL, 0, quote_buf.data(), size, &p_resp, &resp_size);
            } else {
                qgs_msg_error_ret = qgs_msg_gen_error_resp(resp_error_code, GET_QUOTE_RESP, &p_resp, &resp_size);
            }
            if (QGS_MSG_SUCCESS != qgs_msg_error_ret) {
                QGS_LOG_ERROR("call qgs_msg_gen function failed\n");
                qgs_msg_free(p_resp);
                return {};
            }
            break;
        }
        case GET_COLLATERAL_REQ: {
            const uint8_t *p_fsmpc;
            uint32_t fsmpc_size;
            const uint8_t *p_pckca;
            uint32_t pckca_size;
            tdx_ql_qve_collateral_t *p_collateral = NULL;
            free_collateral_func free_func = NULL;

            qgs_msg_error_ret = qgs_msg_inflate_get_collateral_req(p_req,
                                                            req_size,
                                                            &p_fsmpc, &fsmpc_size,
                                                            &p_pckca, &pckca_size);
            if (QGS_MSG_SUCCESS != qgs_msg_error_ret || fsmpc_size >= UINT16_MAX) {
                resp_error_code = QGS_MSG_ERROR_UNEXPECTED;
                QGS_LOG_ERROR("qgs_msg_inflate_get_collateral_req return error\n");
            } else {
                do {
                    extern tee_att_error_t tee_att_get_qpl_handle(const tee_att_config_t *p_context,
                                                                void **pp_qpl_handle);

                    char *error1 = NULL;
                    char *error2 = NULL;
                    void *p_handle = NULL;
                    quote3_error_t quote3_ret = SGX_QL_SUCCESS;
                    tee_att_ret = ::tee_att_get_qpl_handle(ptr.get(), &p_handle);
                    if (TEE_ATT_SUCCESS != tee_att_ret || NULL == p_handle) {
                        resp_error_code = QGS_MSG_ERROR_UNEXPECTED;
                        QGS_LOG_ERROR("tee_att_get_qpl_handle return 0x%x\n", tee_att_ret);
                        break;
                    }

                    auto get_func = (get_collateral_func)dlsym(p_handle, "tdx_ql_get_quote_verification_collateral");
                    error1 = dlerror();
                    free_func = (free_collateral_func)dlsym(p_handle, "tdx_ql_free_quote_verification_collateral");
                    error2 = dlerror();
                    if ((NULL == error1) && (NULL != get_func) && (NULL == error2) && (NULL != free_func)) {
                        SE_PROD_LOG("Found tdx quote verification functions.\n");
                        quote3_ret = get_func(p_fsmpc, (uint16_t)fsmpc_size, (const char *)p_pckca, &p_collateral);
                        if (SGX_QL_SUCCESS != quote3_ret) {
                            resp_error_code = QGS_MSG_ERROR_UNEXPECTED;
                            QGS_LOG_ERROR("tdx_ql_get_quote_verification_collateral return %d\n", quote3_ret);
                            break;
                        } else {
                            resp_error_code = QGS_MSG_SUCCESS;
                            QGS_LOG_INFO("tdx_ql_get_quote_verification_collateral return SUCCESS\n");
                            break;
                        }
                    } else {
                        resp_error_code = QGS_MSG_ERROR_UNEXPECTED;
                        QGS_LOG_ERROR("Cannot find tdx quote verification functions.\n");
                        break;
                    }
                } while (0);
            }
            if (resp_error_code == QGS_MSG_SUCCESS) {
                qgs_msg_error_ret = qgs_msg_gen_get_collateral_resp(p_collateral->major_version, p_collateral->minor_version,
                                                                 (const uint8_t *)p_collateral->pck_crl_issuer_chain, p_collateral->pck_crl_issuer_chain_size,
                                                                 (const uint8_t *)p_collateral->root_ca_crl, p_collateral->root_ca_crl_size,
                                                                 (const uint8_t *)p_collateral->pck_crl, p_collateral->pck_crl_size,
                                                                 (const uint8_t *)p_collateral->tcb_info_issuer_chain, p_collateral->tcb_info_issuer_chain_size,
                                                                 (const uint8_t *)p_collateral->tcb_info, p_collateral->tcb_info_size,
                                                                 (const uint8_t *)p_collateral->qe_identity_issuer_chain, p_collateral->qe_identity_issuer_chain_size,
                                                                 (const uint8_t *)p_collateral->qe_identity, p_collateral->qe_identity_size,
                                                                 &p_resp, &resp_size);
                free_func(p_collateral);
            } else {
                qgs_msg_error_ret = qgs_msg_gen_error_resp(resp_error_code, GET_COLLATERAL_RESP, &p_resp, &resp_size);
            }
            if (QGS_MSG_SUCCESS != qgs_msg_error_ret) {
                QGS_LOG_ERROR("call qgs_msg_gen function failed\n");
                qgs_msg_free(p_resp);
                return {};
            }
            break;
        }
        default:
            QGS_LOG_ERROR("Whoops, bad request!");
            return {};
        }

        QGS_LOG_INFO("Return from get_resp\n");
        data_buffer resp(p_resp, p_resp + resp_size);
        qgs_msg_free(p_resp);
        return resp;
    }
}
} // namespace dcap
} // namespace sgx
} // namespace intel
