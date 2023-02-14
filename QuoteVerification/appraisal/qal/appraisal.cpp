/*
 * Copyright (C) 2011-2023 Intel Corporation. All rights reserved.
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

#include "sgx_dcap_qal.h"
#include <iostream>
#include "jwt-cpp/jwt.h"
#include <stdlib.h>
#include <string>
#include <sstream>
#include "opa_wasm.h"
#include "se_thread.h"
#include "se_trace.h"

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

static bool g_wasm_prepared = false;
static se_mutex_t g_wasm_mutex;

#define CHECK_NULL_BREAK(p) if(!p){ break;}

static void __attribute__((constructor)) _sgx_qal_init()
{
    OPAEvaluateEngine::getInstance();
    se_mutex_init(&g_wasm_mutex);
}

static void __attribute__((destructor)) _sgx_qal_fini()
{
    se_mutex_destroy(&g_wasm_mutex);
}

static quote3_error_t prepare_wasm_once()
{
    quote3_error_t ret = SGX_QL_ERROR_UNEXPECTED;
    if (g_wasm_prepared == true)
    {
        // wasm env only needs to prepare once
        return SGX_QL_SUCCESS;
    }
    else
    {
        se_mutex_lock(&g_wasm_mutex);
        if (g_wasm_prepared == false)
        {
            ret = OPAEvaluateEngine::getInstance()->prepare_wasm();
            if (ret != SGX_QL_SUCCESS)
            {
                se_mutex_unlock(&g_wasm_mutex);
                SE_TRACE(SE_TRACE_ERROR, "prepare wasm failed\n");
                return ret;
            }
            g_wasm_prepared = true;
        }
        se_mutex_unlock(&g_wasm_mutex);
    }
    return ret;
}

typedef enum _claim_type_t
{
    HEADER,
    PAYLOAD
} claim_type_t;

static std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> ECPubKeyFromXY(const std::string &x, const std::string &y)
{
    const auto dx = jwt::base::decode<jwt::alphabet::base64url>(jwt::base::pad<jwt::alphabet::base64url>(x));
    const auto dy = jwt::base::decode<jwt::alphabet::base64url>(jwt::base::pad<jwt::alphabet::base64url>(y));
    BIGNUM *bx = NULL;
    BIGNUM *by = NULL;
    EC_POINT *q = NULL;
    EC_KEY *ec = NULL;
    EVP_PKEY *pkey = NULL;
    bool flag = false;

    do
    {
        bx = BN_bin2bn(reinterpret_cast<const unsigned char *>(dx.c_str()), (int)dx.length(), 0);
        CHECK_NULL_BREAK(bx);
        by = BN_bin2bn(reinterpret_cast<const unsigned char *>(dy.c_str()), (int)dy.length(), 0);
        CHECK_NULL_BREAK(by);
 
        ec = EC_KEY_new_by_curve_name(NID_secp384r1);
        CHECK_NULL_BREAK(ec);
        const EC_GROUP *g = EC_KEY_get0_group(ec);

        q = EC_POINT_new(g);
        CHECK_NULL_BREAK(q);

        if(EC_POINT_set_affine_coordinates_GFp(g, q, bx, by, NULL)!=1)
        {
            break;
        }
        if(EC_KEY_set_public_key(ec, q) != 1)
        {
            break;
        }
        pkey = EVP_PKEY_new();
        CHECK_NULL_BREAK(pkey);

        if(EVP_PKEY_assign_EC_KEY(pkey, ec) != 1)
        {
            break;
        }
        flag = true;
    } while (0);

    if (bx)
    {
        BN_free(bx);
    }
    if (by)
    {
        BN_free(by);
    }
    if (q)
    {
        EC_POINT_free(q);
    }

    if (flag == false)
    {
        if (pkey)
        {
            // No need to free ec as below function will free it as well.
            EVP_PKEY_free(pkey);
        }
        else if (ec)
        {
            EC_KEY_free(ec);
        }
        return std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(nullptr, nullptr);
    }
    else
    {
        return std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(pkey, EVP_PKEY_free);
    }

}

static bool convert_jwk_to_pem_str(std::string jwk_json, std::string &pem_str)
{
    if (jwk_json.empty() == true)
    {
        return false;
    }
    rapidjson::Document jwk_doc;
    jwk_doc.Parse(jwk_json.c_str());
    if (jwk_doc.HasParseError() || jwk_doc.HasMember("x") == false || jwk_doc.HasMember("y") == false)
    {
        return false;
    }
    rapidjson::Value &vx = jwk_doc["x"];
    rapidjson::Value &vy = jwk_doc["y"];
    if (vx.IsString() == false || vy.IsString() == false)
    {
        return false;
    }
    auto ec_pubkey = ECPubKeyFromXY(vx.GetString(), vy.GetString());
    if (!ec_pubkey)
    {
        return false;
    }

    BIO *bio = NULL;
    if (!(bio = BIO_new(BIO_s_mem())))
    {
        return false;
    }

    if (0 == PEM_write_bio_PUBKEY(bio, ec_pubkey.get()))
    {
        BIO_free(bio);
        return false;
    }
    size_t st = BIO_number_written(bio) + 1;
    char *pem = (char *)malloc(st);
    if (pem == NULL)
    {
        BIO_free(bio);
        return false;
    }
    memset(pem, 0, st);
    if (BIO_read(bio, pem, (int)st - 1) <= 0)
    {
        BIO_free(bio);
        free(pem);
        return false;
    }
    pem_str = pem;
    BIO_free(bio);
    free(pem);
    return true;
}

static std::string get_info_from_jwt(const char *p_jwt_str, const char *claim_name, claim_type_t ctype, std::string &signature, std::string &jwk)
{
    if (p_jwt_str == NULL || claim_name == NULL || (ctype != HEADER && ctype != PAYLOAD))
        return "";
    std::string jwt_str(p_jwt_str);
    try
    {
        auto decoded = jwt::decode(jwt_str);
        auto alg = decoded.get_algorithm();
        auto typ = decoded.get_type();

        if ((alg == "none" && typ == "JWT"))
        {
            if (ctype == HEADER)
            {
                if (decoded.has_header_claim(claim_name) == false)
                    return "";
                auto claim = decoded.get_header_claim(claim_name);
                return claim.to_json().to_str();
            }
            else
            {
                if (decoded.has_payload_claim(claim_name) == false)
                    return "";
                auto claim = decoded.get_payload_claim(claim_name);
                return claim.to_json().to_str();
            }
        }
        else if (alg == "ES384" && (typ == "JWS" || typ == "JWT"))
        {
            // If the jwt has alg, it should have public key in the JWT header
            // we need to get the jwk first and verify the jwt
            if (decoded.has_header_claim("jwk") == false)
            {
                return "";
            }
            auto jwk_json = decoded.get_header_claim("jwk").to_json();

            std::string pub_key;
            if (convert_jwk_to_pem_str(jwk_json.to_str(), pub_key) == false)
            {
                SE_TRACE(SE_TRACE_ERROR, "Fail to convert jwk to pem\n");
                return "";
            }
            auto verifier =
                jwt::verify()
                    .allow_algorithm(jwt::algorithm::es384(pub_key));
            try
            {
                verifier.verify(decoded);
            }
            catch (...)
            {
                SE_TRACE(SE_TRACE_ERROR, "Fail to verify the JWT: \n%s\n\n", jwt_str.c_str());
                return "";
            }

            // After verify, we can get the header or payload
            signature = decoded.get_signature_base64();
            jwk = jwk_json.to_str();
            if (ctype == HEADER)
            {
                if (decoded.has_header_claim(claim_name) == false)
                    return "";
                auto claim = decoded.get_header_claim(claim_name);
                return claim.to_json().to_str();
            }
            else
            {
                if (decoded.has_payload_claim(claim_name) == false)
                    return "";
                auto claim = decoded.get_payload_claim(claim_name);
                return claim.to_json().to_str();
            }
        }
    }
    catch (...)
    {
        SE_TRACE(SE_TRACE_ERROR, "Fail to verify the JWT: \n%s\n\n", jwt_str.c_str());
    }
    // Don't support other alg/types
    return "";
}

static quote3_error_t construct_complete_json(const uint8_t *p_verification_result_token, uint8_t **p_qaps, uint8_t qaps_count, std::string &output_json)
{
    rapidjson::Document json_doc, qvl_doc;
    json_doc.SetObject();

    // 1: qvl_result
    std::string qvl_result = "";
    {
        std::string qvl_sig = "", qvl_jwk = "";
        qvl_result = get_info_from_jwt((const char *)p_verification_result_token, "qvl_result", PAYLOAD, qvl_sig, qvl_jwk);
    }
    if (qvl_result.empty())
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    qvl_doc.Parse(qvl_result.c_str());
    if (qvl_doc.HasParseError())
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    json_doc.AddMember("qvl_result", qvl_doc, json_doc.GetAllocator());

    rapidjson::Value nested_obj(rapidjson::kObjectType);
    json_doc.AddMember("policies", nested_obj, json_doc.GetAllocator());

    // 2: policies
    std::string signature[qaps_count];
    std::string jwk[qaps_count];
    for (uint32_t i = 0; i < qaps_count; i++)
    {
        signature[i] = "";
        jwk[i] = "";
        if (!p_qaps[i])
        {
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
        auto policy_json = get_info_from_jwt(reinterpret_cast<const char *>(p_qaps[i]), "policies", PAYLOAD, signature[i], jwk[i]);

        if (policy_json.empty() || signature[i].empty() || jwk[i].empty())
        {
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
        rapidjson::Document policy_doc;
        policy_doc.Parse<rapidjson::kParseStopWhenDoneFlag>(policy_json.c_str());
        if (policy_doc.HasParseError() || (policy_doc.HasMember("sgx_enclave") == false && policy_doc.HasMember("sgx_platform") == false))
        {
            // std::cerr << "error " << policy_doc.GetErrorOffset() << " string: " << policy_doc.GetParseError() << std::endl;
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
        rapidjson::Document jwk_doc(&json_doc.GetAllocator());
        jwk_doc.Parse<rapidjson::kParseStopWhenDoneFlag>(jwk[i].c_str());
        if (jwk_doc.HasParseError())
        {
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
        if (policy_doc.HasMember("sgx_platform"))
        {
            rapidjson::Document subdoc;
            subdoc.SetObject();
            subdoc.CopyFrom(policy_doc["sgx_platform"], json_doc.GetAllocator());

            rapidjson::Value str_v(rapidjson::kStringType);
            str_v.SetString(signature[i].c_str(), (unsigned int)signature[i].length());
            subdoc.AddMember("signature", str_v, json_doc.GetAllocator());
            subdoc.AddMember("signing_key", jwk_doc, json_doc.GetAllocator());

            json_doc["policies"].AddMember("sgx_platform", subdoc, json_doc.GetAllocator());
        }
        else if (policy_doc.HasMember("sgx_enclave"))
        {
            rapidjson::Document subdoc;
            subdoc.SetObject();
            subdoc.CopyFrom(policy_doc["sgx_enclave"], json_doc.GetAllocator());

            rapidjson::Value str_v(rapidjson::kStringType);
            str_v.SetString(signature[i].c_str(), (unsigned int)signature[i].length());
            subdoc.AddMember("signature", str_v, json_doc.GetAllocator());
            subdoc.AddMember("signing_key", jwk_doc, json_doc.GetAllocator());

            json_doc["policies"].AddMember("sgx_enclave", subdoc, json_doc.GetAllocator());
        }
        else
        {
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
    }

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::ASCII<>> writer(buffer);
    json_doc.Accept(writer);
    output_json = buffer.GetString();
    SE_TRACE(SE_TRACE_DEBUG, "\nWhole json: \n %s\n", buffer.GetString());
    {
        rapidjson::Document doc;
        doc.SetObject();
        if (doc.Parse(buffer.GetString()).HasParseError())
        {
            SE_TRACE(SE_TRACE_ERROR,"error with offset %lu, %d\n", doc.GetErrorOffset(), doc.GetParseError());
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
    }
    output_json = buffer.GetString();
    return SGX_QL_SUCCESS;
}

quote3_error_t tee_appraise_verification_token(
    const uint8_t *p_verification_result_token,
    uint8_t **p_qaps,
    uint8_t qaps_count,
    const time_t appraisal_check_date,
    sgx_ql_qe_report_info_t *p_qae_report_info,
    uint32_t *p_appraisal_result_token_buffer_size,
    uint8_t *p_appraisal_result_token)
{
    if (p_verification_result_token == NULL ||
        appraisal_check_date == 0 ||
        p_qae_report_info != NULL)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    // If p_appraisal_result_token=NULL and *p_appraisal_result_token_buffer_size=0,
    // The required token buffer size will be returned.
    if (p_appraisal_result_token_buffer_size == NULL ||
        (*p_appraisal_result_token_buffer_size != 0 && p_appraisal_result_token == NULL))
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    if (p_qaps == NULL || qaps_count == 0)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    quote3_error_t ret = SGX_QL_ERROR_UNEXPECTED;

    std::string json_str = "";
    try
    {
        ret = construct_complete_json(p_verification_result_token, p_qaps, qaps_count, json_str);

        if (ret != SGX_QL_SUCCESS)
        {
            return ret;
        }
    }
    catch (...)
    {
        ret = SGX_QL_ERROR_INVALID_PARAMETER;
        return ret;
    }
    OPAEvaluateEngine *p_instance = OPAEvaluateEngine::getInstance();

    // prepare_wasm only needs to call once.
    ret = prepare_wasm_once();
    if (ret == SGX_QL_SUCCESS)
    {
        se_mutex_lock(&g_wasm_mutex);
        ret = p_instance->start_eval(reinterpret_cast<const uint8_t *>(json_str.c_str()), (uint32_t)(json_str.length() + 1), appraisal_check_date,
                                     p_appraisal_result_token_buffer_size, p_appraisal_result_token);
        se_mutex_unlock(&g_wasm_mutex);
    }

    return ret;
}
