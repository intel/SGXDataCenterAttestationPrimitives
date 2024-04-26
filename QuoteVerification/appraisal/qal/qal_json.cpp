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

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include <iostream>
#include <sstream>
#include "jwt-cpp/jwt.h"
#include "se_thread.h"
#include "se_trace.h"
#include "sgx_ql_lib_common.h"
#include "sgx_dcap_qal.h"
#include "qal_json.h"
#include <openssl/param_build.h>
#include <openssl/core_names.h>

#include "sgx_dcap_pcs_com.h" // For default policy from pccs
#define QAL_JSON
#include "default_policies.h"

#define FMSPC_SIZE 6
typedef struct __policy_t
{
    std::string description;
    std::string policy;
} policy_t;

static const std::map<std::string, policy_t> s_default_policy_map =
{
    {SGX_PLATFORM_CLASS_ID, {"Default Strict SGX platform TCB policy from Intel", default_sgx_platform_policy.str()}},
    {TDX10_PLATFORM_CLASS_ID, {"Default Strict TDX 1.0 platform TCB policy from Intel", default_tdx10_platform_policy.str()}},
    {TDX15_PLATFORM_CLASS_ID, {"Default Strict TDX 1.5 platform TCB policy from Intel", default_tdx15_platform_policy.str()}},
    {TDX_TDQE_CLASS_ID, {"Default Strict Verified TD QE Identity policy from Intel", default_verified_TDQE_policy.str()}}
};

// For authentication
typedef enum _internal_result_t
{
    // authentication result for each type of policies
    POLICY_NOT_IN_RESULT = -2,  // The provided policy is not used in the appraisal result
    NO_POLICY_PROVIDED,         // This type of policy is not provided. Default setting
    POLICY_AUTH_FAILED,         // This type of policy is provided but it is not the one used in the appraisal process
    POLICY_AUTH_SUCCESS         // This type of policy is provided and used in the appraisal process
}internal_result_t;

typedef struct _auth_info_t
{
    std::string description;
    internal_result_t result;
} auth_info_t;

static std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> get_ec_pub_key_from_xy(const std::string &x, const std::string &y)
{
    const auto dx = jwt::base::decode<jwt::alphabet::base64url>(jwt::base::pad<jwt::alphabet::base64url>(x));
    const auto dy = jwt::base::decode<jwt::alphabet::base64url>(jwt::base::pad<jwt::alphabet::base64url>(y));
    BIGNUM *bx = NULL;
    BIGNUM *by = NULL;
    EC_POINT *point = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;

    EC_GROUP *ec_group = NULL;
    size_t len = 0;
    uint8_t *octet_str = NULL;
    OSSL_PARAM_BLD *params_build = NULL;
    OSSL_PARAM *params = NULL;
    bool flag = false;
    do
    {

        bx = BN_bin2bn(reinterpret_cast<const unsigned char *>(dx.c_str()), (int)dx.length(), 0);
        CHECK_NULL_BREAK(bx);
        by = BN_bin2bn(reinterpret_cast<const unsigned char *>(dy.c_str()), (int)dy.length(), 0);
        CHECK_NULL_BREAK(by);

        ec_group = EC_GROUP_new_by_curve_name(NID_secp384r1);
        CHECK_NULL_BREAK(ec_group);
        point = EC_POINT_new(ec_group);
        CHECK_NULL_BREAK(point);
        if (EC_POINT_set_affine_coordinates(ec_group, point, bx, by, NULL) != 1)
        {
            break;
        }
        if (EC_POINT_is_on_curve(ec_group, point, NULL) != 1)
        {
            break;
        }
        len = EC_POINT_point2oct(ec_group, point, POINT_CONVERSION_COMPRESSED, NULL, 0, NULL);
        if (len == 0)
        {
            break;
        }
        octet_str = (uint8_t *)malloc(len);
        CHECK_NULL_BREAK(octet_str);
        if (EC_POINT_point2oct(ec_group, point, POINT_CONVERSION_COMPRESSED, octet_str, len, NULL) == 0)
        {
            break;
        }

        params_build = OSSL_PARAM_BLD_new();
        CHECK_NULL_BREAK(params_build);

        if (1 != OSSL_PARAM_BLD_push_utf8_string(params_build, "group", SN_secp384r1, 0))
        {
            break;
        }
        if (1 != OSSL_PARAM_BLD_push_octet_string(params_build, OSSL_PKEY_PARAM_PUB_KEY, octet_str, len))
        {
            break;
        }
        params = OSSL_PARAM_BLD_to_param(params_build);
        CHECK_NULL_BREAK(params);

        // get pkey from params
        pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        CHECK_NULL_BREAK(pkey_ctx);

        if (1 != EVP_PKEY_fromdata_init(pkey_ctx))
        {
            break;
        }
        if (1 != EVP_PKEY_fromdata(pkey_ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params))
        {
            break;
        }

        flag = true;
    } while (0);

    BN_free(bx);
    BN_free(by);
    EC_GROUP_free(ec_group);
    EC_POINT_clear_free(point);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(params_build);
    EVP_PKEY_CTX_free(pkey_ctx);
    free(octet_str);

    if (flag == false)
    {
        EVP_PKEY_free(pkey);
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
    jwk_doc.Parse<rapidjson::kParseCommentsFlag>(jwk_json.c_str());
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
    auto ec_pubkey = get_ec_pub_key_from_xy(vx.GetString(), vy.GetString());
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
    if (p_jwt_str == NULL || (ctype != HEADER && ctype != PAYLOAD))
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
                if(claim_name == NULL)
                {
                    auto header = decoded.get_header();
                    return header;
                    
                }
                else
                {
                    if (decoded.has_header_claim(claim_name) == false)
                        return "";
                    auto claim = decoded.get_header_claim(claim_name);
                    return claim.to_json().to_str();
                }
            }
            else
            {
                if (claim_name == NULL)
                {
                    return decoded.get_payload();
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
                SE_TRACE(SE_TRACE_DEBUG, "Fail to convert jwk to pem\n");
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
                SE_TRACE(SE_TRACE_DEBUG, "Fail to verify the JWT: \n%s\n\n", jwt_str.c_str());
                return "";
            }

            // After verify, we can get the header or payload
            signature = decoded.get_signature_base64();
            jwk = jwk_json.to_str();
            if (ctype == HEADER)
            {
                if(claim_name == NULL)
                {
                    auto header = decoded.get_header();
                    return header;
                    
                }
                else
                {
                    if (decoded.has_header_claim(claim_name) == false)
                        return "";
                    auto claim = decoded.get_header_claim(claim_name);
                    return claim.to_json().to_str();
                }
            }
            else
            {
                if (claim_name == NULL)
                {
                    return decoded.get_payload();
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
    }
    catch (...)
    {
        SE_TRACE(SE_TRACE_DEBUG, "Fail to verify the JWT: \n%s\n\n", jwt_str.c_str());
    }
    // Don't support other alg/types
    return "";
}

static void set_default_policies(std::map<std::string, std::string> &id_map, rapidjson::Value &report_array, uint8_t *fmspc, uint16_t fmspc_size)
{
    quote3_error_t ret = SGX_QL_ERROR_UNEXPECTED;
    char *p_platform_policy_from_pccs = NULL;
    uint32_t platform_policy_size = 0;
    // Check if we need to use default policies
    uint32_t index = 0;
    for (; index < report_array.Size(); index++)
    {
        std::string class_id = report_array[index]["environment"]["class_id"].GetString();
        if (id_map.count(class_id) == 0 && s_default_policy_map.count(class_id) != 0)
        {

            ret = tee_dcap_get_default_platform_policy(fmspc, fmspc_size, (uint8_t **)&p_platform_policy_from_pccs, &platform_policy_size);
            if (SGX_QL_SUCCESS != ret || p_platform_policy_from_pccs == NULL)
            {
                se_trace(SE_TRACE_ERROR, "Failed to get default platform policy from PCCS. Will try to use strict policy instead\n");
            }
            break;
        }
    }
    if (index == report_array.Size())
    {
        // The platform policies are provided by users. No need to use default policies
        return;
    }

    // The default policies from PCCS have merged the TDQE and platform policy. If a user inputs one of the TDQE and
    // TDX platform policy, we cannot use the merged policy from PCCS. In this case, we should stop searching the policies
    // from the result from PCCS and directly use the strict default policy from QAL.
    bool finish_set = false;
    if (p_platform_policy_from_pccs != NULL && id_map.count(TDX_TDQE_CLASS_ID) == 0 &&
        id_map.count(TDX10_PLATFORM_CLASS_ID) == 0 && id_map.count(TDX15_PLATFORM_CLASS_ID) == 0)
    {
        std::string policies(p_platform_policy_from_pccs, platform_policy_size);

        size_t last = 0;
        size_t next = 0;
        std::vector<std::string> vec;
        while ((next = policies.find(",", last)) != std::string::npos)
        {
            std::string token = policies.substr(last, next - last);
            last = next + 1;
            vec.push_back(token);
        }
        vec.push_back(policies.substr(last));
        for (auto item : vec)
        {
            std::string signature = "";
            std::string jwk = "";
            auto policy_json = get_info_from_jwt(reinterpret_cast<const char *>(item.c_str()), "policy_payload", PAYLOAD, signature, jwk);
            if (policy_json.empty() == false && signature.empty() == false && jwk.empty() == false)
            {
                rapidjson::Document policy_doc;
                policy_doc.Parse<rapidjson::kParseStopWhenDoneFlag | rapidjson::kParseCommentsFlag>(policy_json.c_str());

                std::map<std::string, std::string> temp_policy_map;

                if (policy_doc.HasParseError() || policy_doc.HasMember("policy_array") == false ||
                    policy_doc["policy_array"].IsArray() == false)
                {
                    // Seems the policy from PCCS is not acceptable, we will continue to use the strict default policies
                    break;
                }
                rapidjson::Value &policy_array = policy_doc["policy_array"];
                for (uint32_t i = 0; i < policy_array.Size(); i++)
                {
                    if (policy_array[i].HasMember("environment") == false ||
                        policy_array[i]["environment"].HasMember("class_id") == false ||
                        policy_array[i]["environment"]["class_id"].IsString() == false)
                    {
                        break;
                    }

                    for (uint32_t j = 0; j < report_array.Size(); j++)
                    {
                        // Find the policy that matches the report_array and isn't included in the id_map
                        std::string class_id = report_array[j]["environment"]["class_id"].GetString();
                        if (class_id == policy_array[i]["environment"]["class_id"].GetString() && id_map.count(class_id) == 0)
                        {
                            rapidjson::Document jwk_doc;
                            jwk_doc.Parse<rapidjson::kParseCommentsFlag>(jwk.c_str());
                            if (jwk_doc.HasParseError())
                            {
                                break;
                            }
                            std::string v;
                            {
                                rapidjson::Document d;
                                d.SetObject();
                                rapidjson::Value &p = policy_array[i];
                                d.CopyFrom(p, d.GetAllocator());
                                rapidjson::Value str_v(rapidjson::kStringType);
                                str_v.SetString(signature.c_str(), (unsigned int)signature.length());
                                d.AddMember("signature", str_v, d.GetAllocator());
                                d.AddMember("signing_key", jwk_doc, jwk_doc.GetAllocator());
                                rapidjson::StringBuffer buffer;
                                rapidjson::Writer<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::ASCII<>> writer(buffer);
                                d.Accept(writer);
                                v = buffer.GetString();
                            }
                            temp_policy_map[class_id] = v;
                            break;
                        }
                    }
                }
                if ((temp_policy_map.size() == 1 && temp_policy_map.count(SGX_PLATFORM_CLASS_ID) == 1) ||
                    (temp_policy_map.size() == 2 && temp_policy_map.count(TDX_TDQE_CLASS_ID) == 1 &&
                     (temp_policy_map.count(TDX10_PLATFORM_CLASS_ID) == 1 || temp_policy_map.count(TDX15_PLATFORM_CLASS_ID) == 1)))
                {
                    id_map.insert(temp_policy_map.begin(), temp_policy_map.end());
                    finish_set = true;
                    break; // break out the for() loop
                }
            }
        }
        if(finish_set == false)
        {
            se_trace(SE_TRACE_ERROR, "The policies from PCCS are unacceptable. Will use the strict default policies.\n");
        }
    }
    if (p_platform_policy_from_pccs != NULL)
    {
        tee_dcap_free_platform_policy((uint8_t *)p_platform_policy_from_pccs);
    }
    if (finish_set)
    {
        return;
    }

    for (uint32_t i = 0; i < report_array.Size(); i++)
    {
        auto class_id = report_array[i]["environment"]["class_id"].GetString();
        if (id_map.count(class_id) == 0)
        {
            // Use the hard coded default strict policy in QAL
            auto it = s_default_policy_map.find(class_id);
            if (it != s_default_policy_map.end())
            {
                id_map[class_id] = it->second.policy;
            }
        }
    }
    return;
}

quote3_error_t construct_complete_json(const uint8_t *p_verification_result_token, uint8_t **p_qaps, uint8_t qaps_count, std::string &output_json)
{
    assert(p_verification_result_token != NULL && p_qaps != NULL && qaps_count != 0);

    rapidjson::Document json_doc, qvl_doc, sub_doc;
    json_doc.SetObject();
    std::map<std::string, std::string> id_map;

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
    qvl_doc.Parse<rapidjson::kParseStopWhenDoneFlag>(qvl_result.c_str());
    if (qvl_doc.HasParseError() || qvl_doc.HasMember("qvl_result") == false)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    rapidjson::Value &report_array = qvl_doc["qvl_result"];
    if (report_array.IsString())
    {
        // If report_array is not an array, we try to parse it as a json again, in case it was signed as a nested payload        
        std::string str2;
        {
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::ASCII<>> writer(buffer);
            report_array.Accept(writer);
            str2 = buffer.GetString();
        }
        sub_doc.Parse(str2.c_str());
        if (sub_doc.HasParseError() || sub_doc.HasMember("qvl_result") == false)
            return SGX_QL_ERROR_INVALID_PARAMETER;
        report_array = sub_doc["qvl_result"];
    }
    if (report_array.IsArray() == false)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    // 2: Handle policies from users
    std::string signature[qaps_count];
    std::string jwk[qaps_count];
    uint8_t fmspc[FMSPC_SIZE] = {0};
    bool fmspc_parsed = false;
    std::vector<std::string> desired_id_vec = {TENANT_ENCLAVE_CLASS_ID, TENANT_TDX10_CLASS_ID, TENANT_TDX15_CLASS_ID, SGX_PLATFORM_CLASS_ID,
                                              TDX15_PLATFORM_CLASS_ID, TDX10_PLATFORM_CLASS_ID, TDX_TDQE_CLASS_ID};
    for (uint32_t i = 0; i < qaps_count; i++)
    {
        signature[i] = "";
        jwk[i] = "";
        if (!p_qaps[i])
        {
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
        auto policy_json = get_info_from_jwt(reinterpret_cast<const char *>(p_qaps[i]), "policy_payload", PAYLOAD, signature[i], jwk[i]);

        if (policy_json.empty() || signature[i].empty() || jwk[i].empty())
        {
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }

        rapidjson::Document policy_doc;
        policy_doc.Parse<rapidjson::kParseStopWhenDoneFlag | rapidjson::kParseCommentsFlag>(policy_json.c_str());
        if (policy_doc.HasParseError() || policy_doc.HasMember("policy_array") == false)
        {
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }

        // Access the policy array
        rapidjson::Value &policy_array = policy_doc["policy_array"];
        rapidjson::Document sub_doc1;
        std::string str;
    
        if( policy_array.IsString())
        {
            // If policy_array is not an array, we try to parse it as a json again, in case it was signed as a nested payload
            {
                rapidjson::StringBuffer buffer;
                rapidjson::Writer<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::ASCII<>> writer(buffer);
                policy_array.Accept(writer);
                str = buffer.GetString();
            } 
            sub_doc1.Parse<rapidjson::kParseStopWhenDoneFlag | rapidjson::kParseCommentsFlag>(str.c_str());
            if (sub_doc1.HasParseError() || sub_doc1.HasMember("policy_array") == false)
                return SGX_QL_ERROR_INVALID_PARAMETER;
            policy_array = sub_doc1["policy_array"];
        }

        if(policy_array.IsArray() == false)
        {
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
        // Construct the id_map after extract the report_array and policy_array
        // to choose one policy for one class_id
        for (uint32_t j=0; j < report_array.Size(); j++)
        {
            if(report_array[j].HasMember("environment") == false ||
               report_array[j]["environment"].HasMember("class_id") == false ||
               report_array[j]["environment"]["class_id"].IsString() == false)
            {
                se_trace(SE_TRACE_ERROR, "The input QVL result is not correct.\n");
                return SGX_QL_ERROR_INVALID_PARAMETER;
            }
            std::string class_id = report_array[j]["environment"]["class_id"].GetString();

            if (fmspc_parsed == false)
            {
                // Try to retrieve fmpsc from platform tcb result
                auto it = s_default_policy_map.find(class_id);
                if (it != s_default_policy_map.end() && class_id != TDX_TDQE_CLASS_ID)
                {
                    if (report_array[j].HasMember("measurement") == true &&
                        report_array[j]["measurement"].HasMember("fmspc") == true &&
                        report_array[j]["measurement"]["fmspc"].IsString() == true)
                    {
                        const char *tmp_str = report_array[j]["measurement"]["fmspc"].GetString();
                        if (strlen(tmp_str) != FMSPC_SIZE * 2)
                        {
                            se_trace(SE_TRACE_ERROR, "The input QVL result is not correct.\n");
                            return SGX_QL_ERROR_INVALID_PARAMETER;
                        }
                        for (uint32_t z = 0; z < strlen(tmp_str) / 2; z++)
                        {
                            char a[3] = {0};
                            strncpy(a, tmp_str + z * 2, 2);
                            fmspc[z] = (uint8_t)strtoul(a, NULL, 16);
                        }
                        fmspc_parsed = true;
                    }
                }
            }

            for (uint32_t z = 0; z < policy_array.Size(); z++)
            {
                if (policy_array[z].HasMember("environment") == false ||
                    policy_array[z]["environment"].HasMember("class_id") == false ||
                    policy_array[z]["environment"]["class_id"].IsString() == false)
                {
                    se_trace(SE_TRACE_ERROR, "The policy format is not correct. Item: %d, policy:\n%s\n", i, p_qaps[i]);
                    return SGX_QL_ERROR_INVALID_PARAMETER;
                }
                std::string class_id_p = policy_array[z]["environment"]["class_id"].GetString();
                if(std::find(desired_id_vec.begin(), desired_id_vec.end(), class_id_p) == desired_id_vec.end())
                {
                    se_trace(SE_TRACE_ERROR, "The policy format is not correct. Item: %d, policy:\n%s\n", i, p_qaps[i]);
                    return SGX_QL_ERROR_INVALID_PARAMETER;
                }
                if (class_id_p == class_id)
                {
                    if (id_map.count(class_id) == 0)
                    {
                        rapidjson::Document jwk_doc;
                        jwk_doc.Parse<rapidjson::kParseStopWhenDoneFlag | rapidjson::kParseCommentsFlag>(jwk[i].c_str());
                        if (jwk_doc.HasParseError())
                        {
                            return SGX_QL_ERROR_INVALID_PARAMETER;
                        }
                        std::string v;
                        {
                            rapidjson::Document d;
                            d.SetObject();
                            rapidjson::Value &p = policy_array[z];
                            d.CopyFrom(p, d.GetAllocator());
                            rapidjson::Value str_v(rapidjson::kStringType);
                            str_v.SetString(signature[i].c_str(), (unsigned int)signature[i].length());
                            d.AddMember("signature", str_v, d.GetAllocator());
                            d.AddMember("signing_key", jwk_doc, jwk_doc.GetAllocator());
                            rapidjson::StringBuffer buffer;
                            rapidjson::Writer<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::ASCII<>> writer(buffer);
                            d.Accept(writer);
                            v = buffer.GetString();
                        }
                        id_map[class_id] = v;
                        break;
                    }
                    else
                    {
                        se_trace(SE_TRACE_ERROR, "The input policies are not correct. Repeatedly entering numerous policies with the same class_id is prohibited.\n");
                        return SGX_QL_ERROR_INVALID_PARAMETER;
                    }
                }
            }
        }
    }

    // 3: Set default policies in case we need to do so
    set_default_policies(id_map, report_array, fmspc, FMSPC_SIZE);

    json_doc.AddMember("qvl_result", qvl_doc["qvl_result"], json_doc.GetAllocator());

    rapidjson::Value nested_obj(rapidjson::kObjectType);
    json_doc.AddMember("policies", nested_obj, json_doc.GetAllocator());

    rapidjson::Value obj(rapidjson::kArrayType);
    rapidjson::Document subdoc;
    subdoc.SetArray();
    {
        for (auto it = id_map.begin(); it != id_map.end(); ++it)
        {
            rapidjson::Document d;
            d.SetObject();
            d.Parse<rapidjson::kParseStopWhenDoneFlag | rapidjson::kParseCommentsFlag>(it->second.c_str());
            if (d.HasParseError())
                return SGX_QL_ERROR_UNEXPECTED;
            rapidjson::Value object(rapidjson::Type::kObjectType);
            object.CopyFrom(d, json_doc.GetAllocator());
            subdoc.PushBack(object, json_doc.GetAllocator());
        }
    }
    json_doc["policies"].AddMember("policy_array", subdoc, json_doc.GetAllocator());

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::ASCII<>> writer(buffer);
    json_doc.Accept(writer);

    SE_TRACE(SE_TRACE_DEBUG, "\nWhole json: \n %s\n", buffer.GetString());
    {
        rapidjson::Document doc;
        doc.SetObject();
        if (doc.Parse<rapidjson::kParseStopWhenDoneFlag | rapidjson::kParseCommentsFlag>(buffer.GetString()).HasParseError())
        {
            SE_TRACE(SE_TRACE_DEBUG, "error with offset %lu, %d\n", doc.GetErrorOffset(), doc.GetParseError());
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
    }
    output_json = buffer.GetString();

    return SGX_QL_SUCCESS;
}

static quote3_error_t authenticate_one_policy(rapidjson::Value &report_array, const uint8_t* policy, std::map<std::string, auth_info_t> &result_map)
{
    std::string signature = "";
    std::string jwk = "";

    auto policy_json = get_info_from_jwt(reinterpret_cast<const char *>(policy), "policy_payload", PAYLOAD, signature, jwk);

    if (policy_json.empty() || signature.empty() || jwk.empty())
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    rapidjson::Document policy_doc;
    policy_doc.Parse<rapidjson::kParseStopWhenDoneFlag | rapidjson::kParseCommentsFlag>(policy_json.c_str());
    if (policy_doc.HasParseError() || policy_doc.HasMember("policy_array") == false)
    {
        se_trace(SE_TRACE_ERROR, "The input policy is not correct:\n%s\n", policy);
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    // Access the policy array
    rapidjson::Value &policy_array = policy_doc["policy_array"];
    rapidjson::Document sub_doc1;
    std::string str;

    if (policy_array.IsString())
    {
        // If policy_array is not an array, we try to parse it as a json again, in case it was signed as a nested payload
        {
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::ASCII<>> writer(buffer);
            policy_array.Accept(writer);
            str = buffer.GetString();
        }
        sub_doc1.Parse<rapidjson::kParseStopWhenDoneFlag | rapidjson::kParseCommentsFlag>(str.c_str());
        if (sub_doc1.HasParseError() || sub_doc1.HasMember("policy_array") == false)
            return SGX_QL_ERROR_INVALID_PARAMETER;
        policy_array = sub_doc1["policy_array"];
    }

    if (policy_array.IsArray() == false)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    for (uint32_t i = 0; i < policy_array.Size(); i++)
    {
        if (policy_array[i].HasMember("environment") == false ||
            policy_array[i]["environment"].HasMember("class_id") == false ||
            policy_array[i]["environment"]["class_id"].IsString() == false)
        {
            se_trace(SE_TRACE_ERROR, "The input policy is not correct:\n%s\n", policy);
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
        std::string class_id_p = policy_array[i]["environment"]["class_id"].GetString();
        if(result_map.find(class_id_p) == result_map.end())
        {
            // The policy file contains some unrecognized policy
            se_trace(SE_TRACE_ERROR, "The input policy is not correct:\n%s\n", policy);
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
        uint32_t j = 0;
        for (; j < report_array.Size(); j++)
        {
            if (report_array[j].HasMember("policy") == false ||
                report_array[j]["policy"].HasMember("environment") == false ||
                report_array[j]["policy"]["environment"].HasMember("class_id") == false ||
                report_array[j]["policy"]["environment"]["class_id"].IsString() == false)
            {
                return SGX_QL_ERROR_INVALID_PARAMETER;
            }
            std::string class_id_r = report_array[j]["policy"]["environment"]["class_id"].GetString();
            if (class_id_p == class_id_r)
            {
                if (result_map[class_id_r].result != -1)
                {
                    // Some other policy has matched this result
                    se_trace(SE_TRACE_ERROR, "\033[0;31mERROR:\033[0mThe input policies are incorrect. For a given type, only one policy is permitted.\n");
                    return SGX_QL_ERROR_INVALID_PARAMETER;
                }
                std::string sig_r = "";
                if (report_array[j]["policy"].HasMember("signature") == true)
                {
                    sig_r = report_array[j]["policy"]["signature"].GetString();
                }
                std::string jwk_r = "";
                if (report_array[j]["policy"].HasMember("signing_key") == true)
                {
                    rapidjson::Value &tmp_key = report_array[j]["policy"]["signing_key"];
                    rapidjson::StringBuffer buffer;
                    rapidjson::Writer<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::ASCII<>> writer(buffer);
                    tmp_key.Accept(writer);
                    jwk_r = buffer.GetString();
                }
                
                if ((sig_r == "" && jwk_r != "") || (sig_r != "" && jwk_r == ""))
                {
                    // If the result is generated by QAL, this error should not be happened
                    SE_TRACE_DEBUG("The input appraisal result format is not correct.\n");
                    return SGX_QL_ERROR_INVALID_PARAMETER;
                }
                if (sig_r != "" && jwk_r != "")
                {
                    std::string pem = "", pem_r = "";
                    if(convert_jwk_to_pem_str(jwk, pem) == false)
                    {
                       SE_TRACE_DEBUG("The input policy format is not correct.\n");
                       return SGX_QL_ERROR_INVALID_PARAMETER; 
                    }
                    if(convert_jwk_to_pem_str(jwk_r, pem_r) == false)
                    {
                       SE_TRACE_DEBUG("The input appraisal result format is not correct.\n");
                       return SGX_QL_ERROR_INVALID_PARAMETER; 
                    }
                    if (sig_r == signature && pem_r == pem)
                    {
                        result_map[class_id_r].result = POLICY_AUTH_SUCCESS;
                    }
                    else
                    {
                        result_map[class_id_r].result = POLICY_AUTH_FAILED;
                    }
                    break;
                }
            }
        }
        if(j == report_array.Size())
        {
            // No class_id is found in appraisal result token that matches the input policy
            // For example, you are trying to audit some tdx policies within an SGX appraisal result token
            se_trace(SE_TRACE_ERROR, "\033[0;31mERROR:\033[0m The appraisal result token doesn't utilize the policy with class_id %s:\n%s\n", 
                                    class_id_p.c_str(), policy);
            result_map[class_id_p].result = POLICY_NOT_IN_RESULT;
        }
    }
    return SGX_QL_SUCCESS;
}

quote3_error_t authenticate_appraisal_result_internal(const uint8_t *p_appraisal_result_token, const tee_policy_bundle_t *p_policies, tee_policy_auth_result_t *result)
{
    assert(p_appraisal_result_token != NULL && p_policies != NULL && result != NULL);
    // Result for each type of policies:
    //      -2 - The provided policy is not used in the appraisal result
    //      -1 - This type of policy is not provided, default value
    //       0 - Failure. This type of policy is provided but it is not the one used in the appraisal process
    //       1 - Success. This type of policy is provided and used in the appraisal process
    std::map<std::string, auth_info_t> result_map = {
        {TENANT_ENCLAVE_CLASS_ID, {TENANT_ENCLAVE_DESCRIPTION, NO_POLICY_PROVIDED}},
        {TENANT_TDX10_CLASS_ID, {TENANT_TDX10_DESCRIPTION, NO_POLICY_PROVIDED}},
        {TENANT_TDX15_CLASS_ID, {TENANT_TDX15_DESCRIPTION, NO_POLICY_PROVIDED}},

        {SGX_PLATFORM_CLASS_ID, {SGX_PLATFORM_DESCRIPTION, NO_POLICY_PROVIDED}},
        {TDX15_PLATFORM_CLASS_ID, {TDX15_PLATFORM_DESCRIPTION, NO_POLICY_PROVIDED}},
        {TDX10_PLATFORM_CLASS_ID, {TDX10_PLATFORM_DESCRIPTION, NO_POLICY_PROVIDED}},
        {TDX_TDQE_CLASS_ID, {TDX_TDQE_DESCRIPTION, NO_POLICY_PROVIDED}}
    };

    // Decode appraisal_result_token
    std::string sig = "", jwk = "";
    std::string result_json = get_info_from_jwt(reinterpret_cast<const char *>(p_appraisal_result_token), "appraisal_result", PAYLOAD, sig, jwk);
    rapidjson::Document result_doc;

    result_doc.SetObject();
    result_doc.Parse<rapidjson::kParseStopWhenDoneFlag | rapidjson::kParseCommentsFlag>(result_json.c_str());

    if (result_doc.HasParseError() || result_doc.IsArray() == false || result_doc.Size() != 1)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    if(result_doc[0].IsObject() == false || result_doc[0].HasMember("result") == false)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    if(result_doc[0]["result"].IsObject() == false || result_doc[0]["result"].HasMember("appraised_reports") == false)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    rapidjson::Value &report_array = result_doc[0]["result"]["appraised_reports"];
    if (report_array.IsArray() == false)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    quote3_error_t ret = SGX_QL_ERROR_UNEXPECTED;

    // Handle customized policies
    if (p_policies->p_tenant_identity_policy)
    {
        ret = authenticate_one_policy(report_array, p_policies->p_tenant_identity_policy, result_map);
        if (ret != SGX_QL_SUCCESS)
            return ret;
    }
    if (p_policies->platform_policy.pt == CUSTOMIZED && p_policies->platform_policy.p_policy)
    {
        ret = authenticate_one_policy(report_array, p_policies->platform_policy.p_policy, result_map);
        if (ret != SGX_QL_SUCCESS)
            return ret;
    }
    if (p_policies->tdqe_policy.pt == CUSTOMIZED && p_policies->tdqe_policy.p_policy)
    {
        ret = authenticate_one_policy(report_array, p_policies->tdqe_policy.p_policy, result_map);
        if (ret != SGX_QL_SUCCESS)
            return ret;
    }

    // Handle default policies
    for (uint32_t i = 0; i < report_array.Size(); i++)
    {
        if (report_array[i].HasMember("policy") == false ||
            report_array[i]["policy"].HasMember("environment") == false ||
            report_array[i]["policy"]["environment"].HasMember("class_id") == false ||
            report_array[i]["policy"]["environment"]["class_id"].IsString() == false ||
            report_array[i]["policy"]["environment"].HasMember("description") == false ||
            report_array[i]["policy"]["environment"]["description"].IsString() == false)
        {
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
        std::string class_id_r = report_array[i]["policy"]["environment"]["class_id"].GetString();
        std::string description = report_array[i]["policy"]["environment"]["description"].GetString();
        std::string sig_r = "";
        if (report_array[i].HasMember("signature") == true &&
        report_array[i]["signature"].IsString() == true)
        {
            sig_r = report_array[i]["signature"].GetString();
        }
        std::string jwk_r = "";
        if (report_array[i].HasMember("signing_key") == true)
        {
            rapidjson::Value &tmp_key = report_array[i]["signing_key"];
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::ASCII<>> writer(buffer);
            tmp_key.Accept(writer);
            jwk_r = buffer.GetString();
        }
        if (sig_r == "" && jwk_r == "")
        {
            auto it = s_default_policy_map.find(class_id_r);
            if(it != s_default_policy_map.end())
            {
                if(description == it->second.description)
                {
                    // Only set the result map when there is no customized policy needed to be audited
                    if (result_map[class_id_r].result == NO_POLICY_PROVIDED)
                        result_map[class_id_r].result = POLICY_AUTH_SUCCESS;
                }
            }
        }
    }

    // Print result
    se_trace(SE_TRACE_ERROR, "\nThe final result map: \n");
    for (auto const& iter : result_map)
    {
        std::string result_desc[] = {
            /* -2 */ "This policy is provided but not used in the appraisal process",
            /* -1 */ "This type of policy is not provided",
            /*  0 */ "This type of policy is provided but it is not the one used in the appraisal process",
            /*  1 */ "This type of policy is provided and used in the appraisal process",
        };
        se_trace(SE_TRACE_ERROR, "\t\"%-30s\": class-id=%s, result=%d, \"%30s\"\n", iter.second.description.c_str(), 
                                    iter.first.c_str(), iter.second.result, result_desc[iter.second.result+2].c_str());
    }

    // Check result
    if ((result_map[TENANT_ENCLAVE_CLASS_ID].result == POLICY_AUTH_SUCCESS &&
         result_map[SGX_PLATFORM_CLASS_ID].result == POLICY_AUTH_SUCCESS) ||
        (result_map[TENANT_TDX10_CLASS_ID].result == POLICY_AUTH_SUCCESS &&
         result_map[TDX10_PLATFORM_CLASS_ID].result == POLICY_AUTH_SUCCESS &&
         result_map[TDX_TDQE_CLASS_ID].result == POLICY_AUTH_SUCCESS) ||
        (result_map[TENANT_TDX15_CLASS_ID].result == POLICY_AUTH_SUCCESS &&
         result_map[TDX15_PLATFORM_CLASS_ID].result == POLICY_AUTH_SUCCESS &&
         result_map[TDX_TDQE_CLASS_ID].result == POLICY_AUTH_SUCCESS))
    {
        *result = TEE_AUTH_SUCCESS; // The policies are audited successfully.
    }
    else
    {
        bool flag = false;
        for (auto const& iter : result_map)
        {
            if(iter.second.result == POLICY_AUTH_FAILED)
            {
                flag = true;
            }
        }
        if(flag == true)
        {
            // At least one policy is audited failed.
            *result = TEE_AUTH_FAILURE;
        }
        else
        {
            // Some policy is not audited
            *result = TEE_AUTH_INCOMPLET;
        }
    }
    return SGX_QL_SUCCESS;
}
