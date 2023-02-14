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

#include "jwt-cpp/jwt.h"

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#include <string>
#include <iostream>
#include "util.h"

template <typename T>
std::string json_stringify(const T &obj)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    obj.Accept(writer);
    return sb.GetString();
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        std::cerr << "Commandline is not correct.\n\n Usage: tee_appraisal_tool [manifest.json]" << std::endl;
        return -1;
    }
    size_t file_size = 0;
    char *json_buffer = (char *)read_file_to_buffer(argv[1], &file_size);
    if (json_buffer == NULL)
    {
        std::cerr << "Error: failed to read the file \"" << argv[1] << "\"" << std::endl;
        return -1;
    }

    rapidjson::Document d;
    if (d.Parse(json_buffer).HasParseError())
    {
        std::cerr << "Failed to parse the input manifest." << std::endl;
        free(json_buffer);
        return -1;
    }
    bool to_be_sign = false;
    std::string payload = "";
    std::string claim_type = "";
    std::string ec_priv_key = "";
    std::string pub_jwk = "";
    if (d.HasMember("To_be_sign") && d["To_be_sign"].IsBool())
    {
        to_be_sign = d["To_be_sign"].GetBool();
    }
    if (d.HasMember("policy_payload") && d["policy_payload"].IsObject())
    {
        payload = json_stringify(d["policy_payload"]);
        claim_type = "policies";
    }
    if (d.HasMember("qvl_result_payload") && d["qvl_result_payload"].IsObject())
    {
        payload = json_stringify(d["qvl_result_payload"]);
        claim_type = "qvl_result";
    }
    if (d.HasMember("ec_private_key") && d["ec_private_key"].IsString())
    {
        ec_priv_key = d["ec_private_key"].GetString();
    }
    if (d.HasMember("public_jwk") && d["public_jwk"].IsObject())
    {
        pub_jwk = json_stringify(d["public_jwk"]);
    }

    if ((to_be_sign == true && (ec_priv_key.empty() || pub_jwk.empty())) || payload.empty())
    {
        std::cerr << "JSON file is not correct" << std::endl;
        free(json_buffer);
        return -1;
    }

    if (to_be_sign == true)
    {
        auto token = jwt::create()
                         .set_type("JWT")
                         .set_header_claim("jwk", jwt::claim(pub_jwk))
                         .set_payload_claim(claim_type, jwt::claim(payload))
                         .sign(jwt::algorithm::es384("", ec_priv_key, "", ""));
        std::cout << "signed token: " << token << std::endl;
    }
    else
    {
        auto token = jwt::create()
                         .set_type("JWT")
                         .set_payload_claim(claim_type, jwt::claim(payload))
                         .sign(jwt::algorithm::none{});
        std::cout << "unsigned token: " << token << std::endl;
    }

    free(json_buffer);
    return 0;
}