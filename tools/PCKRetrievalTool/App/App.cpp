/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
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
 * File: app.cpp
 * generate the raw data for PCK Cert retrieval
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>
#ifdef _MSC_VER
#include <Windows.h>
#include <tchar.h>
#include <string>
#else
#include <dlfcn.h>
#endif
#include "se_version.h"
#include "sgx_pce.h"
#include "sgx_quote_3.h"
#include "network_wrapper.h"
#include "utility.h"
     
#define MAX_PATH 260
#define VER_FILE_DESCRIPTION_STR    "Intel(R) Software Guard Extensions PCK Cert ID Retrieval Tool"
#define VER_PRODUCTNAME_STR         "PCKIDRetrievalTool"


void PrintHelp() {
    printf("Usage: %s [OPTION] \n", VER_PRODUCTNAME_STR);
    printf("Example: %s -f pck_retrieval_result.csv, -url http://localhost:8081, -user_token 123456, -user_secure_cert true\n", VER_PRODUCTNAME_STR);
    printf( "\nOptions:\n");
    printf( " -f filename                       - output the retrieval result to the \"filename\"\n");
    printf( " -url cache_server_address         - cache server's address \n");
    printf( " -user_token token_string          - user token to access the cache server \n");
    printf( " -proxy_type proxy_type            - proxy setting when access the cache server \n");
    printf( " -proxy_url  proxy_server_address  - proxy server's address \n");
    printf( " -user_secure_cert ture            - accept secure/insecure https cert \n");
    printf( " -?                - show command help\n");
    printf( " -h                - show command help\n");
    printf( " -help             - show command help\n");
    printf( "If option is not specified, it will write the retrieved data to file: pckid_retrieval.csv\n\n");
}


// Some utility MACRO to output some of the data structures.
#define PRINT_BYTE_ARRAY(stream,mem, len)                     \
{                                                             \
    if (!(mem) || !(len)) {                                       \
        fprintf(stream,"\n( null )\n");                       \
    } else {                                                  \
        uint8_t *array = (uint8_t *)(mem);                      \
        uint32_t i = 0;                                       \
        for (i = 0; i < (len) - 1; i++) {                       \
            fprintf(stream,"%02x", array[i]);                 \
            if (i % 32 == 31 && stream == stdout)             \
               fprintf(stream,"\n");                          \
        }                                                     \
        fprintf(stream,"%02x", array[i]);                     \
    }                                                         \
}

#define WRITE_COMMA                                           \
    fprintf(pFile,",");                                       \

#ifdef DEBUG
#define PRINT_MESSAGE(message) printf(message);
#else
#define PRINT_MESSAGE(message) ;
#endif

char toUpper(char ch)
{
    return static_cast<char>(toupper(ch));
}

std::string server_url_string = "";
std::string proxy_type_string = "";
std::string proxy_url_string = "";
std::string user_token_string = "";
std::string user_secure_cert_string = "";
std::string output_filename = "";
int parse_arg(int argc, const char *argv[])
{
    if (argc == 2) {
        return -1;
    }
    else if(argc == 1) {
        output_filename = "pckid_retrieval.csv";
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0) {
            if (i == argc - 1) {
                fprintf(stderr, "No file name is provided for -f\n");
                return -1;
            }
            else {
                output_filename = argv[i + 1];
                i++;
                continue;
            }
        }
        else if (strcmp(argv[i], "-url") == 0) {
            if (i == argc - 1) {
                fprintf(stderr, "No url provided for -url\n");
                return -1;
            }
            else {
                server_url_string = argv[i + 1];
                i++;
                continue;
            }
        }
        else if (strcmp(argv[i], "-defaulturl") == 0) {
            server_url_string = "https://localhost:8081";
            continue;
        }
        else if (strcmp(argv[i], "-proxy_type") == 0) {
            if (i == argc - 1) {
                fprintf(stderr, "No proxy type provided for -proxy_type\n");
                return -1;
            }
            else {
                proxy_type_string = argv[i + 1];
                std::transform(proxy_type_string.begin(), proxy_type_string.end(), proxy_type_string.begin(), toUpper);
                if (!is_valid_proxy_type(proxy_type_string)) {
                    fprintf(stderr, "Invalid proxy_type %s\n", proxy_type_string.c_str());
                    return -1;
                }
                i++;
                continue;
            }
        }
        else if (strcmp(argv[i], "-proxy_url") == 0) {
            if (i == argc - 1) {
                fprintf(stderr, "No proxy url provided for -proxy_url\n");
                return -1;
            }
            else {
                proxy_url_string = argv[i + 1];
                i++;
                continue;
            }
        }
        else if (strcmp(argv[i], "-user_token") == 0) {
            if (i == argc - 1) {
                fprintf(stderr, "No user token is provided for -user_token\n");
                return -1;
            }
            else {
                user_token_string = argv[i + 1];
                i++;
                continue;
            }
        }
        else if (strcmp(argv[i], "-user_secure_cert") == 0) {
            if (i == argc - 1) {
                fprintf(stderr, "No user secure cert  provided for -user_secure_cert\n");
                return -1;
            }
            else {
                user_secure_cert_string = argv[i + 1];
                std::transform(user_secure_cert_string.begin(), user_secure_cert_string.end(), user_secure_cert_string.begin(),toUpper);
                if (!is_valid_user_secure_cert(user_secure_cert_string)) {
                    fprintf(stderr, "Invalid user secure cert %s\n", user_secure_cert_string.c_str());
                    return -1;
                }
                i++;
                continue;
            }
        }
        else {
            fprintf(stderr, "unknown option %s\n", argv[i]);
            return -1;
        }    
    }
    return 0;
}


int main(int argc, const char* argv[])
{
    int ret = -1;
    network_post_error_t ret_status = POST_SUCCESS;
    uint32_t quote_size = 0;
    uint8_t* p_quote_buffer = NULL;
    FILE* pFile = NULL;
    uint8_t *buffer = NULL;
    uint16_t out_buffer_size = UINT16_MAX;
    uint8_t *raw_data = NULL;
    bool is_server_url_provided = false;
    cache_server_delivery_status_t delivery_status = DELIVERY_ERROR_MAX;
#ifdef MPA
    int ret_mpa = -1;
#endif

    printf("\n%s Version ", VER_FILE_DESCRIPTION_STR);
    printf("%s\n\n", STRPRODUCTVER);

    // parse the command options
    ret = parse_arg(argc, argv);
    if (ret != 0) {
        PrintHelp();
        return ret;
    }
             
    //get quote data
    ret = generate_quote(&p_quote_buffer, quote_size);
    if(ret != 0) {
        if(NULL != p_quote_buffer ) {
            free(p_quote_buffer);
            p_quote_buffer = NULL;
        }
        return ret;
    }

    // for multi-package platform: get platfrom manifest
#ifdef MPA
    ret_mpa = get_platform_manifest(&buffer, out_buffer_size);
    if (ret_mpa == -1) {
        free(p_quote_buffer);
        p_quote_buffer = NULL;
        if(NULL != buffer) {
            free(buffer);
            buffer = NULL;
        }
        return ret;
    }
#else
    buffer = NULL;
    out_buffer_size = 0;
#endif
    do {
        // Output PCK Cert Retrieval Data
        sgx_quote3_t* p_quote = (sgx_quote3_t*) (p_quote_buffer);
        sgx_ql_ecdsa_sig_data_t* p_sig_data = (sgx_ql_ecdsa_sig_data_t*)p_quote->signature_data;
        sgx_ql_auth_data_t* p_auth_data = (sgx_ql_auth_data_t*)p_sig_data->auth_certification_data;
        sgx_ql_certification_data_t* p_temp_cert_data = (sgx_ql_certification_data_t*)((uint8_t*)p_auth_data + sizeof(*p_auth_data) + p_auth_data->size);
        sgx_ql_ppid_rsa3072_encrypted_cert_info_t* p_cert_info = (sgx_ql_ppid_rsa3072_encrypted_cert_info_t*)(p_temp_cert_data->certification_data);
 
        if(output_filename.empty() == false) {
#ifdef _MSC_VER
            if (0 != fopen_s(&pFile, output_filename.c_str(), "w")) {
#else
            if (NULL == (pFile = fopen(output_filename.c_str(), "w"))) {
#endif
                printf("\nError opening %s output file.\n", output_filename.c_str());
                break;
            }
	}
 
        uint64_t data_index = 0;
#ifdef DEBUG
        PRINT_MESSAGE("EncPPID:\n");
        PRINT_BYTE_ARRAY(stdout, p_temp_cert_data->certification_data + data_index, sizeof(p_cert_info->enc_ppid));
        PRINT_MESSAGE("\n PCE_ID:\n");
        data_index = data_index + sizeof(p_cert_info->enc_ppid);
        PRINT_BYTE_ARRAY(stdout, p_temp_cert_data->certification_data + data_index, sizeof(p_cert_info->pce_info.pce_id));
        PRINT_MESSAGE("\n TCBr - CPUSVN:\n");
        data_index = data_index + sizeof(p_cert_info->pce_info.pce_id);
        PRINT_BYTE_ARRAY(stdout, p_temp_cert_data->certification_data + data_index, sizeof(p_cert_info->cpu_svn));
        PRINT_MESSAGE("\n TCBr - PCE_ISVSVN:\n");
        data_index = data_index + sizeof(p_cert_info->cpu_svn);
        PRINT_BYTE_ARRAY(stdout, p_temp_cert_data->certification_data + data_index, sizeof(p_cert_info->pce_info.pce_isv_svn));
        PRINT_MESSAGE("\n QE_ID:\n");
        PRINT_BYTE_ARRAY(stdout, &p_quote->header.user_data[0], 16);
#endif
        if (pFile != NULL) {
            data_index = 0;
            //write encrypted PPID to file
            PRINT_BYTE_ARRAY(pFile, p_temp_cert_data->certification_data + data_index, sizeof(p_cert_info->enc_ppid));
            WRITE_COMMA;

            data_index = data_index + sizeof(p_cert_info->enc_ppid);
            // write pceid to file
            PRINT_BYTE_ARRAY(pFile, p_temp_cert_data->certification_data + data_index, sizeof(p_cert_info->pce_info.pce_id));
            WRITE_COMMA;

            data_index = data_index + sizeof(p_cert_info->pce_info.pce_id);
            //write cpusvn to file
            PRINT_BYTE_ARRAY(pFile, p_temp_cert_data->certification_data + data_index, sizeof(p_cert_info->cpu_svn));
            WRITE_COMMA;

            data_index = data_index + sizeof(p_cert_info->cpu_svn);
            //write pce isv_svn to file
            PRINT_BYTE_ARRAY(pFile, p_temp_cert_data->certification_data + data_index, sizeof(p_cert_info->pce_info.pce_isv_svn));
            WRITE_COMMA;

            //write qe_id to file
            PRINT_BYTE_ARRAY(pFile, &p_quote->header.user_data[0], 16);

            //write platform manifest.
            if (out_buffer_size > 0) {
                WRITE_COMMA;
                PRINT_BYTE_ARRAY(pFile, buffer, static_cast<uint32_t>(out_buffer_size));
                PRINT_MESSAGE("\n");
            }
#ifdef MPA
            if(ret_mpa == 0) {
                if(0 == set_registration_status()) {
                    printf("Registration status has been set to completed status.\n");
                }
            }
#endif
        }

        if (server_url_string.empty() == false) {
            is_server_url_provided = true;
        }
        else {
            is_server_url_provided = is_server_url_avaiable();
        }
        if (is_server_url_provided) {
            // raw_data include: 
            // 1. enc_ppid, pce_svn, pce_id, cpu_svn, the size is sizeof(sgx_ql_ppid_rsa3072_encrypted_cert_info_t)
            // 2. qe_id: its size is 16
            // 3. platform_manifest: its size is out_buffer_size if it is multi-package platform, otherwise it is 0
            raw_data = new uint8_t[out_buffer_size + sizeof(sgx_ql_ppid_rsa3072_encrypted_cert_info_t) + 16];
            if (raw_data == NULL) {
                printf("Error: Memory has been used up.\n");
                break;
            }
            memcpy(raw_data, p_temp_cert_data->certification_data, sizeof(sgx_ql_ppid_rsa3072_encrypted_cert_info_t) + 16);
            if (out_buffer_size > 0) { //for multi-package scenario
                memcpy(raw_data + sizeof(sgx_ql_ppid_rsa3072_encrypted_cert_info_t) + 16, buffer, out_buffer_size);
            }
            uint32_t raw_data_size = static_cast<uint32_t>(sizeof(sgx_ql_ppid_rsa3072_encrypted_cert_info_t)) + 16 + out_buffer_size;
            ret_status = network_https_post(raw_data, raw_data_size);
            if (POST_SUCCESS == ret_status) {
                delivery_status = DELIVERY_SUCCESS;
#ifdef MPA
                if(ret_mpa == 0) {
                    if(0 == set_registration_status()) {
                        printf("Registration status has been set to completed status.\n");
                    }
                }
#endif
            }
            else if (POST_AUTHENTICATION_ERROR == ret_status) {
                printf("Error: the input password is not correct.\n");
                delivery_status = DELIVERY_FAIL;
            }
            else if (POST_NETWORK_ERROR == ret_status) {
                printf("Error: network error, please check the network setting or whether the cache server is down.\n");
                delivery_status = DELIVERY_FAIL;
            }
            else {
                printf("Error: unexpected error happend during sending data to cache server.\n");
                delivery_status = DELIVERY_FAIL;
            }
        }
    }while (0);
    
    if (NULL != p_quote_buffer) {
        free(p_quote_buffer);
        p_quote_buffer = NULL;
    }
    if(NULL != buffer) {
        free(buffer);
        buffer = NULL;
    }
    if(NULL != raw_data) {
        free(raw_data);
        raw_data = NULL;
    }
    if (pFile) {
        fclose(pFile);
    }
    if(delivery_status == DELIVERY_SUCCESS) {
        if(pFile != NULL) {
            printf("the data has been sent to cache server successfuly and %s has been generated successfully!\n",output_filename.c_str());
	}
        else {
            printf("the data has been sent to cache server successfuly!\n");
        }	
    }
    else if(delivery_status == DELIVERY_FAIL) {
        if(pFile != NULL) {
            printf("%s has been generated successfuly, however the data couldn't be sent to cache server!\n",output_filename.c_str());
	}
        else {
            printf("Error: the data couldn't be sent to cache server!\n");
        }	
    } 
    else {
        if(pFile != NULL) {
            printf("%s has been generated successfuly!\n",output_filename.c_str());
	}
        else {
            printf("Error: the retrieved data doesn't save to file, and it doesn't upload to cache server.\n");
        }	
    }

    return ret;
}
