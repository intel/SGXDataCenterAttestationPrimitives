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
 * File: sgx_default_qcnl_wrapper.cpp 
 *  
 * Description: SGX default PCK Collateral Network Library  
 *
 */

#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <map>
#include <fstream>
#include <algorithm>
#include <sgx_key.h>
#include "sgx_default_qcnl_wrapper.h"
#include "sgx_pce.h"
#include "network_wrapper.h"
#include "se_memcpy.h"

using namespace std;

#define MAX_URL_LENGTH  2083
#define QE3_ID_SIZE     16
#define ENC_PPID_SIZE   384
#define CPUSVN_SIZE     16
#define PCESVN_SIZE     2
#define PCEID_SIZE      2
#define FMSPC_SIZE      6

// Default URL for PCCS server if configuration file doesn't exist
extern char server_url[MAX_URL_LENGTH];
// Use secure HTTPS certificate or not
extern bool g_use_secure_cert;

#ifdef _MSC_VER
#define sscanf  sscanf_s
#endif

/**
* Method converts byte containing value from 0x00-0x0F into its corresponding ASCII code,
* e.g. converts 0x00 to '0', 0x0A to 'A'.
* Note: This is mainly a helper method for internal use in byte_array_to_hex_string().
*
* @param in byte to be converted (allowed values: 0x00-0x0F)
*
* @return ASCII code representation of the byte or 0 if method failed (e.g input value was not in provided range).
*/
static uint8_t convert_value_to_ascii(uint8_t in)
{
    if(in <= 0x09)
    {
        return (uint8_t)(in + '0');
    }
    else if(in <= 0x0F)
    {
        return (uint8_t)(in - 10 + 'A');
    }

    return 0;
}

/**
* Method converts char containing ASCII code into its corresponding value,
* e.g. converts '0' to 0x00, 'A' to 0x0A.
*
* @param in char containing ASCII code (allowed values: '0-9', 'a-f', 'A-F')
* @param val output parameter containing converted value, if method succeeds.
*
* @return true if conversion succeeds, false otherwise
*/
static bool convert_ascii_to_value(uint8_t in, uint8_t& val)
{
    if(in >= '0' && in <= '9')
    {
        val = static_cast<uint8_t>(in - '0');
    }
    else if(in >= 'A' && in <= 'F')
    {
        val = static_cast<uint8_t>(in - 'A'+10);
    }
    else if(in >= 'a' && in <= 'f')
    {
        val = static_cast<uint8_t>(in - 'a'+10);
    }
    else
    {
        return false;
    }

    return true;
}

//Function to do HEX encoding of array of bytes
//@param in_buf, bytes array whose length is in_size
//       out_buf, output the HEX encoding of in_buf on success.
//@return true on success and false on error
//The out_size must always be 2*in_size since each byte into encoded by 2 characters
static bool byte_array_to_hex_string(const uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size)
{
    if(in_size>UINT32_MAX/2)return false;
    if(in_buf==NULL||out_buf==NULL|| out_size!=in_size*2 )return false;

    for(uint32_t i=0; i< in_size; i++)
    {
        *out_buf++ = convert_value_to_ascii( static_cast<uint8_t>(*in_buf >> 4));
        *out_buf++ = convert_value_to_ascii( static_cast<uint8_t>(*in_buf & 0xf));
        in_buf++;
    }
    return true;
}

//Function to do HEX decoding
//@param in_buf, character strings which are HEX encoding of a byte array
//       out_buf, output the decode byte array on success
//@return true on success and false on error
//The in_size must be even number and equals 2*out_size
static bool hex_string_to_byte_array(const uint8_t *in_buf, uint32_t in_size, uint8_t *out_buf, uint32_t out_size)
{
    if(out_size>UINT32_MAX/2)return false;
    if(in_buf==NULL||out_buf==NULL||out_size*2!=in_size)return false;

    for(uint32_t i=0;i<out_size;i++)
    {
        uint8_t value_first, value_second;
        if(!convert_ascii_to_value(in_buf[i*2], value_first))
            return false;
        if(!convert_ascii_to_value(in_buf[i*2+1], value_second))
            return false;
        out_buf[i] = static_cast<uint8_t>(value_second+ (value_first<<4));
    }
    return true;
}

// Convert http header string to a <field,value> map 
// HTTP 1.1 header specification
//       message-header = field-name ":" [ field-value ]
//       field-name     = token
//       field-value    = *( field-content | LWS )
//       field-content  = <the OCTETs making up the field-value
//                        and consisting of either *TEXT or combinations
//                        of token, separators, and quoted-string>
//@param resp_header, http header string
//       header_map, a <string,string> map that stores fields and values
static void http_header_to_map(char* resp_header, uint32_t header_size, map<string,string>& header_map)
{
    size_t length = header_size;
    size_t start = 0, end = 0;
    
    while(start < length) {
        while (end < length && resp_header[end] != '\r' && resp_header[end] != '\n') {
            end++;
        }
        if (end == start) {
            start++;
            end++;
        }
        else {
            // parse one line
            string str((unsigned char*)resp_header+start, (unsigned char*)resp_header+end);
            size_t pos = str.find(": ");
            if (pos != string::npos) {
                // HTTP headers are case-insensitive. Convert to lower case
                // for convenience.
                string header_lc= str.substr(0, pos);
                transform(header_lc.begin(), header_lc.end(), header_lc.begin(),
                          [](unsigned char c){return (unsigned char)::tolower(c);});
                header_map.insert(pair<string, string>(header_lc, str.substr(pos+2)));
            }
            start = end;
        }
    }
}

// This function is used to unescpae URL Codes, for example, %20 to SPACE character(0x20)
static string unescape(string& src ) {
    string dst;
    char ch;
    int i, value;
    for (i = 0; i < (int)(src.length()-2); i++) {
        if (int(src[i])=='%') {
            sscanf(src.substr(i+1,2).c_str(), "%x", &value);
            ch = static_cast<char>(value);
            dst += ch;
            i += 2;
        } else {
            dst += src[i];
        }
    }
    return dst;
}

/**
* This function appends request parameters of byte array type to the URL in HEX string format
*
* @param url Request URL
* @param ba  Request parameter in byte array
* @param ba_size Size of byte array
*
* @return true If the byte array was appended to the URL successfully 
*/
static sgx_qcnl_error_t url_append_req_para(string& url, const uint8_t* ba, const uint32_t ba_size) 
{
    if (ba_size >= UINT32_MAX / 2)
        return SGX_QCNL_INVALID_PARAMETER;

    uint8_t* hex = (uint8_t*)malloc(ba_size * 2);
    if (!hex)
        return SGX_QCNL_OUT_OF_MEMORY;
    if (!byte_array_to_hex_string(ba, ba_size, hex, ba_size*2)){
        free(hex);
        return SGX_QCNL_UNEXPECTED_ERROR;
    }
    url.append(reinterpret_cast<const char*>(hex), ba_size*2);
    free(hex);
    return SGX_QCNL_SUCCESS;
}

/**
* This API gets PCK certificate chain and TCBm from PCCS server based on the information provided(QE_ID, TCBr, EncPPID, PCE_ID) 
* The buffer allocated by this function should be freed with sgx_qcnl_free_pck_cert_chain by the caller.
*
* @param p_pck_cert_id PCK cert identity information
* @param pp_quote_config Output buffer for quote configuration data
*
* @return SGX_QCNL_SUCCESS If the PCK certificate chain and TCBm was retrieved from PCCS server successfully.
*/
sgx_qcnl_error_t sgx_qcnl_get_pck_cert_chain(const sgx_ql_pck_cert_id_t *p_pck_cert_id,
                                           sgx_ql_config_t **pp_quote_config)
{
    sgx_qcnl_error_t  ret = SGX_QCNL_UNEXPECTED_ERROR;

    // Check input parameters
    if (p_pck_cert_id == NULL || pp_quote_config == NULL) {
        return SGX_QCNL_INVALID_PARAMETER;
    }
    if (p_pck_cert_id->p_qe3_id == NULL || p_pck_cert_id->qe3_id_size != QE3_ID_SIZE) {
        return SGX_QCNL_INVALID_PARAMETER;
    }
    if (p_pck_cert_id->p_encrypted_ppid != NULL && p_pck_cert_id->encrypted_ppid_size != ENC_PPID_SIZE) {
        // Allow ENCRYPTED_PPID to be NULL, but if it is not NULL, the size must match ENC_PPID_SIZE
        return SGX_QCNL_INVALID_PARAMETER;
    }
    if (p_pck_cert_id->p_platform_cpu_svn == NULL || p_pck_cert_id->p_platform_pce_isv_svn == NULL) {
        return SGX_QCNL_INVALID_PARAMETER;
    }
    if (p_pck_cert_id->crypto_suite != PCE_ALG_RSA_OAEP_3072) {
        return SGX_QCNL_INVALID_PARAMETER;
    }

    // initialize https request url
    string url(server_url);

    // Append QE ID
    url.append("pckcert?qeid=");
    if ((ret = url_append_req_para(url, p_pck_cert_id->p_qe3_id, p_pck_cert_id->qe3_id_size)) != SGX_QCNL_SUCCESS) {
        return ret;
    }

    // Append encrypted PPID
    url.append("&encrypted_ppid=");
    if (p_pck_cert_id->p_encrypted_ppid == NULL) {
        uint8_t enc_ppid_unused[ENC_PPID_SIZE] = { 0 };
        if ((ret = url_append_req_para(url, (const uint8_t*)&enc_ppid_unused, sizeof(enc_ppid_unused))) != SGX_QCNL_SUCCESS) {
            return ret;
        }
    }
    else {
        if ((ret = url_append_req_para(url, p_pck_cert_id->p_encrypted_ppid, p_pck_cert_id->encrypted_ppid_size)) != SGX_QCNL_SUCCESS) {
            return ret;
        }
    }

    // Append cpusvn
    url.append("&cpusvn=");
    if ((ret = url_append_req_para(url, reinterpret_cast<const uint8_t*>(p_pck_cert_id->p_platform_cpu_svn), sizeof(sgx_cpu_svn_t))) != SGX_QCNL_SUCCESS){
        return SGX_QCNL_UNEXPECTED_ERROR;
    }
    
    // Append pcesvn
    url.append("&pcesvn=");
    if ((ret = url_append_req_para(url, reinterpret_cast<const uint8_t*>(p_pck_cert_id->p_platform_pce_isv_svn), sizeof(sgx_isv_svn_t))) != SGX_QCNL_SUCCESS){
        return SGX_QCNL_UNEXPECTED_ERROR;
    }
    
    // Append pceid
    url.append("&pceid=");
    if ((ret = url_append_req_para(url, reinterpret_cast<const uint8_t*>(&p_pck_cert_id->pce_id), sizeof(p_pck_cert_id->pce_id))) != SGX_QCNL_SUCCESS){
        return SGX_QCNL_UNEXPECTED_ERROR;
    }

    char* resp_msg = NULL;
    uint32_t resp_size;
    char* resp_header = NULL;
    uint32_t header_size;

    ret = qcnl_https_get(url.c_str(), &resp_msg, resp_size, &resp_header, header_size);
    if (ret != SGX_QCNL_SUCCESS) {
        return ret;
    }

    do {
        // Get TCBm and certchain from HTTP response header
        map<string,string> header_map;
        map<string, string>::const_iterator it;
        http_header_to_map(resp_header, header_size, header_map);
        it = header_map.find("sgx-tcbm");
        if (it == header_map.end()) {
            ret = SGX_QCNL_MSG_ERROR;
            break;
        }
        string tcbm = it->second;
        it = header_map.find("sgx-pck-certificate-issuer-chain");
        if (it == header_map.end()) {
            ret = SGX_QCNL_MSG_ERROR;
            break;
        }
        string certchain = it->second;
        certchain = unescape(certchain);

        // allocate output buffer
        *pp_quote_config = (sgx_ql_config_t*)malloc(sizeof(sgx_ql_config_t));
        if (*pp_quote_config == NULL) {
            ret = SGX_QCNL_OUT_OF_MEMORY;
            break;
        }
        memset(*pp_quote_config, 0, sizeof(sgx_ql_config_t));

        // set version
        (*pp_quote_config)->version = SGX_QL_CONFIG_VERSION_1;

        // set tcbm (cpusvn and pcesvn) 
        if (tcbm.size() != (CPUSVN_SIZE + PCESVN_SIZE)*2) {
            ret = SGX_QCNL_MSG_ERROR;
            break;
        }
        if (!hex_string_to_byte_array(reinterpret_cast<const uint8_t*>(tcbm.data()), 
                                      CPUSVN_SIZE*2, 
                                      reinterpret_cast<uint8_t*>(&(*pp_quote_config)->cert_cpu_svn), 
                                      sizeof(sgx_cpu_svn_t))) {
            ret = SGX_QCNL_MSG_ERROR;
            break;
        }
        if (!hex_string_to_byte_array(reinterpret_cast<const uint8_t*>(tcbm.data()+CPUSVN_SIZE*2), 
                                      PCESVN_SIZE*2, 
                                      reinterpret_cast<uint8_t*>(&(*pp_quote_config)->cert_pce_isv_svn), 
                                      sizeof(sgx_isv_svn_t))) {
            ret = SGX_QCNL_MSG_ERROR;
            break;
        }

        // set certchain (leaf cert || intermediateCA || root CA)
        if (resp_size >= UINT32_MAX - (uint32_t)certchain.size()) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }

        (*pp_quote_config)->cert_data_size = (uint32_t)(certchain.size() + resp_size);
        (*pp_quote_config)->p_cert_data = (uint8_t*)malloc((*pp_quote_config)->cert_data_size);
        if (!(*pp_quote_config)->p_cert_data) {
            ret = SGX_QCNL_OUT_OF_MEMORY;
            break; 
        }
        if (memcpy_s((*pp_quote_config)->p_cert_data, (*pp_quote_config)->cert_data_size, resp_msg, resp_size) != 0) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }
        if (memcpy_s((*pp_quote_config)->p_cert_data + resp_size, certchain.size(), certchain.data(), certchain.size()) != 0) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }

        ret = SGX_QCNL_SUCCESS;
    } while(0);

    if (ret != SGX_QCNL_SUCCESS) {
        sgx_qcnl_free_pck_cert_chain(*pp_quote_config);
    }
    if (resp_msg) {
        free(resp_msg);
        resp_msg = NULL;
    }
    if (resp_header){
        free(resp_header);
        resp_header = NULL;
    }

    return ret;
}

/**
* This API frees the buffer allocated by sgx_qcnl_get_pck_cert_chain
*/
void sgx_qcnl_free_pck_cert_chain(sgx_ql_config_t *p_quote_config)
{
    if (p_quote_config){
        if (p_quote_config->p_cert_data){
            free(p_quote_config->p_cert_data);
            p_quote_config->p_cert_data = NULL;
        }
        memset(p_quote_config, 0, sizeof(sgx_ql_config_t));
        free(p_quote_config);
    }
}

/**
* This API gets CRL certificate chain from PCCS server. The p_crl_chain buffer allocated by this API
* must be freed with sgx_qcnl_free_pck_crl_chain upon success.
*
* @param ca Currently only "platform" or "processor"
* @param ca_size Size of the ca buffer
* @param p_crl_chain Output buffer for CRL certificate chain
* @param p_crl_chain_size Size of CRL certificate chain
*
* @return SGX_QCNL_SUCCESS If the CRL certificate chain was retrieved from PCCS server successfully.
*/
sgx_qcnl_error_t sgx_qcnl_get_pck_crl_chain(const char* ca,
                                          uint16_t ca_size,
                                          uint8_t **p_crl_chain,
                                          uint16_t *p_crl_chain_size)
{
    // Check input parameters
    if (p_crl_chain == NULL || p_crl_chain_size == NULL) {
        return SGX_QCNL_INVALID_PARAMETER;
    }
    if (ca == NULL || (ca_size != 8 && ca_size != 9)) {
        return SGX_QCNL_INVALID_PARAMETER;
    }
    if (ca_size == 8 && strncmp(ca, "platform", ca_size) != 0) {
        return SGX_QCNL_INVALID_PARAMETER;
    }
    if (ca_size == 9 && strncmp(ca, "processor", ca_size) != 0) {
        return SGX_QCNL_INVALID_PARAMETER;
    }

    // initialize https request url
    string url(server_url);

    // Append ca 
    url.append("pckcrl?ca=").append(ca);

    char* resp_msg = NULL;
    uint32_t resp_size;
    char* resp_header = NULL;
    uint32_t header_size;

    sgx_qcnl_error_t ret = qcnl_https_get(url.c_str(), &resp_msg, resp_size, &resp_header, header_size);
    if (ret != SGX_QCNL_SUCCESS) {
        return ret;
    }

    do {
        // Get certchain from HTTP response header
        map<string,string> header_map;
        map<string, string>::const_iterator it;
        http_header_to_map(resp_header, header_size, header_map);
        it = header_map.find("sgx-pck-crl-issuer-chain");
        if (it == header_map.end()) {
            ret = SGX_QCNL_MSG_ERROR;
            break;
        }
        string certchain = it->second;
        certchain = unescape(certchain);

        if (resp_size >= UINT32_MAX - (uint32_t)certchain.size()
           || (resp_size+(uint32_t)certchain.size() >= UINT16_MAX)) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }

        *p_crl_chain_size = (uint16_t)(certchain.size() + resp_size);
        *p_crl_chain = (uint8_t*)malloc(*p_crl_chain_size);
        if (*p_crl_chain == NULL) {
            ret = SGX_QCNL_OUT_OF_MEMORY;
            break;
        }

        // set certchain (crl || intermediateCA || root CA)
        if (memcpy_s(*p_crl_chain, *p_crl_chain_size, resp_msg, resp_size) != 0) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }
        if (memcpy_s(*p_crl_chain + resp_size, certchain.size(), certchain.data(), certchain.size()) != 0) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }

        ret = SGX_QCNL_SUCCESS;
    } while(0);

    if (ret != SGX_QCNL_SUCCESS) {
        sgx_qcnl_free_pck_crl_chain(*p_crl_chain);
    }
    if (resp_msg) {
        free(resp_msg);
        resp_msg = NULL;
    }
    if (resp_header){
        free(resp_header);
        resp_header = NULL;
    }

    return ret;
}

/**
* This API frees the p_crl_chain buffer allocated by sgx_qcnl_get_pck_crl_chain
*/
void sgx_qcnl_free_pck_crl_chain(uint8_t *p_crl_chain)
{
    if (p_crl_chain) {
        free(p_crl_chain);
    }
}

/**
* This API gets TCB information from PCCS server. The p_tcbinfo buffer allocated by this API
* must be freed with sgx_qcnl_free_tcbinfo upon success.
*
* @param fmspc Family-Model-Stepping value
* @param fmspc_size Size of the fmspc buffer
* @param p_tcbinfo Output buffer for TCB information
* @param p_tcbinfo_size Size of TCB information
*
* @return SGX_QCNL_SUCCESS If the TCB information was retrieved from PCCS server successfully.
*/
sgx_qcnl_error_t sgx_qcnl_get_tcbinfo(const char* fmspc,
                                    uint16_t fmspc_size,
                                    uint8_t **p_tcbinfo,
                                    uint16_t *p_tcbinfo_size)
{
    // Check input parameters
    // fmspc is always 6 bytes
    if (p_tcbinfo == NULL || p_tcbinfo_size == NULL) {
        return SGX_QCNL_INVALID_PARAMETER;
    }
    if (fmspc == NULL || fmspc_size != FMSPC_SIZE) {
        return SGX_QCNL_INVALID_PARAMETER;
    }

    sgx_qcnl_error_t ret = SGX_QCNL_UNEXPECTED_ERROR;
    // initialize https request url
    string url(server_url);

    // Append fmspc
    url.append("tcb?fmspc=");
    if ((ret = url_append_req_para(url, reinterpret_cast<const uint8_t*>(fmspc), fmspc_size)) != SGX_QCNL_SUCCESS) {
        return SGX_QCNL_UNEXPECTED_ERROR;
    }

    char* resp_msg = NULL;
    uint32_t resp_size;
    char* resp_header = NULL;
    uint32_t header_size;

    ret = qcnl_https_get(url.c_str(), &resp_msg, resp_size, &resp_header, header_size);
    if (ret != SGX_QCNL_SUCCESS) {
        return ret;
    }

    do {
        // Get certchain from HTTP response header
        map<string,string> header_map;
        map<string, string>::const_iterator it;
        http_header_to_map(resp_header, header_size, header_map);
        it = header_map.find("sgx-tcb-info-issuer-chain");
        if (it == header_map.end()) {
            ret = SGX_QCNL_MSG_ERROR;
            break;
        }
        string certchain = it->second;
        certchain = unescape(certchain);

        if (resp_size >= UINT32_MAX - (uint32_t)certchain.size()
           || (resp_size+(uint32_t)certchain.size() >= UINT16_MAX)) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }

        *p_tcbinfo_size = (uint16_t)(certchain.size() + resp_size);
        *p_tcbinfo = (uint8_t*)malloc(*p_tcbinfo_size);
        if (*p_tcbinfo == NULL) {
            ret = SGX_QCNL_OUT_OF_MEMORY;
            break;
        }

        // set certchain (tcbinfo || signingCA || root CA)
        if (memcpy_s(*p_tcbinfo, *p_tcbinfo_size, resp_msg, resp_size) != 0) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }
        if (memcpy_s(*p_tcbinfo + resp_size, certchain.size(), certchain.data(), certchain.size()) != 0) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }

        ret = SGX_QCNL_SUCCESS;
    } while(0);

    if (ret != SGX_QCNL_SUCCESS) {
        sgx_qcnl_free_tcbinfo(*p_tcbinfo);
    }
    if (resp_msg) {
        free(resp_msg);
        resp_msg = NULL;
    }
    if (resp_header){
        free(resp_header);
        resp_header = NULL;
    }

    return ret;
}

/**
* This API frees the p_tcbinfo buffer allocated by sgx_qcnl_get_tcbinfo
*/
void sgx_qcnl_free_tcbinfo(uint8_t *p_tcbinfo)
{
    if (p_tcbinfo) {
        free(p_tcbinfo);
    }
}

/**
* This API gets QE identity from PCCS server. The p_qe_identity buffer allocated by this API
* must be freed with sgx_qcnl_free_qe_identity upon success.
*
* @param qe_type Currently only 0 (ECDSA QE) is supported
* @param p_qe_identity Output buffer for QE identity
* @param p_qe_identity_size Size of QE identity
*
* @return SGX_QCNL_SUCCESS If the QE identity was retrieved from PCCS server successfully.
*/
sgx_qcnl_error_t sgx_qcnl_get_qe_identity(uint8_t qe_type,
                                        uint8_t **p_qe_identity,
                                        uint16_t *p_qe_identity_size)
{
    // Check input parameters
    if (p_qe_identity == NULL || p_qe_identity_size == NULL || qe_type != 0) {
        return SGX_QCNL_INVALID_PARAMETER;
    }

    // initialize https request url
    string url(server_url);

    // Append qe identity 
    url.append("qe/identity");

    char* resp_msg = NULL;
    uint32_t resp_size;
    char* resp_header = NULL;
    uint32_t header_size;

    sgx_qcnl_error_t ret = qcnl_https_get(url.c_str(), &resp_msg, resp_size, &resp_header, header_size);
    if (ret != SGX_QCNL_SUCCESS) {
        return ret;
    }

    do {
        // Get certchain from HTTP response header
        map<string,string> header_map;
        map<string, string>::const_iterator it;
        http_header_to_map(resp_header, header_size, header_map);
        it = header_map.find("sgx-enclave-identity-issuer-chain");
        if (it == header_map.end()) {
            ret = SGX_QCNL_MSG_ERROR;
            break;
        }
        string certchain = it->second;
        certchain = unescape(certchain);

        if (resp_size >= UINT32_MAX - (uint32_t)certchain.size() 
           || (resp_size+(uint32_t)certchain.size() >= UINT16_MAX)) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }

        *p_qe_identity_size = (uint16_t)(certchain.size() + resp_size);
        *p_qe_identity = (uint8_t*)malloc(*p_qe_identity_size);
        if (*p_qe_identity == NULL) {
            ret = SGX_QCNL_OUT_OF_MEMORY;
            break;
        }

        // set certchain (QE identity || signingCA || root CA)
        if (memcpy_s(*p_qe_identity, *p_qe_identity_size, resp_msg, resp_size) != 0) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }
        if (memcpy_s(*p_qe_identity + resp_size, certchain.size(), certchain.data(), certchain.size()) != 0) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }

        ret = SGX_QCNL_SUCCESS;
    } while(0);

    if (ret != SGX_QCNL_SUCCESS) {
        sgx_qcnl_free_qe_identity(*p_qe_identity);
    }
    if (resp_msg) {
        free(resp_msg);
        resp_msg = NULL;
    }
    if (resp_header){
        free(resp_header);
        resp_header = NULL;
    }

    return ret;
}

/**
* This API frees the p_qe_identity buffer allocated by sgx_qcnl_get_qe_identity
*/
void sgx_qcnl_free_qe_identity(uint8_t *p_qe_identity)
{
    if(p_qe_identity) {
        free(p_qe_identity);
    }
}

/**
* This API gets QvE identity from PCCS server. The pp_qve_identity and pp_qve_identity_issuer_chain buffer allocated by this API
* must be freed with sgx_qcnl_free_qve_identity upon success.
*
* @param pp_qve_identity Output buffer for QvE identity
* @param p_qve_identity_size Size of QvE identity
* @param pp_qve_identity_issuer_chain Output buffer for QvE identity certificate chain
* @param p_qve_identity_issuer_chain_size Size of QvE identity certificate chain
*
* @return SGX_QCNL_SUCCESS If the QvE identity was retrieved from PCCS server successfully.
*/
sgx_qcnl_error_t sgx_qcnl_get_qve_identity(char **pp_qve_identity, 
                                           uint32_t *p_qve_identity_size,
                                           char **pp_qve_identity_issuer_chain,
                                           uint32_t *p_qve_identity_issuer_chain_size)
{
    // Check input parameters
    if (pp_qve_identity == NULL || p_qve_identity_size == NULL 
       || pp_qve_identity_issuer_chain == NULL || p_qve_identity_issuer_chain_size == NULL) {
        return SGX_QCNL_INVALID_PARAMETER;
    }

    *pp_qve_identity = NULL;
    *pp_qve_identity_issuer_chain = NULL;

    // initialize https request url
    string url(server_url);

    // Append qve identity 
    url.append("qve/identity");

    char* resp_msg = NULL;
    uint32_t resp_size;
    char* resp_header = NULL;
    uint32_t header_size;

    sgx_qcnl_error_t ret = qcnl_https_get(url.c_str(), &resp_msg, resp_size, &resp_header, header_size);
    if (ret != SGX_QCNL_SUCCESS) {
        return ret;
    }

    do {
        // Get certchain from HTTP response header
        map<string,string> header_map;
        map<string, string>::const_iterator it;
        http_header_to_map(resp_header, header_size, header_map);
        it = header_map.find("sgx-enclave-identity-issuer-chain");
        if (it == header_map.end()) {
            ret = SGX_QCNL_MSG_ERROR;
            break;
        }
        string certchain = it->second;
        certchain = unescape(certchain);

        if (resp_size >= UINT32_MAX - 1) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }
        if (certchain.size() >= UINT32_MAX - 1){
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }

        // allocate buffers
        *p_qve_identity_size = resp_size + 1;
        *pp_qve_identity = (char*)malloc(*p_qve_identity_size);
        if (*pp_qve_identity == NULL) {
            ret = SGX_QCNL_OUT_OF_MEMORY;
            break;
        }
        *p_qve_identity_issuer_chain_size = (uint32_t)(certchain.size() + 1);
        *pp_qve_identity_issuer_chain = (char*)malloc(*p_qve_identity_issuer_chain_size);
        if (*pp_qve_identity_issuer_chain == NULL) {
            ret = SGX_QCNL_OUT_OF_MEMORY;
            break;
        }

        // set QvE identity
        if (memcpy_s(*pp_qve_identity, *p_qve_identity_size, resp_msg, resp_size) != 0) {
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
    } while(0);

    if (ret != SGX_QCNL_SUCCESS) {
        sgx_qcnl_free_qve_identity(*pp_qve_identity, *pp_qve_identity_issuer_chain);
    }
    if (resp_msg) {
        free(resp_msg);
        resp_msg = NULL;
    }
    if (resp_header){
        free(resp_header);
        resp_header = NULL;
    }

    return ret;
}

/**
* This API frees the p_qve_identity and p_qve_identity_issuer_chain buffer allocated by sgx_qcnl_get_qve_identity
*/
void sgx_qcnl_free_qve_identity(char *p_qve_identity, char *p_qve_identity_issuer_chain)
{
    if(p_qve_identity) {
        free(p_qve_identity);
        p_qve_identity = NULL;
    }
    if(p_qve_identity_issuer_chain) {
        free(p_qve_identity_issuer_chain);
        p_qve_identity_issuer_chain = NULL;
    }
}

/**
* This API gets Root CA CRL from PCCS server. The p_root_ca_crl buffer allocated by this API
* must be freed with sgx_qcnl_free_root_ca_crl upon success.
*
* @param p_root_ca_crl Output buffer for Root CA CRL 
* @param p_root_ca_cal_size Size of Root CA CRL
*
* @return SGX_QCNL_SUCCESS If the Root CA CRL was retrieved from PCCS server successfully.
*/
sgx_qcnl_error_t sgx_qcnl_get_root_ca_crl (uint8_t **p_root_ca_crl, uint16_t *p_root_ca_cal_size)
{
    // Check input parameters
    if (p_root_ca_crl == NULL || p_root_ca_cal_size == NULL) {
        return SGX_QCNL_INVALID_PARAMETER;
    }

    // initialize https request url
    string url(server_url);

    // Append url
    url.append("rootcacrl");

    char* resp_msg = NULL;
    uint32_t resp_size;
    char* resp_header = NULL;
    uint32_t header_size;

    sgx_qcnl_error_t ret = qcnl_https_get(url.c_str(), &resp_msg, resp_size, &resp_header, header_size);
    if (ret != SGX_QCNL_SUCCESS) {
        return ret;
    }

    do {
        if (resp_size >= UINT16_MAX) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }

        *p_root_ca_cal_size = (uint16_t)(resp_size);
        *p_root_ca_crl = (uint8_t*)malloc(*p_root_ca_cal_size);
        if (*p_root_ca_crl == NULL) {
            ret = SGX_QCNL_OUT_OF_MEMORY;
            break;
        }

        // set Root CA CRL
        if (memcpy_s(*p_root_ca_crl, *p_root_ca_cal_size, resp_msg, resp_size) != 0) {
            ret = SGX_QCNL_UNEXPECTED_ERROR;
            break;
        }

        ret = SGX_QCNL_SUCCESS;
    } while(0);

    if (ret != SGX_QCNL_SUCCESS) {
        sgx_qcnl_free_root_ca_crl(*p_root_ca_crl);
    }
    if (resp_msg) {
        free(resp_msg);
        resp_msg = NULL;
    }
    if (resp_header){
        free(resp_header);
        resp_header = NULL;
    }

    return ret;
}

/**
* This API frees the p_root_ca_crl buffer allocated by sgx_qcnl_get_root_ca_crl
*/
void sgx_qcnl_free_root_ca_crl (uint8_t *p_root_ca_crl)
{
    if(p_root_ca_crl) {
        free(p_root_ca_crl);
    }
}
