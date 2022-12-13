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
 * File: td_ql_logic.cpp
 *
 * Description: This is the implementation of the quoting class that will support
 * the reference ECDSA-P256 quoting class used by an application requiring quote
 * generation.  These are the untrusted functions of the reference code. It will
 * call the trusted functions in the ECDSA-P256 quoting enclave.
 *
 */
#include <string.h>
#include <limits.h>

#include "sgx_urts.h"
#include "td_ql_logic.h"
#include "user_types.h"
#include "tdqe_u.h"
#include "id_enclave_u.h"

#ifndef _MSC_VER
    #define TDQE_ENCLAVE_NAME "libsgx_tdqe.signed.so.1"
    #define ID_ENCLAVE_NAME "libsgx_id_enclave.signed.so.1"
    #define TEE_ATT_QUOTE_CONFIG_LIB_FILE_NAME "libdcap_quoteprov.so.1"
#else
    #define TDQE_ENCLAVE_NAME _T("tdqe.signed.dll")
    #define ID_ENCLAVE_NAME _T("id_enclave.signed.dll")
    #define TEE_ATT_QUOTE_CONFIG_LIB_FILE_NAME _T("dcap_quoteprov.dll")
#endif
#define ECDSA_BLOB_LABEL "tdqe_data.blob"


#define MAX_CERT_DATA_SIZE (4098*3)
#define MIN_CERT_DATA_SIZE (500)  // Chosen to be large enough to contain the native cert data types.


typedef tee_att_error_t (*sgx_get_quote_config_func_t)(const sgx_ql_pck_cert_id_t *p_pck_cert_id,
                                                      sgx_ql_config_t **pp_quote_config);

typedef tee_att_error_t (*sgx_free_quote_config_func_t)(sgx_ql_config_t *p_quote_config);

typedef tee_att_error_t (*sgx_write_persistent_data_func_t)(const uint8_t *p_buf,
                                                           uint32_t buf_size,
                                                           const char *p_label);

typedef tee_att_error_t (*sgx_read_persistent_data_func_t)(const uint8_t *p_buf,
                                                          uint32_t *p_buf_size,
                                                          const char *p_label);
#ifndef _MSC_VER
inline errno_t memcpy_s(void *dest, size_t numberOfElements, const void *src, size_t count)
{
    if(0 == count)
        return -1;
    if(NULL == dest)
        return -1;
    if ((src == NULL) || (numberOfElements < count)) {
        memset(dest, 0, numberOfElements);
        return -1;
    }

    memcpy(dest, src, count);
    return 0;
}
#define strcpy_s(dst, dstsize, src) strncpy(dst, src, dstsize)
#endif


/**
 * Since the error code space of the PCE library is not unique from SGX SDK error space, need to explicitly
 * translate the errors here instead of in the final high level error scrubbing function.
 *
 * @param pce_error Error return by the pce library API.
 *
 * @return TEE_ATT_SUCCESS
 * @return TEE_ATT_OUT_OF_EPC
 * @return TEE_ATT_INTERFACE_UNAVAILABLE
 * @return TEE_ATT_ERROR_UNEXPECTED
 * @return TEE_ATT_KEY_CERTIFCATION_ERROR
 *
 */
static tee_att_error_t translate_pce_errors(sgx_pce_error_t pce_error)
{
    tee_att_error_t ret_val = TEE_ATT_ERROR_UNEXPECTED;

    switch(pce_error) {

    case SGX_PCE_SUCCESS:
        ret_val = TEE_ATT_SUCCESS;
        break;

    case SGX_PCE_OUT_OF_EPC:
        ret_val = TEE_ATT_OUT_OF_EPC;
        break;

    case SGX_PCE_INTERFACE_UNAVAILABLE:
        ret_val = TEE_ATT_INTERFACE_UNAVAILABLE;
        break;

    case SGX_PCE_INVALID_TCB:
        ret_val = TEE_ATT_KEY_CERTIFCATION_ERROR;
        break;

    case SGX_PCE_INVALID_PRIVILEGE:       // Indicates that the QE does not have the prov key bit set.  Unexpected for a production release.
        ret_val = TEE_ATT_ERROR_INVALID_PRIVILEGE;
        break;

    case SGX_PCE_UNEXPECTED:
    case SGX_PCE_INVALID_PARAMETER:       // Inputs to the PCE are generated by the QE library.  Don't expect input errors.
    case SGX_PCE_INVALID_REPORT:          // Indicates that the QE.REPORT is invalid.  This unexpected.
    case SGX_PCE_CRYPTO_ERROR:            // Indicates that the QE.REPORT.ReportData is invalid.  This unexpected.
        ret_val = TEE_ATT_ERROR_UNEXPECTED;
        break;

    default:
        ret_val = TEE_ATT_ERROR_UNEXPECTED;
        break;
    }

    return(ret_val);
}

#ifndef _MSC_VER
void *
#else
HMODULE
#endif
tee_att_config_t::get_qpl_handle()
{
    if (m_qpl_handle)
        return m_qpl_handle;
#ifndef _MSC_VER
    if (qpl_path[0]) {
        m_qpl_handle = dlopen(qpl_path, RTLD_LAZY);
        if (NULL == m_qpl_handle) {
                SE_PROD_LOG("Cannot open Quote Provider Library %s\n", qpl_path);
            }
        return m_qpl_handle;
    }
    else {
        m_qpl_handle = dlopen(TEE_ATT_QUOTE_CONFIG_LIB_FILE_NAME, RTLD_LAZY);
        if (NULL == m_qpl_handle) {
            SE_PROD_LOG("Cannot open Quote Provider Library %s\n", TEE_ATT_QUOTE_CONFIG_LIB_FILE_NAME);
        }
    }
    return m_qpl_handle;
}
#else
    m_qpl_handle = LoadLibrary(TEE_ATT_QUOTE_CONFIG_LIB_FILE_NAME);
    if (m_qpl_handle == NULL) {
        SE_PROD_LOG("Couldn't find the platform library. %d\n", GetLastError());
        return NULL;
    }
    return m_qpl_handle;
}
#endif

/**
 * Wrapper function for retrieving the PCK Certificate data from the platform's Quote Provider Library.
 *
 * @param p_pck_cert_id Pointer to the platorm identification data.  Must not be NULL.
 * @param p_cert_cpu_svn Returned CPUSVN of the PCK cert. Must not be NULL.
 * @param p_cert_isv_svn Returned CPUSVN of the PCK cert.  Must not be NULL.
 * @param p_cert_data_size Pointer to the size in bytes of the cert data.  Must not be NULL. If p_cert_data is NULL,
 *                         then this function will return the size of the bufffer to allocate. If p_cert_data is not
 *                         NULL, then the p_cert_data_size points the number of bytes in the p_cert_data buffer and it
 *                         must not be 0.
 * @param p_cert_data Pointer ot the buffer to containt the cert data.  Can be NULL.  If NULL, the required buffer size
 *                         will be returned in p_cert_data_size.
 *
 * @return TEE_ATT_SUCCESS
 * @return TEE_ATT_ERROR_INVALID_PARAMETER
 * @return TEE_ATT_PLATFORM_LIB_UNAVAILABLE
 * @return TEE_ATT_NO_PLATFORM_CERT_DATA
 */
tee_att_error_t tee_att_config_t::get_platform_quote_cert_data(sgx_ql_pck_cert_id_t *p_pck_cert_id,
                                                   sgx_cpu_svn_t *p_cert_cpu_svn,
                                                   sgx_isv_svn_t *p_cert_pce_isv_svn,
                                                   uint32_t *p_cert_data_size,
                                                   uint8_t *p_cert_data)
{
    tee_att_error_t ret_val = TEE_ATT_PLATFORM_LIB_UNAVAILABLE;
    sgx_get_quote_config_func_t p_sgx_get_quote_config = NULL;
    sgx_free_quote_config_func_t p_sgx_free_quote_config = NULL;
    sgx_ql_config_t *p_pck_cert_config = NULL;

    #ifndef _MSC_VER
    void *handle = NULL;
    char *error1 = NULL;
    char *error2 = NULL;
    #else
    HINSTANCE handle;
    #endif

    if ((NULL == p_pck_cert_id) ||
        (NULL == p_cert_cpu_svn) ||
        (NULL == p_cert_pce_isv_svn) ||
        (NULL == p_cert_data_size)) {
        return TEE_ATT_ERROR_INVALID_PARAMETER;
    }
    if ((NULL != p_cert_data) && (0 == *p_cert_data_size)) {
        return TEE_ATT_ERROR_INVALID_PARAMETER;
    }

    handle = get_qpl_handle();
#ifndef _MSC_VER
    if (!handle) {

        SE_PROD_LOG("Couldn't find the platform library. %s\n", dlerror());
        return ret_val;
    }
    else {
        p_sgx_get_quote_config = (sgx_get_quote_config_func_t)dlsym(handle, "sgx_ql_get_quote_config");
        error1 = dlerror();
        p_sgx_free_quote_config = (sgx_free_quote_config_func_t)dlsym(handle, "sgx_ql_free_quote_config");
        error2 = dlerror();

        if ((NULL != error1) ||
            (NULL == p_sgx_get_quote_config) ||
            (NULL != error2) ||
            (NULL == p_sgx_free_quote_config)) {
            SE_PROD_LOG("Couldn't find 'sgx_ql_get_quote_config()' and 'sgx_ql_free_quote_config()' in the platform library. %s\n", dlerror());
            goto CLEANUP;
        }

#else
    if (handle == NULL) {
        SE_PROD_LOG("Couldn't find the platform library. %d\n", GetLastError());
        return ret_val;
    }
    else {
        SE_TRACE(SE_TRACE_DEBUG, "Found the Quote's dependent library.\n");
        p_sgx_get_quote_config = (sgx_get_quote_config_func_t)GetProcAddress(handle, "sgx_ql_get_quote_config");
        p_sgx_free_quote_config = (sgx_free_quote_config_func_t)GetProcAddress(handle, "sgx_ql_free_quote_config");

        if ((NULL == p_sgx_get_quote_config) ||
            (NULL == p_sgx_free_quote_config))
        {
            SE_PROD_LOG("Couldn't find 'sgx_ql_get_quote_config()' and 'sgx_ql_free_quote_config()' in the platform library. %d\n", GetLastError());
            goto CLEANUP;
        }
#endif
        SE_TRACE(SE_TRACE_DEBUG, "Found the sgx_ql_get_quote_config and sgx_ql_free_quote_config API.\n");
        SE_TRACE(SE_TRACE_DEBUG, "Request the Quote Config data.\n");
        ret_val = p_sgx_get_quote_config(p_pck_cert_id, &p_pck_cert_config);
        if (TEE_ATT_SUCCESS != ret_val) {
            SE_PROD_LOG("Error returned from the p_sgx_get_quote_config API. 0x%04x\n", ret_val);
            goto CLEANUP;
        }
        if (NULL == p_pck_cert_config) {
            ret_val = TEE_ATT_NO_PLATFORM_CERT_DATA;
            SE_PROD_LOG("p_sgx_get_quote_config returned NULL for p_pck_cert_config.\n");
            goto CLEANUP;
        }
        if (p_pck_cert_config->version != SGX_QL_CONFIG_VERSION_1) {
            SE_PROD_LOG("p_sgx_get_quote_config returned incompatible pck_cert_config version.\n");
            ret_val = TEE_ATT_NO_PLATFORM_CERT_DATA;
            goto CLEANUP;
        }
        if (0 != memcpy_s(p_cert_cpu_svn, sizeof(*p_cert_cpu_svn), &p_pck_cert_config->cert_cpu_svn, sizeof(p_pck_cert_config->cert_cpu_svn))) {
            ret_val = TEE_ATT_ERROR_UNEXPECTED;
            goto CLEANUP;
        }
        *p_cert_pce_isv_svn = p_pck_cert_config->cert_pce_isv_svn;
        if (NULL == p_cert_data) {
            // The caller only needs the TCBm and/or the required buffer size.
            // Return the required buffer size.
            *p_cert_data_size = p_pck_cert_config->cert_data_size;
        }
        else {
            // The caller wants the TCBm and the required buffer size.
            if (*p_cert_data_size < p_pck_cert_config->cert_data_size) {
                // The buffer passed in to this API is not large enouge to contain the provider library's returned cert data.
                // This shouldn't happen since the passed in value should be the result of calling this function
                // with the inputted p_cert_data equal to NULL just befor this caller.
                SE_PROD_LOG("sgx_ql_get_quote_config returned a cert_data_size too large to fit in inputted buffer.\n");
                ret_val = TEE_ATT_ERROR_INVALID_PARAMETER;
                goto CLEANUP;
            }
            if (NULL == p_pck_cert_config->p_cert_data) {
                SE_PROD_LOG("sgx_ql_get_quote_config returned NULL for p_cert_data.\n");
                ret_val = TEE_ATT_NO_PLATFORM_CERT_DATA;
                goto CLEANUP;
            }
            // Copy the returned cert data
            if (0 != memcpy_s(p_cert_data, *p_cert_data_size, p_pck_cert_config->p_cert_data, p_pck_cert_config->cert_data_size)) {
                ret_val = TEE_ATT_ERROR_UNEXPECTED;
                goto CLEANUP;
            }
            // Return the number of bytes copied.
            *p_cert_data_size = p_pck_cert_config->cert_data_size;
        }

    }
CLEANUP:
    if (NULL != p_sgx_free_quote_config) {
        if (NULL != p_pck_cert_config) {
            p_sgx_free_quote_config(p_pck_cert_config);
        }
    }
    return(ret_val);
}

/**
 *
 * @param q_file_name
 * @param p_file_path
 * @param buf_size
 *
 * @return
 */
bool tee_att_config_t::get_qe_path(tee_att_ae_type_t type,
                        TCHAR *p_file_path,
                        size_t buf_size)
{
    if(!p_file_path || buf_size == 0) {
        return false;
    }
    const TCHAR* context_path, *p_file_name;
    switch (type)
    {
    case TEE_ATT_TDQE:
        context_path = tdqe_path;
        p_file_name = TDQE_ENCLAVE_NAME;
        break;
    case TEE_ATT_QPL:
        context_path = qpl_path;
        p_file_name = TEE_ATT_QUOTE_CONFIG_LIB_FILE_NAME;
        break;
    case TEE_ATT_IDE:
        context_path = ide_path;
        p_file_name = ID_ENCLAVE_NAME;

        break;
    default:
        return false;
    }
#ifndef _MSC_VER
    Dl_info dl_info;
    if(*context_path)
    {
        size_t len = strnlen(context_path, MAX_PATH);
        if( len > buf_size -1) {
            return false;
        }
        strncpy(p_file_path, context_path, len);
        p_file_path[len] = '\0';  //null terminate the string
        return true;
    }
    else if(0 != dladdr(__builtin_return_address(0), &dl_info) &&
        NULL != dl_info.dli_fname)
    {
        if(strnlen(dl_info.dli_fname,buf_size)>=buf_size) {
            return false;
        }
        (void)strncpy(p_file_path,dl_info.dli_fname,buf_size);
        p_file_path[buf_size - 1] = '\0';  //null terminate the string
    }
    else //not a dynamic executable
    {
        ssize_t i = readlink( "/proc/self/exe", p_file_path, buf_size );
        if (i == -1)
            return false;
        p_file_path[i] = '\0';
    }

    char* p_last_slash = strrchr(p_file_path, '/' );
    if ( p_last_slash != NULL ) {
        p_last_slash++;   //increment beyond the last slash
        *p_last_slash = '\0';  //null terminate the string
    }
    else {
        p_file_path[0] = '\0';
    }

    if(strnlen(p_file_path,buf_size)+strnlen(p_file_name,buf_size)+sizeof(char)>buf_size) {
        return false;
    }
    (void)strncat(p_file_path,p_file_name, strnlen(p_file_name,buf_size));
#else
    HMODULE hModule = NULL;
    if (*context_path)
    {
        if (_tcsncpy_s(p_file_path, buf_size - 1, context_path, MAX_PATH))
            return false;
        p_file_path[buf_size - 1] = '\0';  //null terminate the string
        return true;
    }
#ifndef AESM_ECDSA_BUNDLE
    if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, _T(__FUNCTION__), &hModule))
        return false;
#endif
    DWORD path_length = GetModuleFileName(hModule, p_file_path, static_cast<DWORD>(buf_size));
    if (path_length == 0)
        return false;
    if (path_length == buf_size)
        return false;

    TCHAR *p_last_slash = _tcsrchr(p_file_path, _T('\\'));
    if (p_last_slash != NULL)
    {
        p_last_slash++;
        *p_last_slash = _T('\0');
    }
    else
        return false;
    if (_tcsnlen(p_file_name, MAX_PATH) + _tcsnlen(p_file_path, MAX_PATH) + sizeof(TCHAR) > buf_size)
        return false;
    if (_tcscat_s(p_file_path, buf_size, p_file_name))
        return false;
#endif
    return true;
}


/**
 * @return TEE_ATT_SUCCESS
 * @return TEE_ATT_ENCLAVE_LOAD_ERROR
 * @return TEE_ATT_ERROR_UNEXPECTED
 * @return TEE_ATT_OUT_OF_EPC
 * @return SGX_ERROR_ENCLAVE_FILE_ACCESS  The QE file cannot be found or accessed.
 * @return SGX_ERROR_OUT_OF_MEMORY
 * @return SGX_ERROR_INVALID_ENCLAVE Enclave file parser failed.
 * @return SGX_ERROR_UNDEFINED_SYMBOL Enclave not statically built.
 * @return SGX_ERROR_MODE_INCOMPATIBLE Enclave linked with the incorrect tRTS library (simulation)
 * @return SGX_ERROR_PCL_NOT_ENCRYPTED Invalid protected code loader state.
 * @return SGX_ERROR_PCL_ENCRYPTED Invalid protected code loader state.
 * @return SGX_ERROR_INVALID_METADATA Enclave meta data is invalid.
 * @return SGX_ERROR_ENCLAVE_LOST Power transition caused the enclave to be unloaded.
 * @return SGX_ERROR_MEMORY_MAP_CONFLICT Error loading the enclave.
 * @return SGX_ERROR_INVALID_VERSION Metadata version is unsupported.
 * @return SGX_ERROR_NO_DEVICE SGX not enabled on platform.
 * @return SGX_ERROR_INVALID_ATTRIBUTE Invalid encave attribute.
 * @return SGX_ERROR_NDEBUG_ENCLAVE Enlcave properties disallows launching in debug mode.
 * @return SGX_ERROR_INVALID_MISC Invalid Misc. attribute setting.
 * @return SGX_ERROR_UNEXPECTED
 * @return SE_ERROR_INVALID_LAUNCH_TOKEN A debug LE is trying to launch a production QE.
 * @return SGX_ERROR_INVALID_SIGNATURE
 * @return SE_ERROR_INVALID_MEASUREMENT
 * @return SGX_ERROR_DEVICE_BUSY
 * @return SE_ERROR_INVALID_ISVSVNLE
 * @return SGX_ERROR_INVALID_ENCLAVE_ID
 */

tee_att_error_t tee_att_config_t::load_qe(bool *is_fresh_loaded) {
    tee_att_error_t ret_val = TEE_ATT_SUCCESS;
    sgx_status_t sgx_status = SGX_SUCCESS;
    int launch_token_updated = 0;
    TCHAR qe_enclave_path[MAX_PATH] = _T("");


    int rc = se_mutex_lock(&m_enclave_load_mutex);
    if (0 == rc) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to lock mutex\n");
        return TEE_ATT_ENCLAVE_LOAD_ERROR;
    }

    if (is_fresh_loaded) {
        *is_fresh_loaded =false;
    }

    // Load the TDQE
    if (m_eid == 0) {
        if (!get_qe_path(TEE_ATT_TDQE, qe_enclave_path, MAX_PATH)) {
            SE_TRACE(SE_TRACE_ERROR, "Couldn't find QE file.\n");
            ret_val = TEE_ATT_ENCLAVE_LOAD_ERROR;
            goto CLEANUP;
        }
        SE_TRACE(SE_TRACE_DEBUG, "Call sgx_create_enclave for QE. %s\n", qe_enclave_path);
        sgx_status = sgx_create_enclave(qe_enclave_path,
                                        0,
                                        &m_launch_token,
                                        &launch_token_updated,
                                        &m_eid,
                                        &m_attributes);
        if (SGX_SUCCESS != sgx_status) {
            SE_PROD_LOG("Error, call sgx_create_enclave QE fail [%s], SGXError:%04x.\n", __FUNCTION__, sgx_status);
            if (sgx_status == SGX_ERROR_OUT_OF_EPC) {
                ret_val = TEE_ATT_OUT_OF_EPC;
            }
            else {
                ret_val = (tee_att_error_t)sgx_status;
            }
            goto CLEANUP;
        }

        if (is_fresh_loaded) {
            *is_fresh_loaded = true;
        }

    } else {
        SE_TRACE(SE_TRACE_DEBUG, "QE already loaded. %d\n", m_eid);
    }

    CLEANUP:
    rc = se_mutex_unlock(&m_enclave_load_mutex);
    if (0 == rc) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to unlock mutex.\n");
        ret_val = TEE_ATT_ERROR_UNEXPECTED;
    }

    return ret_val;
    }

/**
 *
 * @return
 */
void tee_att_config_t::unload_qe()
{

    int rc = se_mutex_lock(&m_enclave_load_mutex);
    if (0 == rc) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to lock mutex\n");
        return;
    }

    // Unload the QE enclave
    if (0 != m_eid) {
        SE_TRACE(SE_TRACE_DEBUG, "Unload QE enclave 0X%lX\n", m_eid);
        sgx_destroy_enclave(m_eid);
        m_eid = 0;
    }

    rc = se_mutex_unlock(&m_enclave_load_mutex);
    if (0 == rc) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to unlock mutex\n");
    }
}


tee_att_error_t tee_att_config_t::load_id_enclave(sgx_enclave_id_t* p_id_enclave_eid)
{
    tee_att_error_t ret_val = TEE_ATT_SUCCESS;
    sgx_status_t sgx_status = SGX_SUCCESS;
    int launch_token_updated = 0;
    TCHAR id_enclave_path[MAX_PATH] = _T("");

    sgx_launch_token_t launch_token = { 0 };

    int rc = se_mutex_lock(&m_enclave_load_mutex);
    if (0 == rc) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to lock mutex\n");
        return TEE_ATT_ENCLAVE_LOAD_ERROR;
    }

    // Load the ID ENCLAVE
    if (!get_qe_path(TEE_ATT_IDE, id_enclave_path, MAX_PATH)) {
        SE_TRACE(SE_TRACE_ERROR, "Couldn't find ID_ENCLAVE file.\n");
        ret_val = TEE_ATT_ENCLAVE_LOAD_ERROR;
        goto CLEANUP;
    }
    SE_TRACE(SE_TRACE_DEBUG, "Call sgx_create_enclave for ID_ENCLAVE. %s\n", id_enclave_path);
    sgx_status = sgx_create_enclave(id_enclave_path,
        0,
        &launch_token,
        &launch_token_updated,
        p_id_enclave_eid,
        NULL);
    if (SGX_SUCCESS != sgx_status) {
        SE_TRACE(SE_TRACE_ERROR, "Error, call sgx_create_enclave ID_ENCLAVE fail [%s], SGXError:%04x.\n", __FUNCTION__, sgx_status);
        SE_TRACE(SE_TRACE_ERROR, "Failed to load enclave.\n");
        if (sgx_status == SGX_ERROR_OUT_OF_EPC) {
            ret_val = TEE_ATT_OUT_OF_EPC;
        }
        else {
            ret_val = (tee_att_error_t)sgx_status;
        }
        goto CLEANUP;
    }
CLEANUP:
    rc = se_mutex_unlock(&m_enclave_load_mutex);
    if (0 == rc) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to unlock mutex.\n");
        ret_val = TEE_ATT_ERROR_UNEXPECTED;
    }

    return ret_val;
}

tee_att_error_t tee_att_config_t::load_id_enclave_get_id(sgx_key_128bit_t* p_id)
{
    tee_att_error_t ret_val = TEE_ATT_SUCCESS;
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_status_t ecall_ret = SGX_SUCCESS;
    sgx_enclave_id_t id_enclave_eid = 0;
    ret_val = load_id_enclave(&id_enclave_eid);
    if (ret_val != TEE_ATT_SUCCESS)
    {
        return ret_val;
    }
    sgx_status = ide_get_id(id_enclave_eid, &ecall_ret, p_id);
    if (SGX_SUCCESS != sgx_status) {
        SE_PROD_LOG("Failed call into the ID_ENCLAVE. 0x%04x.\n", sgx_status);
        ret_val = (tee_att_error_t)sgx_status;
        goto CLEANUP;
    }

    if (SGX_SUCCESS != ecall_ret) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to get QE_ID. 0x%04x.\n", ecall_ret);
        ret_val = (tee_att_error_t)ecall_ret;
        goto CLEANUP;
    }
    SE_TRACE(SE_TRACE_DEBUG, "TDQE_ID:\n");
    PRINT_BYTE_ARRAY(SE_TRACE_DEBUG, p_id, sizeof(*p_id));

CLEANUP:
    if (0 != id_enclave_eid) {
        sgx_destroy_enclave(id_enclave_eid);
    }

    return ret_val;
}

/* This function output encrypted PPID which is encrypted with backend server's pub key
 *
 * note: this function is called in lock area of global ecdsa blob mutex
 */
tee_att_error_t tee_att_config_t::getencryptedppid(sgx_target_info_t& pce_target_info, uint8_t *p_buf, uint32_t buf_size)
{
    tdqe_error_t tdqe_error = TDQE_ERROR_UNEXPECTED;
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_pce_error_t pce_error;
    sgx_report_t tdqe_report;
    uint32_t enc_key_size = REF_RSA_OAEP_3072_MOD_SIZE + REF_RSA_OAEP_3072_EXP_SIZE;
    uint8_t enc_public_key[REF_RSA_OAEP_3072_MOD_SIZE + REF_RSA_OAEP_3072_EXP_SIZE];
    uint8_t encrypted_ppid[REF_RSA_OAEP_3072_MOD_SIZE];
    uint32_t encrypted_ppid_ret_size;
    sgx_pce_info_t pce_info;
    uint8_t signature_scheme;

    if (!p_buf || buf_size < REF_RSA_OAEP_3072_MOD_SIZE)
        return TEE_ATT_ERROR_INVALID_PARAMETER;

    if (m_pencryptedppid)
    {
        memcpy_s(p_buf, buf_size, m_pencryptedppid, REF_RSA_OAEP_3072_MOD_SIZE);
        return TEE_ATT_SUCCESS;
    }

    sgx_status = get_pce_encrypt_key(m_eid,
                                             (uint32_t*)&tdqe_error,
                                             &pce_target_info,
                                             &tdqe_report,
                                             PCE_ALG_RSA_OAEP_3072,
                                             PPID_RSA3072_ENCRYPTED,
                                             enc_key_size,
                                             enc_public_key);
    if (SGX_SUCCESS != sgx_status) {
        SE_TRACE(SE_TRACE_ERROR, "Failed call into the TDQE. 0x%04x.\n", sgx_status);
        return (tee_att_error_t)sgx_status;
    }

    if (TDQE_SUCCESS != tdqe_error) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to generated PCE encryption key.\n");
        return (tee_att_error_t)tdqe_error;
    }

    pce_error = sgx_get_pce_info(&tdqe_report,
                                        enc_public_key,
                                        enc_key_size,
                                        PCE_ALG_RSA_OAEP_3072,
                                        encrypted_ppid,
                                        REF_RSA_OAEP_3072_MOD_SIZE,
                                        &encrypted_ppid_ret_size,
                                        &pce_info.pce_isv_svn,
                                        &pce_info.pce_id,
                                        &signature_scheme);
    if (SGX_PCE_SUCCESS != pce_error) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to get PCE info, 0x%04x.\n", pce_error);
        return translate_pce_errors(pce_error);
    }

    if (signature_scheme != PCE_NIST_P256_ECDSA_SHA256) {
        SE_TRACE(SE_TRACE_ERROR, "PCE returned incorrect signature scheme.\n");
        return TEE_ATT_ERROR_INVALID_PCE_SIG_SCHEME;
    }

    if (encrypted_ppid_ret_size != REF_RSA_OAEP_3072_MOD_SIZE) {
        SE_TRACE(SE_TRACE_ERROR, "PCE returned unexpected returned encrypted PPID size.\n");
        return TEE_ATT_ERROR_UNEXPECTED;
    }

    m_pencryptedppid = (uint8_t *)malloc(sizeof(uint8_t) * REF_RSA_OAEP_3072_MOD_SIZE);
    if (!m_pencryptedppid) {
        SE_TRACE(SE_TRACE_ERROR, "Fail to allocate memory.\n");
        return TEE_ATT_ERROR_OUT_OF_MEMORY;
    }

    if (0 != memcpy_s(m_pencryptedppid, REF_RSA_OAEP_3072_MOD_SIZE, encrypted_ppid, REF_RSA_OAEP_3072_MOD_SIZE) ||
        0 != memcpy_s(p_buf, buf_size, m_pencryptedppid, REF_RSA_OAEP_3072_MOD_SIZE) ||
        0 != memcpy_s(&m_pce_info, sizeof(m_pce_info), &pce_info, sizeof (pce_info))) {
        SE_TRACE(SE_TRACE_ERROR, "Fail to copy memory.\n");
        return TEE_ATT_ERROR_UNEXPECTED;
    }

    return  TEE_ATT_SUCCESS;
}

/**
 * This function is used to write the ECDSA data blob.
 *
 * @param p_buf    Points to the buffer to be written to disk.  Must not be NULL.
 * @param buf_size Size in bytes pointed to by p_buf.  Must be no larger than MAX_PATH.
 * @param p_label String of the label for the data to be stored.  Must not be NULL.
 *
 * @return TEE_ATT_PLATFORM_LIB_UNAVAILABLE
 * @return TEE_ATT_ERROR_UNEXPECTED
 * @return TEE_ATT_ERROR_INVALID_PARAMETER
 * @return TEE_ATT_FILE_ACCESS_ERROR
 * @return TEE_ATT_SUCCESS
 */
tee_att_error_t tee_att_config_t::write_persistent_data(const uint8_t *p_buf,
                                            uint32_t buf_size,
                                            const char *p_label)
{
    tee_att_error_t ret_val = TEE_ATT_PLATFORM_LIB_UNAVAILABLE;
    sgx_write_persistent_data_func_t p_sgx_qe_write_persistent_data;
    #ifndef _MSC_VER
    void *handle;
    char *error;
    #else
    HINSTANCE handle;
    #endif

    if((NULL == p_buf) ||
       (0 == buf_size)||
       (NULL == p_label)) {
        return(TEE_ATT_ERROR_INVALID_PARAMETER);
    }

    handle = get_qpl_handle();
#ifndef _MSC_VER
    if (handle) {
        p_sgx_qe_write_persistent_data = (sgx_write_persistent_data_func_t)dlsym(handle, "sgx_ql_write_persistent_data");
        if ((error = dlerror()) == NULL &&
            NULL != p_sgx_qe_write_persistent_data) {
            SE_TRACE(SE_TRACE_DEBUG, "Found the sgx_ql_write_persistent_data API.\n");
            ret_val = p_sgx_qe_write_persistent_data(p_buf,
                                                        buf_size,
                                                        p_label);
            if (TEE_ATT_SUCCESS != ret_val) {
                SE_PROD_LOG("Error returned from the sgx_ql_write_persistent_data API. 0x%04x\n", ret_val);
            }
        } else {
            SE_TRACE(SE_TRACE_WARNING, "Couldn't find 'sgx_ql_write_persistent_data()' in the platform library. %s\n", dlerror());
        }
    } else {
        SE_PROD_LOG("Couldn't find the platform library. %s\n", dlerror());
    }
#else
    if (handle != NULL) {
        p_sgx_qe_write_persistent_data = (sgx_write_persistent_data_func_t)GetProcAddress(handle, "sgx_ql_write_persistent_data");
        if (NULL != p_sgx_qe_write_persistent_data) {
            SE_TRACE(SE_TRACE_DEBUG, "Found the sgx_ql_write_persistent_data API.\n");
            ret_val = p_sgx_qe_write_persistent_data(p_buf,
                buf_size,
                p_label);
            if (TEE_ATT_SUCCESS != ret_val) {
                SE_TRACE(SE_TRACE_ERROR, "Error returned from the sgx_ql_write_persistent_data API. 0x%04x\n", ret_val);
            }
        }
        else {
            SE_TRACE(SE_TRACE_WARNING, "Couldn't find 'sgx_ql_write_persistent_data()' in the platform library. %s\n");
        }
    }
    else {
        SE_TRACE(SE_TRACE_DEBUG, "Couldn't find the platform library. %s\n");
    }
#endif

    //CLEANUP:
    return(ret_val);
}

/**
 * This function is used to read the ECDSA data blob.
 *
 * @param p_buf    Points to the buffer to be written to disk.  Must not be NULL.
 * @param p_buf_size Size in bytes pointed to by p_buf.  Must not be NULL.
 * @param p_label String of the label for the data to be stored.  Must not be NULL.
 *
 * @return TEE_ATT_SUCCESS
 * @return TEE_ATT_PLATFORM_LIB_UNAVAILABLE
 * @return TEE_ATT_ERROR_UNEXPECTED
 * @return TEE_ATT_ERROR_INVALID_PARAMETER
 * @return TEE_ATT_FILE_ACCESS_ERROR
 */
tee_att_error_t tee_att_config_t::read_persistent_data(uint8_t *p_buf,
                                           uint32_t *p_buf_size,
                                           const char *p_label)
{
    tee_att_error_t ret_val = TEE_ATT_PLATFORM_LIB_UNAVAILABLE;
    sgx_read_persistent_data_func_t p_sgx_qe_read_persistent_data;

    #ifndef _MSC_VER
    void *handle;
    char *error;
    #else
    HINSTANCE handle;
    #endif

    if((NULL == p_buf) ||
       (NULL == p_buf_size)||
       (NULL == p_label)) {
        return(TEE_ATT_ERROR_INVALID_PARAMETER);
    }

    handle = get_qpl_handle();
#ifndef _MSC_VER
    if (handle) {
        p_sgx_qe_read_persistent_data = (sgx_read_persistent_data_func_t)dlsym(handle, "sgx_ql_read_persistent_data");
        if ((error = dlerror()) == NULL &&
            NULL != p_sgx_qe_read_persistent_data) {
            SE_TRACE(SE_TRACE_DEBUG, "Found the sgx_qe_read_persistent_data API.\n");
            ret_val = p_sgx_qe_read_persistent_data(p_buf,
                                                    p_buf_size,
                                                    p_label);
            if (TEE_ATT_SUCCESS != ret_val) {
                SE_PROD_LOG("Error returned from the sgx_ql_read_persistent_data API. 0x%04x\n", ret_val);
            }
        } else {
            SE_TRACE(SE_TRACE_WARNING, "Couldn't find 'sgx_ql_read_persistent_data()' in the platform library. %s\n", dlerror());
        }
    } else {
        SE_PROD_LOG("Couldn't find the platform library. %s\n", dlerror());
    }
    #else
    if (handle != NULL) {
        SE_TRACE(SE_TRACE_DEBUG, "Found the Quote's dependent library.\n");
        p_sgx_qe_read_persistent_data = (sgx_read_persistent_data_func_t)GetProcAddress(handle, "sgx_ql_read_persistent_data");
        if (NULL != p_sgx_qe_read_persistent_data) {
            SE_TRACE(SE_TRACE_DEBUG, "Found the sgx_ql_read_persistent_data API.\n");
            ret_val = p_sgx_qe_read_persistent_data(p_buf,
                                                    p_buf_size,
                                                    p_label);
            if (TEE_ATT_SUCCESS != ret_val) {
                SE_TRACE(SE_TRACE_ERROR, "Error returned from the sgx_ql_read_persistent_data API. 0x%04x\n", ret_val);
            }
        }
        else {
            SE_TRACE(SE_TRACE_WARNING, "Couldn't find 'sgx_ql_write_persistent_data()' in the platform library. %s\n");
        }
    }
    else {
        SE_TRACE(SE_TRACE_DEBUG, "Couldn't find the platform library. %s\n");
    }

    #endif

    //CLEANUP:
    return(ret_val);
}

/**
 *
 * @param p_ecdsa_blob
 * @param p_plaintext_data
 * @param p_encrypted_ppid
 * @param encrypted_ppid_size
 * @param certification_key_type
 *
 * @return TEE_ATT_SUCCESS
 * @return TEE_ATT_ERROR_INVALID_PARAMETER
 * @return errors from PCE translator from sgx_pce_sign_report()
 * @return ecall errors
 * @return errors from TDQE's store_cert_data()
 *
 */
tee_att_error_t tee_att_config_t::certify_key(uint8_t *p_ecdsa_blob,
                                  ref_plaintext_ecdsa_data_sdk_t* p_plaintext_data,
                                  uint8_t *p_encrypted_ppid,
                                  uint32_t encrypted_ppid_size,
                                  sgx_ql_cert_key_type_t certification_key_type)
{
    tee_att_error_t refqt_ret = TEE_ATT_ERROR_UNEXPECTED;
    sgx_status_t sgx_status = SGX_SUCCESS;
    tdqe_error_t tdqe_error = TDQE_ERROR_UNEXPECTED;
    sgx_pce_error_t pce_error;
    sgx_ec256_signature_t pce_sig;
    uint32_t sig_out_size;

    // Verify inputs
    if((NULL == p_ecdsa_blob) ||
       (NULL == p_plaintext_data) ||
       (0 == m_eid)) {
        return(TEE_ATT_ERROR_INVALID_PARAMETER);
    }

    if(NULL != p_encrypted_ppid) {
        if(encrypted_ppid_size != REF_RSA_OAEP_3072_MOD_SIZE) {
            return(TEE_ATT_ERROR_INVALID_PARAMETER);
        }
    }

    if (PPID_RSA3072_ENCRYPTED != certification_key_type) {
        return(TEE_ATT_ERROR_INVALID_PARAMETER);
    }

    SE_TRACE(SE_TRACE_DEBUG, "Certify Key.\n");
    // Set the TCB to the value you want to use when certifying the key.
    // For the reference, use the CPUSNV and PCEISVSVN that matches the test PCK.  CPUSVN = 00000000010100000000000000000000, PCE ISVSVN = 0000
    // For E3's, there will not be a PCK Cert for every CPUSVN+PCE ISVNSVN combination.  The platform will need to know which values to use.
    // For E5's, the PCK Cert can be requested on demand and use the CPUSVN+PCE ISVSVN of the current platform.
    //
    SE_TRACE(SE_TRACE_DEBUG, "pce_cert_psvn.cpusvn:\n");
    PRINT_BYTE_ARRAY(SE_TRACE_DEBUG, &p_plaintext_data->cert_cpu_svn, sizeof(p_plaintext_data->cert_cpu_svn));
    SE_TRACE(SE_TRACE_DEBUG, "\npce_cert_psvn.isv_svn = 0x%04x.\n", p_plaintext_data->cert_pce_info.pce_isv_svn);
    pce_error = sgx_pce_sign_report(&p_plaintext_data->cert_pce_info.pce_isv_svn,
                                    &p_plaintext_data->cert_cpu_svn,
                                    &p_plaintext_data->qe_report,
                                    (uint8_t*)&pce_sig,
                                    sizeof(pce_sig),
                                    &sig_out_size);
    if (SGX_PCE_SUCCESS != pce_error) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to certify the attestation key. PCE Error = 0x%04x.\n", pce_error);
        refqt_ret = translate_pce_errors(pce_error);
        goto CLEANUP;
    }

    // Update the signature data and the report that was signed.
    if(0 != memcpy_s(&p_plaintext_data->qe_report_cert_key_sig, sizeof(p_plaintext_data->qe_report_cert_key_sig), &pce_sig, sizeof(pce_sig))) {
        refqt_ret = TEE_ATT_ERROR_UNEXPECTED;
        goto CLEANUP;
    }
    // Update the ECDSA key blob with certification data
    SE_TRACE(SE_TRACE_DEBUG, "Update ECDSA blob with cert data.\n");
    sgx_status = store_cert_data(m_eid,
                                 (uint32_t*)&tdqe_error,
                                 p_plaintext_data,
                                 certification_key_type,
                                 p_encrypted_ppid,
                                 encrypted_ppid_size,
                                 p_ecdsa_blob,
                                 SGX_QL_TRUSTED_ECDSA_BLOB_SIZE_SDK);
    if (SGX_SUCCESS != sgx_status) {
        SE_TRACE(SE_TRACE_ERROR, "Failed call into the TDQE. 0x%04x\n", sgx_status);
        // /todo:  May want to retry on SGX_ERROR_ENCLAVE_LOST caused by power transition
        refqt_ret = (tee_att_error_t)sgx_status;
        goto CLEANUP;
    }
    if (TDQE_SUCCESS != tdqe_error) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to generate ECDSA blob. 0x%04x.\n", tdqe_error);
        refqt_ret = (tee_att_error_t)tdqe_error;
        goto CLEANUP;
    } else {
        SE_TRACE(SE_TRACE_DEBUG, "Certification done.  Store updated ECDSA blob to disk.\n");
        refqt_ret = write_persistent_data(p_ecdsa_blob,
                                          SGX_QL_TRUSTED_ECDSA_BLOB_SIZE_SDK,
                                          ECDSA_BLOB_LABEL);
        if (refqt_ret != TEE_ATT_SUCCESS) {
            // This should not be a critical failure but a warning.  The ECDSA key is still in memory.
            SE_TRACE(SE_TRACE_WARNING, "Warning, unable to store resealed ECDSA blob to persistent storage.\n");
            SE_TRACE(SE_TRACE_DEBUG, "File storage is not required for the QE_Library.  Library will use ECDSA Blob cached in memory.\n");
            refqt_ret = TEE_ATT_SUCCESS;
        }
    }

    CLEANUP:
    return(refqt_ret);
}


/**
 * This is the ECDSA-P256 specific init quote code.  The generic quote interfaces have been converted/reduced to the ECDSA specific inputs.
 * The method will generate a new key and certify it when needed.
 * /todo:  Add support to re-certify when the key exists but its certification is out of date.
 * /todo:  Add the ability to specify additional certification data such as the CPU_SVN and PCE_SVN information when requesting a PCE signature
 *         to support E3 platforms.
 *
 * @param certification_key_type
 * @param qe_target_info
 * @param refresh_att_key
 * @param pub_key_id
 *
 * @return TEE_ATT_SUCCESS
 * @return TEE_ATT_ERROR_INVALID_PARAMETER
 * @return SGX_PCE_INVALID_PARAMETER->TEE_ATT_ERROR_UNEXPECTED
 * @return SGX_PCE_INTERFACE_UNAVAILABLE->TEE_ATT_INTERFACE_UNAVAILABLE
 * @return SGX_PCE_OUT_OF_EPC->TEE_ATT_OUT_OF_EPC
 * @return Errors from load_qe()
 * @return Errors from failed ecall (need to handle at least ENCLAVE_LOST)
 * @return TDQE_ERROR_INVALID_PLATFORM
 * @return TDQE_ERROR_INVALID_PARAMETER
 * @return TDQE_ERROR_CRYPTO Error generating the PPID Encryption key.
 * @return TDQE_ERROR_UNEXPECTED
 * @return SGX_PCE_INVALID_REPORT QE.REPORT verification failed.->TEE_ATT_ERROR_UNEXPECTED
 * @return SGX_PCE_CRYPTO_ERROR QE.REPORT.ReportData hash compare failed.-> TEE_ATT_ERROR_UNEXPECTED
 * @return SGX_PCE_INVALID_PRIVILEGE QE doesn't have the prov bit set.-> TEE_ATT_ERROR_UNEXPECTED (for produciton
 *         release.
 * @return SGX_PCE_UNEXPECTED->TEE_ATT_ERROR_UNEXPECTED
 * @return TEE_ATT_ERROR_INVALID_PCE_SIG_SCHEME PCE used and unexpected/unsupported signature scheme.
 * @return TEE_ATT_ERROR_UNEXPECTED
 * @return TDQE_ERROR_ATT_KEY_GEN Error generated the attestaion key.
 * @return TDQE_ERROR_CRYPTO Error generating QE_ID.
 * @return TDQE_ERROR_OUT_OF_MEMORY
 * @return SGX_ERROR_UNEXPECTED (from Seal)
 * @return SGX_ERROR_INVALID_PARAMETER (from Seal)
 * @return SGX_ERROR_OUT_OF_MEMORY (create report)
 * @return TDQE_ERROR_CRYPTO Error decrypting PPID (only for cert_key_type = PPID_CLEARTEXT)
 * @return TDQE_ECDSABLOB_ERROR  (probably should be unexpected since the blob was either generated during this call
 *         or was already verified once.
 *
 */
tee_att_error_t tee_att_config_t::ecdsa_init_quote(sgx_ql_cert_key_type_t certification_key_type,
                                               sgx_target_info_t *p_qe_target_info,
                                               bool refresh_att_key,
                                               ref_sha256_hash_t *p_pub_key_id)
{
    tee_att_error_t refqt_ret = TEE_ATT_SUCCESS;
    sgx_status_t sgx_status = SGX_SUCCESS;
    tdqe_error_t tdqe_error = TDQE_ERROR_UNEXPECTED;
    uint8_t resealed = 0;
    ref_sha256_hash_t blob_ecdsa_id;
    sgx_target_info_t pce_target_info;
    sgx_isv_svn_t pce_isv_svn;
    //int enclave_lost_retry_time = 1;
    bool gen_new_key = false;
    sgx_psvn_t pce_cert_psvn;
    sgx_ql_pck_cert_id_t pck_cert_id;
    sgx_pce_error_t pce_error;
    sgx_report_body_t tdqe_report_body;
    uint32_t cert_data_size;
    sgx_sealed_data_t *p_sealed_ecdsa;
    ref_plaintext_ecdsa_data_sdk_t plaintext_data;
    ref_plaintext_ecdsa_data_sdk_t *p_seal_data_plain_text;
    uint8_t encrypted_ppid[REF_RSA_OAEP_3072_MOD_SIZE];
    int blob_mutex_rc = 0;
    bool is_fresh_loaded = false;

    // Verify inputs
    if (PPID_RSA3072_ENCRYPTED != certification_key_type) {
        SE_TRACE(SE_TRACE_ERROR, "Invalid certification key type.\n");
        return(TEE_ATT_ERROR_INVALID_PARAMETER);
    }

    if (NULL == p_qe_target_info) {
        SE_TRACE(SE_TRACE_ERROR, "Invalid qe target info.\n");
        return(TEE_ATT_ERROR_INVALID_PARAMETER);
    }

    // Get PCE Target Info
    SE_TRACE(SE_TRACE_DEBUG, "Call sgx_pce_get_target().\n");
    pce_error = sgx_pce_get_target(&pce_target_info, &pce_isv_svn);
    if (SGX_PCE_SUCCESS != pce_error) {
        SE_TRACE(SE_TRACE_ERROR, "Error, call sgx_pce_get_target [%s], pce_error:%04x.\n", __FUNCTION__, pce_error);
        refqt_ret = translate_pce_errors(pce_error);
        goto CLEANUP;
    }

    // Load the QE enclave
    SE_TRACE(SE_TRACE_DEBUG, "Call Load the QE.\n");
    refqt_ret = load_qe(&is_fresh_loaded);
    if (TEE_ATT_SUCCESS != refqt_ret)
    {
        goto CLEANUP;

    }

    if (is_fresh_loaded) {
        m_raw_pce_isvsvn = pce_isv_svn;
    }
    // Compose the target_info from the attributes returned by sgx_create_enclave and mr_enclave from qe report.
    memset(p_qe_target_info, 0, sizeof(sgx_target_info_t));
    if(0 != memcpy_s(&p_qe_target_info->attributes, sizeof(p_qe_target_info->attributes),
                     &m_attributes.secs_attr, sizeof(m_attributes.secs_attr))) {
        refqt_ret = TEE_ATT_ERROR_UNEXPECTED;
        goto CLEANUP;
    }
    if(0 != memcpy_s(&p_qe_target_info->misc_select, sizeof(p_qe_target_info->misc_select),
             &m_attributes.misc_select, sizeof(m_attributes.misc_select))) {
        refqt_ret = TEE_ATT_ERROR_UNEXPECTED;
        goto CLEANUP;
    }

    blob_mutex_rc = se_mutex_lock(&m_ecdsa_blob_mutex);
    if (0 == blob_mutex_rc) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to lock mutex\n");
        goto CLEANUP;
    }

    // If the caller has requested a new key, then force the generation of the new key regardless if the ECDSA blob exists.  Otherwise,
    // check to see if the ECDSA blob exists and is valid.
    do {
        if (true == refresh_att_key) {
            SE_TRACE(SE_TRACE_DEBUG, "Caller requests a new ECDSA Key.\n");
            gen_new_key = true;
            break;
        }
        uint32_t blob_size_read = sizeof(m_ecdsa_blob);
        // Get ECDSA Blob if exists
        SE_TRACE(SE_TRACE_DEBUG, "Read ECDSA blob.\n");
        refqt_ret = read_persistent_data((uint8_t*)m_ecdsa_blob,
                                         &blob_size_read,
                                         ECDSA_BLOB_LABEL);
        if (TEE_ATT_SUCCESS != refqt_ret) {
            // Ignore errors since persistent storage is not required.  Blob in memory may still be OK so continue to try to verify the cached blob.
            SE_TRACE(SE_TRACE_WARNING, "ECDSA Blob doesn't exist is persistent storage.  Try to use the cached version.\n");
            refqt_ret = TEE_ATT_SUCCESS;
        }
        else if (blob_size_read != sizeof(m_ecdsa_blob)) {
            // If the blob was successfully read from persistent storage, verify its size.
            SE_TRACE(SE_TRACE_ERROR, "Invalid ECDSA Blob file size. blob_size_read = %uld, sizeof(g_ecdsa_blob) = %uld.  Since caller requested use any key, generate a new key.\n", blob_size_read, (uint32_t)sizeof(m_ecdsa_blob));
            gen_new_key = true;
            break;
        }
        memset(&tdqe_report_body, 0, sizeof(tdqe_report_body));
        // Verify the cached blob.
        sgx_status = verify_blob(m_eid,
                                 (uint32_t*)&tdqe_error,
                                 (uint8_t*)m_ecdsa_blob,
                                 sizeof(m_ecdsa_blob),
                                 &resealed,
                                 &tdqe_report_body,
                                 sizeof(blob_ecdsa_id),
                                 (uint8_t*)&blob_ecdsa_id);
        if (SGX_SUCCESS != sgx_status) {
            SE_TRACE(SE_TRACE_ERROR, "Failed call into the TDQE. 0x%04x\n", sgx_status);
            ///todo:  May want to retry on SGX_ERROR_ENCLAVE_LOST caused by power transition or return a differnet error
            refqt_ret = (tee_att_error_t)sgx_status;
            goto CLEANUP;
        }
        if (TDQE_SUCCESS != tdqe_error) {
            SE_TRACE(SE_TRACE_DEBUG, "Invalid ECDSA Blob verificaton. 0x%04x, generate a new key.\n", tdqe_error);
            gen_new_key = true;
            break;
        }
        SE_TRACE(SE_TRACE_DEBUG, "Successfully verified ECDSA Blob.\n");
        p_qe_target_info->mr_enclave = tdqe_report_body.mr_enclave;
        if (resealed) {
            SE_TRACE(SE_TRACE_DEBUG, "ECDSA Blob was resealed. Store it disk.\n");
            refqt_ret = write_persistent_data((uint8_t *)m_ecdsa_blob,
                                              sizeof(m_ecdsa_blob),
                                              ECDSA_BLOB_LABEL);
            if (refqt_ret != TEE_ATT_SUCCESS) {
                // Don't need to error since the blob is still good in memory.
                /// todo:  What is the best way to notify the requester that the blob was not stored to disk?
                SE_TRACE(SE_TRACE_WARNING, "Warning, unable to store resealed ECDSA blob to persistent storage.\n");
                SE_TRACE(SE_TRACE_DEBUG, "File storage is not required for the QE_Library.  Library will use ECDSA Blob cached in memory.\n");
                refqt_ret = TEE_ATT_SUCCESS;
            }
            // Resealed means that uCode has been updated or TDQE has been updated. Re-generate AK
            SE_TRACE(SE_TRACE_DEBUG, "ECDSA Blob was resealed. It means the TDQE or CPUSVN has been upgraded.\n");
            gen_new_key = true;
            break;
        }

        p_sealed_ecdsa = reinterpret_cast<sgx_sealed_data_t *>(m_ecdsa_blob);
        p_seal_data_plain_text = reinterpret_cast<ref_plaintext_ecdsa_data_sdk_t *>(m_ecdsa_blob + sizeof(sgx_sealed_data_t) + p_sealed_ecdsa->plain_text_offset);
        // Check to see if the requested certification type matches the type in the blob.
        if(p_seal_data_plain_text->certification_key_type != certification_key_type) {
            SE_TRACE(SE_TRACE_ERROR, "Requested certificaiton_key_type doesn't match existing blob's type,  Gen and certify new key.\n");
            gen_new_key = true;
            break;
        }
        //QE's TCB has increased, (a decrease would cause a blob verification failure) then catch it here and generate a
        //new key
        if((tdqe_report_body.isv_svn > p_seal_data_plain_text->cert_qe_isv_svn) ||
           (0 != memcmp(&p_seal_data_plain_text->raw_cpu_svn, &tdqe_report_body.cpu_svn, sizeof(p_seal_data_plain_text->raw_cpu_svn)))) {
            SE_TRACE(SE_TRACE_ERROR, "Platform TCB has increased, gen and certify new key.\n");
            gen_new_key = true;
            break;
        }
        // PCE's raw isvsvn changed, catch it here and generate a new key
        if (m_raw_pce_isvsvn != p_seal_data_plain_text->raw_pce_info.pce_isv_svn) {
            SE_TRACE(SE_TRACE_ERROR, "PCE's raw isvsvn changed, gen and certify new key.\n");
            gen_new_key = true;
            break;
        }
        ///todo: Probably don't need this check.  PCE target info changes shouldn't require re-certification unless there is OwnerID changes.
        //but is safe since it will just uneccessarily cause key regeneration and recertificaiton.
        if(0 != memcmp(&p_seal_data_plain_text->pce_target_info, &pce_target_info, sizeof(p_seal_data_plain_text->pce_target_info))) {
            SE_TRACE(SE_TRACE_DEBUG, "Recertification is not available since PCE TargetInfo changed. Gen and certify new key.\n");
            gen_new_key = true;
            break;
        }
        if(0 != memcpy_s(p_pub_key_id, sizeof(*p_pub_key_id), &blob_ecdsa_id, sizeof(blob_ecdsa_id))) {
            refqt_ret = TEE_ATT_ERROR_UNEXPECTED;
            goto CLEANUP;
        }
        SE_TRACE(SE_TRACE_DEBUG, "Using ECDSA_ID from ECDSA Blob.  ECDSA_ID:\n");
        PRINT_BYTE_ARRAY(SE_TRACE_DEBUG, (uint8_t *)&blob_ecdsa_id, sizeof(blob_ecdsa_id));
        SE_TRACE(SE_TRACE_DEBUG, "\n");

        if (TEE_ATT_SUCCESS != (refqt_ret = getencryptedppid(pce_target_info, encrypted_ppid, REF_RSA_OAEP_3072_MOD_SIZE))){
            SE_TRACE(SE_TRACE_DEBUG, "Fail to retrieve encrypted PPID.\n");
            goto CLEANUP;
        }

        if (NULL == m_qe_id)
        {
            m_qe_id = (sgx_key_128bit_t*)malloc(sizeof(sgx_key_128bit_t));
            if (!m_qe_id) {
                SE_TRACE(SE_TRACE_ERROR, "Fail to allocate memory.\n");
                refqt_ret = TEE_ATT_ERROR_OUT_OF_MEMORY;
                goto CLEANUP;
            }

            refqt_ret = load_id_enclave_get_id(m_qe_id);
            if (TEE_ATT_SUCCESS != refqt_ret) {
                goto CLEANUP;
            }
        }

        // Determine if the raw-TCB has changed since the blob was last generated or the platform library
        // has a new TCBm. If the raw-TCB was downgraded, the ECDSA blob will not be accessible and fail
        // above.
        // For key recertification, the attestation owner doesn't need to generate a new attestation key but
        // it does need the attestation key to get recertified by the PCE.  This can happen due to a TCB
        // Recovery that requires the att key to be certified due to a higher PCE ISVSVN.  If the CPUSVN changes
        // both a new attestation key will be generated and it will get recertified. Recertification without a new
        // attestation key can also happen when the resulting TCBm from the call to sgx_get_quote_config() differs from
        // the value used to certify existing attestation key.

        // Get the TCB the PCE should use to ceritfy the attestaion key. Find and call the platform software's
        // sgx_ql_get_quote_config(). If it is not available or the API returns TEE_ATT_NO_PLATFORM_CERT_DATA, then use
        // the platform's raw TCB to certify the key.
        cert_data_size = 0;
        pck_cert_id.p_qe3_id = (uint8_t*)m_qe_id;
        pck_cert_id.qe3_id_size = sizeof(*m_qe_id);
        pck_cert_id.p_platform_cpu_svn = &p_seal_data_plain_text->cert_cpu_svn;
        pck_cert_id.p_platform_pce_isv_svn = &p_seal_data_plain_text->cert_pce_info.pce_isv_svn;
        pck_cert_id.p_encrypted_ppid = encrypted_ppid;
        pck_cert_id.encrypted_ppid_size = REF_RSA_OAEP_3072_MOD_SIZE;
        pck_cert_id.crypto_suite = PCE_ALG_RSA_OAEP_3072;
        pck_cert_id.pce_id = p_seal_data_plain_text->cert_pce_info.pce_id;
        refqt_ret = get_platform_quote_cert_data(&pck_cert_id,
                                                 &pce_cert_psvn.cpu_svn,
                                                 &pce_cert_psvn.isv_svn,
                                                 &cert_data_size,
                                                 NULL);
        if (refqt_ret != TEE_ATT_SUCCESS) {
            if (refqt_ret != TEE_ATT_PLATFORM_LIB_UNAVAILABLE) {
                // The dependent library was found but it returned an error
                goto CLEANUP;
            }
            refqt_ret = TEE_ATT_SUCCESS;
            if(pce_isv_svn > p_seal_data_plain_text->cert_pce_info.pce_isv_svn) {
                SE_TRACE(SE_TRACE_DEBUG, "Using raw-PCE_ISVSVN to certify the key and it has increased. Recertify.\n");

                // Use the raw TCB of the platform and the EncPPID certification type
                pce_cert_psvn.cpu_svn = tdqe_report_body.cpu_svn;
                pce_cert_psvn.isv_svn = pce_isv_svn;
                // Set up the certification data to update the blob with.
                memset(&plaintext_data, 0, sizeof(plaintext_data));
                if(0 != memcpy_s(&plaintext_data.cert_cpu_svn, sizeof(plaintext_data.cert_cpu_svn),
                                 &pce_cert_psvn.cpu_svn, sizeof(pce_cert_psvn.cpu_svn))) {
                    refqt_ret = TEE_ATT_ERROR_UNEXPECTED;
                    goto CLEANUP;
                }
                plaintext_data.cert_pce_info.pce_isv_svn = pce_cert_psvn.isv_svn;
                plaintext_data.cert_pce_info.pce_id = p_seal_data_plain_text->cert_pce_info.pce_id;
                if(0 != memcpy_s(&plaintext_data.raw_cpu_svn, sizeof(plaintext_data.raw_cpu_svn),
                                 &tdqe_report_body.cpu_svn, sizeof(tdqe_report_body.cpu_svn))) {
                    refqt_ret = TEE_ATT_ERROR_UNEXPECTED;
                    goto CLEANUP;
                }
                plaintext_data.raw_pce_info.pce_isv_svn = pce_isv_svn;
                plaintext_data.raw_pce_info.pce_id = p_seal_data_plain_text->cert_pce_info.pce_id;
                // For recertification, pull out out the certification data from the blob that doesn't need to change.
                if(0 != memcpy_s(&plaintext_data.qe_report, sizeof(plaintext_data.qe_report),
                                 &p_seal_data_plain_text->qe_report, sizeof(p_seal_data_plain_text->qe_report))) {
                    refqt_ret = TEE_ATT_ERROR_UNEXPECTED;
                    goto CLEANUP;
                }
                if (0 != memcpy_s(&plaintext_data.qe_id, sizeof(plaintext_data.qe_id),
                    m_qe_id, sizeof(*m_qe_id))) {
                    refqt_ret = TEE_ATT_ERROR_UNEXPECTED;
                    goto CLEANUP;
                }
                plaintext_data.signature_scheme = p_seal_data_plain_text->signature_scheme;  ///todo: Not likely that the signature scheme changed but may want to re-get from PCE. It is just more involved.
                if(0 != memcpy_s(&plaintext_data.pce_target_info, sizeof(plaintext_data.pce_target_info),
                                 &pce_target_info, sizeof(pce_target_info))) {
                    refqt_ret = TEE_ATT_ERROR_UNEXPECTED;
                    goto CLEANUP;
                }
                plaintext_data.certification_key_type = certification_key_type;  //Cert key request it checked if it changed above.  If changed, recertification is not allowed.
                refqt_ret = certify_key(m_ecdsa_blob,
                                        &plaintext_data,
                                        NULL,
                                        0,
                                        certification_key_type);
            }
        }
        else {
            // Check if the returned certification TCB is different than the TCB used to certify the key in the
            // ECDSA blob. If it hasn't changed then continue to use the cert data in the blob.  Otherwise, need to
            // do recertify using the new data.
            if((pce_cert_psvn.isv_svn != p_seal_data_plain_text->cert_pce_info.pce_isv_svn) ||
               (0 != memcmp(&pce_cert_psvn.cpu_svn, &p_seal_data_plain_text->cert_cpu_svn, sizeof(pce_cert_psvn.cpu_svn))))
            {
                SE_TRACE(SE_TRACE_DEBUG, "The Cert TCB value returned by the platform library is different than the value used to certify the key.  Recertify.\n");

                // Set up the certification data to update the blob with.
                memset(&plaintext_data, 0, sizeof(plaintext_data));
                if(0 != memcpy_s(&plaintext_data.cert_cpu_svn, sizeof(plaintext_data.cert_cpu_svn),
                                 &pce_cert_psvn.cpu_svn, sizeof(pce_cert_psvn.cpu_svn))) {
                    refqt_ret = TEE_ATT_ERROR_UNEXPECTED;
                    goto CLEANUP;
                }
                plaintext_data.cert_pce_info.pce_isv_svn = pce_cert_psvn.isv_svn;
                plaintext_data.cert_pce_info.pce_id = p_seal_data_plain_text->cert_pce_info.pce_id;
                if(0 != memcpy_s(&plaintext_data.raw_cpu_svn, sizeof(plaintext_data.raw_cpu_svn),
                                 &tdqe_report_body.cpu_svn, sizeof(tdqe_report_body.cpu_svn))) {
                    refqt_ret = TEE_ATT_ERROR_UNEXPECTED;
                    goto CLEANUP;
                }
                plaintext_data.raw_pce_info.pce_isv_svn = pce_isv_svn;
                plaintext_data.raw_pce_info.pce_id = p_seal_data_plain_text->cert_pce_info.pce_id;
                // For recertification, pull out out the certification data from the blob that doesn't need to change.
                if(0 != memcpy_s(&plaintext_data.qe_report, sizeof(plaintext_data.qe_report),
                                 &p_seal_data_plain_text->qe_report, sizeof(p_seal_data_plain_text->qe_report))){
                    refqt_ret = TEE_ATT_ERROR_UNEXPECTED;
                    goto CLEANUP;
                }
                if (0 != memcpy_s(&plaintext_data.qe_id, sizeof(plaintext_data.qe_id),
                    m_qe_id, sizeof(*m_qe_id))) {
                    refqt_ret = TEE_ATT_ERROR_UNEXPECTED;
                    goto CLEANUP;
                }
                plaintext_data.signature_scheme = p_seal_data_plain_text->signature_scheme;  ///todo: Not likely that the signature scheme changed but may want to re-get from PCE. It is just more involved.
                if(0 != memcpy_s(&plaintext_data.pce_target_info, sizeof(plaintext_data.pce_target_info),
                                 &pce_target_info, sizeof(pce_target_info))) {
                    refqt_ret = TEE_ATT_ERROR_UNEXPECTED;
                    goto CLEANUP;
                }
                plaintext_data.certification_key_type = certification_key_type;  //Cert key request it checked if it changed above.  If changed, recertification is not allowed.
                refqt_ret = certify_key(m_ecdsa_blob,
                                        &plaintext_data,
                                        NULL,
                                        0,
                                        certification_key_type);
            }
        }
    } while (0);

    if (true == gen_new_key) {
        sgx_report_t tdqe_report;

        // Authentication data is added to by the QE owner and will be 'signed' by the certification key.  It's use is dependent of the owner.
        // Just use a fixed value for the reference.
        uint8_t authentication_data[REF_ECDSDA_AUTHENTICATION_DATA_SIZE] =
               {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};

        SE_TRACE(SE_TRACE_DEBUG, "Generate and certify a new ECDSA attestation key\n");
        if (PPID_RSA3072_ENCRYPTED == certification_key_type) {
            if (TEE_ATT_SUCCESS != (refqt_ret = getencryptedppid(pce_target_info, encrypted_ppid, REF_RSA_OAEP_3072_MOD_SIZE))) {
                SE_TRACE(SE_TRACE_DEBUG, "Fail to retrieve encrypted PPID.\n");
                goto CLEANUP;
            }
        } else {
            SE_TRACE(SE_TRACE_ERROR, "certification_key_type not supported.\n");
            refqt_ret = TEE_ATT_ERROR_INVALID_PARAMETER;
            goto CLEANUP;
        }
        // Generate the ECDSA key
        SE_TRACE(SE_TRACE_DEBUG, "Get ATT Key.\n");
        sgx_status = gen_att_key(m_eid,
                                 (uint32_t*)&tdqe_error,
                                 m_ecdsa_blob,
                                 SGX_QL_TRUSTED_ECDSA_BLOB_SIZE_SDK,
                                 &pce_target_info,
                                 &tdqe_report,
                                 &authentication_data[0],
                                 sizeof(authentication_data));
        if (SGX_SUCCESS != sgx_status) {
            SE_TRACE(SE_TRACE_ERROR, "Failed call into the TDQE. 0x%04x.\n", sgx_status);
            // /todo:  May want to retry on SGX_ERROR_ENCLAVE_LOST caused by power transition
            refqt_ret = (tee_att_error_t)sgx_status;
            goto CLEANUP;
        }
        if (TDQE_SUCCESS != tdqe_error) {
            SE_TRACE(SE_TRACE_ERROR, "Failed to generate attestation key. 0x%04x\n", tdqe_error);
            refqt_ret = (tee_att_error_t)tdqe_error;
            goto CLEANUP;
        }

        if(0 != memcpy_s(&p_qe_target_info->mr_enclave, sizeof(p_qe_target_info->mr_enclave),
                    &tdqe_report.body.mr_enclave, sizeof(tdqe_report.body.mr_enclave))) {
            refqt_ret = TEE_ATT_ERROR_UNEXPECTED;
            goto CLEANUP;
        }

        if (NULL == m_qe_id)
        {
            m_qe_id = (sgx_key_128bit_t*)malloc(sizeof(sgx_key_128bit_t));
            if (!m_qe_id) {
                SE_TRACE(SE_TRACE_ERROR, "Fail to allocate memory.\n");
                refqt_ret = TEE_ATT_ERROR_OUT_OF_MEMORY;
                goto CLEANUP;
            }

            refqt_ret = load_id_enclave_get_id(m_qe_id);
            if (TEE_ATT_SUCCESS != refqt_ret) {
                goto CLEANUP;
            }
        }

        // Certify the key
        // Get the certification data from the platform, if available
        p_sealed_ecdsa = reinterpret_cast<sgx_sealed_data_t *>(m_ecdsa_blob);
        p_seal_data_plain_text = reinterpret_cast<ref_plaintext_ecdsa_data_sdk_t *>(m_ecdsa_blob + sizeof(sgx_sealed_data_t) + p_sealed_ecdsa->plain_text_offset);
        cert_data_size = 0;
        memset(&plaintext_data, 0, sizeof(plaintext_data));
        pck_cert_id.p_qe3_id = (uint8_t*)m_qe_id;
        pck_cert_id.qe3_id_size = sizeof(*m_qe_id);
        pck_cert_id.p_platform_cpu_svn = &tdqe_report.body.cpu_svn;
        pck_cert_id.p_platform_pce_isv_svn = &m_pce_info.pce_isv_svn;
        pck_cert_id.p_encrypted_ppid = encrypted_ppid;
        pck_cert_id.encrypted_ppid_size = REF_RSA_OAEP_3072_MOD_SIZE;
        pck_cert_id.crypto_suite = PCE_ALG_RSA_OAEP_3072;
        pck_cert_id.pce_id = m_pce_info.pce_id;
        refqt_ret = get_platform_quote_cert_data(&pck_cert_id,
                                                 &pce_cert_psvn.cpu_svn,
                                                 &pce_cert_psvn.isv_svn,
                                                 &cert_data_size,
                                                 NULL);
        if (refqt_ret != TEE_ATT_SUCCESS) {
            if (refqt_ret != TEE_ATT_PLATFORM_LIB_UNAVAILABLE) {
                // The dependent library was found but it returned an error
                goto CLEANUP;
            }
            SE_TRACE(SE_TRACE_DEBUG, "Platform Quote Config callback is not available, use the platform's raw TCB.\n");
            refqt_ret = TEE_ATT_SUCCESS;
            // Use the raw TCB of the platform and the EncPPID certification type
            pce_cert_psvn.cpu_svn = tdqe_report.body.cpu_svn;
            pce_cert_psvn.isv_svn = pce_isv_svn;
        }

        // Set up the certification data and update the ECDSA Blob.
        // The TDQE will verify these plaintext parameters, add some more plaintext values, add the secret values and
        // generate a sealed blob.
        if(0 != memcpy_s(&plaintext_data.cert_cpu_svn, sizeof(plaintext_data.cert_cpu_svn),
                         &pce_cert_psvn.cpu_svn, sizeof(pce_cert_psvn.cpu_svn))) {
            refqt_ret = TEE_ATT_ERROR_UNEXPECTED;
            goto CLEANUP;
        }
        plaintext_data.cert_pce_info.pce_isv_svn = pce_cert_psvn.isv_svn;
        plaintext_data.cert_pce_info.pce_id = 0;
        if(0 != memcpy_s(&plaintext_data.raw_cpu_svn, sizeof(plaintext_data.raw_cpu_svn),
                         &tdqe_report.body.cpu_svn, sizeof(tdqe_report.body.cpu_svn))) {
            refqt_ret = TEE_ATT_ERROR_UNEXPECTED;
            goto CLEANUP;
        }
        plaintext_data.raw_pce_info.pce_isv_svn = m_pce_info.pce_isv_svn;
        plaintext_data.raw_pce_info.pce_id = m_pce_info.pce_id;
        if(0 != memcpy_s(&plaintext_data.qe_report, sizeof(plaintext_data.qe_report),
                         &tdqe_report, sizeof(tdqe_report))) {
            refqt_ret = TEE_ATT_ERROR_UNEXPECTED;
            goto CLEANUP;
        }
        if (0 != memcpy_s(&plaintext_data.qe_id, sizeof(plaintext_data.qe_id),
            m_qe_id, sizeof(*m_qe_id))) {
            refqt_ret = TEE_ATT_ERROR_UNEXPECTED;
            goto CLEANUP;
        }
        plaintext_data.signature_scheme = PCE_NIST_P256_ECDSA_SHA256;
        if(0 != memcpy_s(&plaintext_data.pce_target_info, sizeof(plaintext_data.pce_target_info),
                         &pce_target_info, sizeof(pce_target_info))) {
            refqt_ret = TEE_ATT_ERROR_UNEXPECTED;
            goto CLEANUP;
        }
        plaintext_data.certification_key_type = certification_key_type;
        refqt_ret = certify_key(m_ecdsa_blob,
                                &plaintext_data,
                                encrypted_ppid,
                                REF_RSA_OAEP_3072_MOD_SIZE,
                                certification_key_type);
        if (TEE_ATT_SUCCESS != refqt_ret) {
            SE_TRACE(SE_TRACE_DEBUG, "Failed to cerify key.\n");
            goto CLEANUP;
        }

        SE_TRACE(SE_TRACE_DEBUG, "Generated and certified a new key.  ECDSA_ID:\n");
        PRINT_BYTE_ARRAY(SE_TRACE_DEBUG, &tdqe_report.body.report_data, sizeof(sgx_sha256_hash_t));
        // Write the ECDSA_ID to the output buffer
        if(0 != memcpy_s(p_pub_key_id, sizeof(*p_pub_key_id), &tdqe_report.body.report_data, sizeof(*p_pub_key_id))) {
            refqt_ret = TEE_ATT_ERROR_UNEXPECTED;
            goto CLEANUP;
        }
    }

    CLEANUP:
    if(0 != blob_mutex_rc ) {
        blob_mutex_rc = se_mutex_unlock(&m_ecdsa_blob_mutex);
        if (0 == blob_mutex_rc)
        {
            SE_TRACE(SE_TRACE_ERROR, "Failed to unlock mutex");
            return TEE_ATT_ERROR_UNEXPECTED;
        }
    }

    return(refqt_ret);
}

/**
* This is the ECDSA-P256 specific init quote code.  The generic quote interfaces have been converted/reduced to the ECDSA specific inputs.
* The method will return the required quote buffer size dependent on the certification key type.
*
* @param certification_key_type
* @param p_quote_size
*
* @return TEE_ATT_SUCCESS
* @return TEE_ATT_ERROR_INVALID_PARAMETER
* @return Errors from load_qe()
* @return Errors from an ecall
* @return TEE_ATT_ATT_KEY_NOT_INITIALIZED  The Attestaion key has not been generated, certified or requires
*         recertification yet. Need to call InitQuote first/again to get attestaion key regenerated/receritifed.
* @return TEE_ATT_ATT_KEY_CERT_DATA_INVALID Quote certification data from the platform library is invalid.
*
*/
tee_att_error_t tee_att_config_t::ecdsa_get_quote_size(sgx_ql_cert_key_type_t certification_key_type,
                                                   uint32_t* p_quote_size)
{

    tee_att_error_t refqt_ret = TEE_ATT_SUCCESS;
    sgx_status_t sgx_status = SGX_SUCCESS;
    tdqe_error_t tdqe_error = TDQE_ERROR_UNEXPECTED;
    uint32_t cert_data_size;
    sgx_sealed_data_t *p_sealed_ecdsa;
    ref_plaintext_ecdsa_data_sdk_t *p_seal_data_plain_text;
    sgx_report_body_t tdqe_report_body;
    sgx_psvn_t pce_cert_psvn;
    uint8_t resealed = 0;
    sgx_ql_pck_cert_id_t pck_cert_id;
    uint32_t blob_size_read;
    int blob_mutex_rc = 0;

    // Verify inputs
    // Only RSA-3072-OAEP Encrypted PPID certification type in the reference.
    if (PPID_RSA3072_ENCRYPTED != certification_key_type) {
        SE_TRACE(SE_TRACE_ERROR, "Invalid certification key type.");
        return(TEE_ATT_ERROR_INVALID_PARAMETER);
    }

    if (NULL == p_quote_size) {
        SE_TRACE(SE_TRACE_ERROR, "p_quote_size is NULL.");
        return(TEE_ATT_ERROR_INVALID_PARAMETER);
    }

    SE_TRACE(SE_TRACE_DEBUG, "sizeof(sgx_quote4_t) = %d.\n",                       (unsigned int)sizeof(sgx_quote4_t));
    SE_TRACE(SE_TRACE_DEBUG, "(2 * sizeof(sgx_ec256_signature_t)) = %d.\n",        (unsigned int)(2 * sizeof(sgx_ec256_signature_t)));
    SE_TRACE(SE_TRACE_DEBUG, "sizeof(sgx_ec256_public_t) = %d.\n",                 (unsigned int)sizeof(sgx_ec256_public_t));
    SE_TRACE(SE_TRACE_DEBUG, "sizeof(uint16_t) = %d.\n",                           (unsigned int)sizeof(uint16_t));
    SE_TRACE(SE_TRACE_DEBUG, "sizeof(uint32_t) = %d.\n",                           (unsigned int)sizeof(uint32_t));
    SE_TRACE(SE_TRACE_DEBUG, "sizeof(uint32_t) = %d.\n",                           (unsigned int)sizeof(uint32_t));
    SE_TRACE(SE_TRACE_DEBUG, "authentication_data_size = %d.\n",                   (unsigned int)REF_ECDSDA_AUTHENTICATION_DATA_SIZE);
    SE_TRACE(SE_TRACE_DEBUG, "sizeof(ref_ppid_rsa3072_encrypted_cert_info_t) = %d.\n", (unsigned int)sizeof(sgx_ql_ppid_rsa3072_encrypted_cert_info_t));

    // Load the TDQE
    SE_TRACE(SE_TRACE_DEBUG, "Call Load the QE.\n");
    refqt_ret = load_qe();
    if (TEE_ATT_SUCCESS != refqt_ret) {
        goto CLEANUP;
    }

    blob_mutex_rc = se_mutex_lock(&m_ecdsa_blob_mutex);
    if (0 == blob_mutex_rc) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to lock mutex\n");
        goto CLEANUP;
    }

    blob_size_read = sizeof(m_ecdsa_blob);
    // Get ECDSA Blob if exists
    SE_TRACE(SE_TRACE_DEBUG, "Read ECDSA blob from persistent storage.\n");
    refqt_ret = read_persistent_data((uint8_t*)m_ecdsa_blob,
                                     &blob_size_read,
                                     ECDSA_BLOB_LABEL);
    if (TEE_ATT_SUCCESS != refqt_ret) {
        // Ignore errors since persistent storage is not required.  Blob in memory may still be OK and continue to try to verify the cached blob.
        SE_TRACE(SE_TRACE_WARNING, "ECDSA Blob doesn't exist is persistent storage.  Try to use the cached version.\n");
        refqt_ret = TEE_ATT_SUCCESS;
    }
    else if (blob_size_read != sizeof(m_ecdsa_blob)) {
        // If the blob was successfully read from persistent storage, verify its size.
        SE_TRACE(SE_TRACE_ERROR, "Invalid ECDSA Blob file size. blob_size_read = %uld, sizeof(g_ecdsa_blob) = %uld.  Since caller requested use any key, generate a new key.\n", blob_size_read, (uint32_t)sizeof(m_ecdsa_blob));
        refqt_ret = TEE_ATT_ATT_KEY_NOT_INITIALIZED;
        goto CLEANUP;
    }
    memset(&tdqe_report_body, 0, sizeof(tdqe_report_body));
    // If exists, verify blob.
    sgx_status = verify_blob(m_eid,
                             (uint32_t*)&tdqe_error,
                             (uint8_t*)m_ecdsa_blob,
                             sizeof(m_ecdsa_blob),
                             &resealed,
                             &tdqe_report_body,
                             0,
                             NULL);
    if (SGX_SUCCESS != sgx_status) {
        SE_TRACE(SE_TRACE_ERROR, "Failed call into the TDQE. 0x%04x\n", sgx_status);
        ///todo:  May want to retry on SGX_ERROR_ENCLAVE_LOST caused by power transition or return a different error
        refqt_ret = (tee_att_error_t)sgx_status;
        goto CLEANUP;
    }
    if (TDQE_SUCCESS != tdqe_error) {
        SE_TRACE(SE_TRACE_ERROR, "Invalid ECDSA Blob verificaton. 0x%04x, generate a new key.\n", tdqe_error);
        ///todo:  Do we want to force the caller to generate the attestation key again when the ECDSA blob fails?
        // May want to add logic to the DCAP wrappers to automatically call init_quote on this failure.
        refqt_ret = TEE_ATT_ATT_KEY_NOT_INITIALIZED;
        goto CLEANUP;
    }
    if (resealed) {
        SE_TRACE(SE_TRACE_DEBUG, "ECDSA Blob was resealed. Store it disk.\n");
        refqt_ret = write_persistent_data((uint8_t *)m_ecdsa_blob,
                                          sizeof(m_ecdsa_blob),
                                          ECDSA_BLOB_LABEL);

        if (refqt_ret != TEE_ATT_SUCCESS) {
            // Don't need to error since the blob is still good in memory.
            // /todo:  What is the best way to notify the requester that the blob was not stored?
            SE_TRACE(SE_TRACE_WARNING, "Warning, unable to store resealed ECDSA blob to persistent storage.\n");
            SE_TRACE(SE_TRACE_DEBUG, "File storage is not required for the QE_Library.  Library will use ECDSA Blob cached in memory.\n");
            refqt_ret = TEE_ATT_SUCCESS;
        }
        SE_TRACE(SE_TRACE_DEBUG, "ECDSA Blob was resealed. It means the TDQE or CPUSVN has been upgraded.\n");
        refqt_ret = TEE_ATT_ATT_KEY_NOT_INITIALIZED;
        goto CLEANUP;
    }

    SE_TRACE(SE_TRACE_DEBUG, "Successfully verified ECDSA Blob.\n");

    p_sealed_ecdsa = reinterpret_cast<sgx_sealed_data_t *>(m_ecdsa_blob);
    p_seal_data_plain_text = reinterpret_cast<ref_plaintext_ecdsa_data_sdk_t *>(m_ecdsa_blob + sizeof(sgx_sealed_data_t) + p_sealed_ecdsa->plain_text_offset);

    // PCE's raw isvsvn changed, catch it here and generate a new key
    if (m_raw_pce_isvsvn != p_seal_data_plain_text->raw_pce_info.pce_isv_svn) {
        SE_TRACE(SE_TRACE_ERROR, "PCE's raw isvsvn changed\n");
        refqt_ret = TEE_ATT_ATT_KEY_NOT_INITIALIZED;
        goto CLEANUP;
    }

    cert_data_size = 0;
    pck_cert_id.p_qe3_id = (uint8_t*)&p_seal_data_plain_text->qe_id;
    pck_cert_id.qe3_id_size = sizeof(p_seal_data_plain_text->qe_id);
    pck_cert_id.p_platform_cpu_svn = &p_seal_data_plain_text->cert_cpu_svn;
    pck_cert_id.p_platform_pce_isv_svn = &p_seal_data_plain_text->cert_pce_info.pce_isv_svn;
    pck_cert_id.p_encrypted_ppid = NULL;
    pck_cert_id.encrypted_ppid_size = 0;
    pck_cert_id.crypto_suite = PCE_ALG_RSA_OAEP_3072;
    pck_cert_id.pce_id = p_seal_data_plain_text->cert_pce_info.pce_id;
    refqt_ret = get_platform_quote_cert_data(&pck_cert_id,
                                             &pce_cert_psvn.cpu_svn,
                                             &pce_cert_psvn.isv_svn,
                                             &cert_data_size,
                                             NULL);
    // Use the default certification data when there is no data from platform library.
    if (refqt_ret != TEE_ATT_SUCCESS) {
        if (refqt_ret != TEE_ATT_PLATFORM_LIB_UNAVAILABLE) {
            // The dependent library was found but it returned an error
            goto CLEANUP;
        }

        *p_quote_size = sizeof(sgx_quote4_t) +                   // quote body
                        sizeof(sgx_ecdsa_sig_data_v4_t) +
                        sizeof(sgx_ql_auth_data_t) +
                        REF_ECDSDA_AUTHENTICATION_DATA_SIZE +    // Authentication data
                        sizeof(sgx_ql_certification_data_t) +
                        sizeof(sgx_ql_certification_data_t) +
                        sizeof(sgx_qe_report_certification_data_t) +
                        sizeof(sgx_ql_ppid_rsa3072_encrypted_cert_info_t);  // RSA3072_ENC_PPID + PCE CPUSVN + PCE ISVSNV + PCEID
        refqt_ret = TEE_ATT_SUCCESS;
    }
    else {
        // Verify that the cert_data_size is reasonable.
        if((cert_data_size > MAX_CERT_DATA_SIZE) ||
           (cert_data_size < MIN_CERT_DATA_SIZE)) {
            refqt_ret = TEE_ATT_ATT_KEY_CERT_DATA_INVALID;
            goto CLEANUP;
        }
        //Check to make sure that the TCBm of from the platform library matches the Cert TCB in the ECDSA blob.
        //We've change to use the TCBm to get the cert data, so below check is redundant. But I think it's OK to leave it here.
        if((0 != memcmp(&p_seal_data_plain_text->cert_cpu_svn, &pce_cert_psvn.cpu_svn, sizeof(p_seal_data_plain_text->cert_cpu_svn))) ||
           (p_seal_data_plain_text->cert_pce_info.pce_isv_svn != pce_cert_psvn.isv_svn)) {
            SE_TRACE(SE_TRACE_ERROR, "TCBm in ECDSA blob doesn't match the value returned by the platform lib. %d and %d\n", p_seal_data_plain_text->cert_pce_info.pce_isv_svn, pce_cert_psvn.isv_svn);

            refqt_ret = TEE_ATT_ATT_KEY_NOT_INITIALIZED;
            goto CLEANUP;
        }
        // Overflow will not occur since the cer_data_size is limited above
        *p_quote_size = (uint32_t)(sizeof(sgx_quote4_t) +                   // quote body
                                   sizeof(sgx_ecdsa_sig_data_v4_t) +
                                   sizeof(sgx_ql_auth_data_t) +
                                   REF_ECDSDA_AUTHENTICATION_DATA_SIZE +    // Authentication data
                                   sizeof(sgx_ql_certification_data_t) +
                                   sizeof(sgx_ql_certification_data_t) +
                                   sizeof(sgx_qe_report_certification_data_t) +
                                   cert_data_size);                         // certification data size returned by get_platform_quote_cert_data()
    }

    CLEANUP:
    if(0 != blob_mutex_rc ) {
        blob_mutex_rc = se_mutex_unlock(&m_ecdsa_blob_mutex);
        if (0 == blob_mutex_rc) {
            SE_TRACE(SE_TRACE_ERROR, "Failed to unlock mutex");
            refqt_ret = TEE_ATT_ERROR_UNEXPECTED;
        }
    }

    return(refqt_ret);
}

/**
* This is the ECDSA-P256 specific get quote code.  The generic quote interfaces have been converted/reduced to the ECDSA
* specific inputs. The method will return the quote dependent on the certification key type.
*
* @param p_app_report
* @param p_quote
* @param quote_size
*
* @return TEE_ATT_SUCCESS
* @return Return codes from load_qe.
* @return TEE_ATT_ATT_KEY_NOT_INITIALIZED  The Attestaion key has not been generated, certified or requires
*         recertification yet. Need to call InitQuote first/again to get attestaion key regenerated/receritifed.
* @return ///todo: List out ecall errors.
* @return TEE_ATT_ATT_KEY_CERT_DATA_INVALID Quote certification data from the platform library is invalid.
* @return TEE_ATT_ERROR_OUT_OF_MEMORY
* @return TDQE_ERROR_INVALID_PLATFORM
* @return TDQE_ERROR_INVALID_PARAMETER
* @return TDQE_ERROR_INVALID_REPORT
* @return TDQE_ECDSABLOB_ERROR  Attestation key is invalid.  Needs to be regenerated/recertified.
* @return TDQE_ERROR_UNEXPECTED
* @return TDQE_ERROR_CRYPTO
* @return TDQE_ERROR_OUT_OF_MEMORY
* @return SGX_ERROR_INVALID_PARAMETER
*/
tee_att_error_t  tee_att_config_t::ecdsa_get_quote(const sgx_report2_t *p_app_report,
                                              sgx_quote4_t *p_quote,
                                              uint32_t quote_size)
{
    tee_att_error_t refqt_ret = TEE_ATT_SUCCESS;
    sgx_status_t sgx_status = SGX_SUCCESS;
    tdqe_error_t tdqe_error = TDQE_ERROR_UNEXPECTED;
    uint8_t resealed = 0;
    uint32_t blob_size_read = sizeof(m_ecdsa_blob);
    sgx_sha256_hash_t blob_ecdsa_id;
    uint32_t cert_data_size;
    sgx_ql_pck_cert_id_t pck_cert_id;
    sgx_sealed_data_t *p_sealed_ecdsa;
    ref_plaintext_ecdsa_data_sdk_t *p_seal_data_plain_text;
    sgx_report_body_t tdqe_report_body;
    sgx_ql_certification_data_t *p_certification_data = NULL;
    sgx_psvn_t pce_cert_psvn;
    int blob_mutex_rc = 0;

    //Verify inputs
    if (NULL == p_app_report ||
        NULL == p_quote) {
        SE_TRACE(SE_TRACE_ERROR, "Invalid input pointer.\n");
        return(TEE_ATT_ERROR_INVALID_PARAMETER);
    }

    // Load the TDQE
    SE_TRACE(SE_TRACE_DEBUG, "Load the TDQE. %s\n", TDQE_ENCLAVE_NAME);
    // Load the QE enclave
    refqt_ret = load_qe();
    if (TEE_ATT_SUCCESS != refqt_ret) {
        goto CLEANUP;
    }

    blob_mutex_rc = se_mutex_lock(&m_ecdsa_blob_mutex);
    if (0 == blob_mutex_rc) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to lock mutex\n");
        goto CLEANUP;
    }

    SE_TRACE(SE_TRACE_DEBUG, "Read and verify ecdsa blob\n");
    blob_size_read = sizeof(m_ecdsa_blob);
    // Get ECDSA Blob if exists
    SE_TRACE(SE_TRACE_DEBUG, "Read ECDSA blob.\n");
    refqt_ret = read_persistent_data((uint8_t*)m_ecdsa_blob,
                                     &blob_size_read,
                                     ECDSA_BLOB_LABEL);
    if (TEE_ATT_SUCCESS != refqt_ret) {
        // Ignore errors since persistent storage is not required.  Blob in memory may still be OK and continue to try to verify the cached blob.
        ///todo:  May want to have a library configuration option that requires persistent storage.  Then treat the
        //failures accordingly
        SE_TRACE(SE_TRACE_WARNING, "ECDSA Blob doesn't exist is persistent storage.  Try to use the cached version.\n");
        refqt_ret = TEE_ATT_SUCCESS;
    }
    else if (blob_size_read != sizeof(m_ecdsa_blob)) {
        // If the blob was successfully read from persistent storage, verify its size.
        SE_TRACE(SE_TRACE_ERROR, "Invalid ECDSA Blob file size. blob_size_read = %uld, sizeof(g_ecdsa_blob) = %uld.  Since caller requested use any key, generate a new key.\n", blob_size_read, (uint32_t)sizeof(m_ecdsa_blob));
        refqt_ret = TEE_ATT_ATT_KEY_NOT_INITIALIZED;
        goto CLEANUP;
    }
    memset(&tdqe_report_body, 0, sizeof(tdqe_report_body));
    // If exists, verify blob.
    SE_TRACE(SE_TRACE_DEBUG, "Verify blob\n");
    sgx_status = verify_blob(m_eid,
                             (uint32_t*)&tdqe_error,
                             (uint8_t*)m_ecdsa_blob,
                             sizeof(m_ecdsa_blob),
                             &resealed,
                             &tdqe_report_body,
                             sizeof(blob_ecdsa_id),
                             (uint8_t*)&blob_ecdsa_id);
    if (SGX_SUCCESS != sgx_status) {
        SE_TRACE(SE_TRACE_ERROR, "Failed call into the TDQE. 0x%04x\n", sgx_status);
        // /todo:  May want to retry on SGX_ERROR_ENCLAVE_LOST caused by power transition or return a differnent error.
        refqt_ret = (tee_att_error_t)sgx_status;
        goto CLEANUP;
    }
    if (TDQE_SUCCESS != tdqe_error) {
        SE_TRACE(SE_TRACE_ERROR, "Invalid ECDSA Blob verification. 0x%04x\n", tdqe_error);
        refqt_ret = TEE_ATT_ATT_KEY_NOT_INITIALIZED;
        goto CLEANUP;
    }
    if (resealed) {
        SE_TRACE(SE_TRACE_DEBUG, "ECDSA Blob was resealed. Store it disk.\n");
        refqt_ret = write_persistent_data((uint8_t *)m_ecdsa_blob,
                                          sizeof(m_ecdsa_blob),
                                          ECDSA_BLOB_LABEL);

        if (refqt_ret != TEE_ATT_SUCCESS) {
            // Don't need to error since the blob is still good in memory.
            // /todo:  What is the best way to notify the requester that the blob was not stored?
            SE_TRACE(SE_TRACE_WARNING, "Warning, unable to store resealed ECDSA blob to persistent storage.\n");
            SE_TRACE(SE_TRACE_DEBUG, "File storage is not required for the QE_Library.  Library will use ECDSA Blob cached in memory.\n");
            refqt_ret = TEE_ATT_SUCCESS;
        }
        SE_TRACE(SE_TRACE_DEBUG, "ECDSA Blob was resealed. It means the TDQE or CPUSVN has been upgraded.\n");
        refqt_ret = TEE_ATT_ATT_KEY_NOT_INITIALIZED;
        goto CLEANUP;
    }
    SE_TRACE(SE_TRACE_DEBUG, "Using ECDSA_ID:\n");
    PRINT_BYTE_ARRAY(SE_TRACE_DEBUG, (uint8_t *)&blob_ecdsa_id, sizeof(blob_ecdsa_id));

    // See if we can get the certification data from the platform library.
    p_sealed_ecdsa = reinterpret_cast<sgx_sealed_data_t *>(m_ecdsa_blob);
    p_seal_data_plain_text = reinterpret_cast<ref_plaintext_ecdsa_data_sdk_t *>(m_ecdsa_blob + sizeof(sgx_sealed_data_t) + p_sealed_ecdsa->plain_text_offset);

    // PCE's raw isvsvn changed, catch it here and generate a new key
    if (m_raw_pce_isvsvn != p_seal_data_plain_text->raw_pce_info.pce_isv_svn) {
        SE_TRACE(SE_TRACE_ERROR, "PCE's raw isvsvn changed\n");
        refqt_ret = TEE_ATT_ATT_KEY_NOT_INITIALIZED;
        goto CLEANUP;
    }

    cert_data_size = 0;
    pck_cert_id.p_qe3_id = (uint8_t*)&p_seal_data_plain_text->qe_id;
    pck_cert_id.qe3_id_size = sizeof(p_seal_data_plain_text->qe_id);
    pck_cert_id.p_platform_cpu_svn = &p_seal_data_plain_text->cert_cpu_svn;
    pck_cert_id.p_platform_pce_isv_svn = &p_seal_data_plain_text->cert_pce_info.pce_isv_svn;
    pck_cert_id.p_encrypted_ppid = NULL;
    pck_cert_id.encrypted_ppid_size = 0;
    pck_cert_id.crypto_suite = PCE_ALG_RSA_OAEP_3072;
    pck_cert_id.pce_id = p_seal_data_plain_text->cert_pce_info.pce_id;
    refqt_ret = get_platform_quote_cert_data(&pck_cert_id,
                                             &pce_cert_psvn.cpu_svn,
                                             &pce_cert_psvn.isv_svn,
                                             &cert_data_size,
                                             NULL);
    if (refqt_ret == TEE_ATT_SUCCESS) {
        // Verify that the cert_data_size is reasonable.
        if((cert_data_size > MAX_CERT_DATA_SIZE) ||
           (cert_data_size < MIN_CERT_DATA_SIZE)) {
            refqt_ret = TEE_ATT_ATT_KEY_CERT_DATA_INVALID;
            goto CLEANUP;
        }
        // malloc the buffer to get the cert data and call again
        p_certification_data = (sgx_ql_certification_data_t *)malloc(sizeof(*p_certification_data) + cert_data_size);
        if(NULL == p_certification_data) {
            refqt_ret = TEE_ATT_ERROR_OUT_OF_MEMORY;
            goto CLEANUP;

        }
        memset(p_certification_data, 0, sizeof(*p_certification_data));
        refqt_ret = get_platform_quote_cert_data(&pck_cert_id,
                                                 &pce_cert_psvn.cpu_svn,
                                                 &pce_cert_psvn.isv_svn,
                                                 &cert_data_size,
                                                 p_certification_data->certification_data);
        if (refqt_ret != TEE_ATT_SUCCESS) {
            // Really shouldn't fail here if we passed the first call.
            refqt_ret = TEE_ATT_ERROR_UNEXPECTED;
            goto CLEANUP;
        }
        // Check to make sure that the TCBm of from the platform library matches the Cert TCB in the ECDSA blob.
        // We've change to use the TCBm to get the cert data, so below check is redundant. But I think it's OK to leave it here.
        if((0 != memcmp(&p_seal_data_plain_text->cert_cpu_svn, &pce_cert_psvn.cpu_svn, sizeof(p_seal_data_plain_text->cert_cpu_svn))) ||
           (p_seal_data_plain_text->cert_pce_info.pce_isv_svn != pce_cert_psvn.isv_svn)) {
            SE_TRACE(SE_TRACE_ERROR, "TCBm in ECDSA blob doesn't match the value returned by the platform lib. %d and %d\n", p_seal_data_plain_text->cert_pce_info.pce_isv_svn, pce_cert_psvn.isv_svn);
            refqt_ret = TEE_ATT_ATT_KEY_NOT_INITIALIZED;
            goto CLEANUP;
        }
        //Verify that the size of the quote is large enough to accomodate the cert data returned from the platform library
        if(quote_size < (sizeof(sgx_quote4_t) +
                         sizeof(sgx_ecdsa_sig_data_v4_t) +
                         sizeof(sgx_ql_auth_data_t) +
                         REF_ECDSDA_AUTHENTICATION_DATA_SIZE +
                         sizeof(sgx_ql_certification_data_t) +
                         sizeof(sgx_ql_certification_data_t) +
                         sizeof(sgx_qe_report_certification_data_t) +
                         cert_data_size)) {
            refqt_ret = TEE_ATT_ERROR_INVALID_PARAMETER;
            goto CLEANUP;
        }
        p_certification_data->cert_key_type = PCK_CERT_CHAIN;
        p_certification_data->size = cert_data_size;
    }
    else
    {
        if (refqt_ret != TEE_ATT_PLATFORM_LIB_UNAVAILABLE) {
            // The dependent library was found but it returned an error
            goto CLEANUP;
        }
        // Generate the quote with ECDSA blob's cert data. It is possible that the ECDSA blob's data contains the mapped
        // TCB of a previously successful call to the platform lib API.  In that case, this flow will not generate
        // the signature based on the raw-TCB.  This would be an 'unexpected' error flow since it is expected that if
        // the library was available before it should be available now.
        //
        // This is the normal flow when there is no provider library.
        refqt_ret = TEE_ATT_SUCCESS;
    }

    SE_TRACE(SE_TRACE_DEBUG, "Call TDQE gen_quote\n");
    sgx_status = gen_quote(m_eid,
                           (uint32_t*)&tdqe_error,
                           (uint8_t*)m_ecdsa_blob,
                           (uint32_t)sizeof(m_ecdsa_blob),
                           p_app_report,
                           NULL,
                           NULL,
                           NULL,
                           (uint8_t*)p_quote,
                           quote_size,
                           (uint8_t*)p_certification_data,
                           p_certification_data ? (uint32_t)(sizeof(*p_certification_data) + cert_data_size) : 0);
    if (SGX_SUCCESS != sgx_status) {
        SE_TRACE(SE_TRACE_ERROR, "Failed call into the TDQE. 0x%04x\n", sgx_status);
        ///todo:  May want to retry on SGX_ERROR_ENCLAVE_LOST caused by power transition
        refqt_ret = (tee_att_error_t)sgx_status;
        goto CLEANUP;
    }
    if (TDQE_SUCCESS != tdqe_error) {
        SE_TRACE(SE_TRACE_ERROR, "Gen Quote failed. 0x%04x\n", tdqe_error);
        refqt_ret = (tee_att_error_t)tdqe_error;
        goto CLEANUP;
    }
    SE_TRACE(SE_TRACE_DEBUG, "Get quote success\n");

    CLEANUP:
    if(NULL != p_certification_data) {
        free(p_certification_data);
    }

    if(0 != blob_mutex_rc ) {
        blob_mutex_rc = se_mutex_unlock(&m_ecdsa_blob_mutex);
        if (0 == blob_mutex_rc) {
            SE_TRACE(SE_TRACE_ERROR, "Failed to unlock mutex");
            refqt_ret = TEE_ATT_ERROR_UNEXPECTED;
        }
    }

    return(refqt_ret);
}
