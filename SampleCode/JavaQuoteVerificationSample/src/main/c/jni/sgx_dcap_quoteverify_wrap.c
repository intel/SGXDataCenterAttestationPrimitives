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
#include <jni.h>
#include <sgx_dcap_quoteverify.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "com_intel_sgx_SgxDcapVerifyQuoteJNI.h"

/* Support for throwing Java exceptions */
typedef enum {
  DCAP_JavaOutOfMemoryError = 1,
  DCAP_JavaIOException,
  DCAP_JavaRuntimeException,
  DCAP_JavaIndexOutOfBoundsException,
  DCAP_JavaArithmeticException,
  DCAP_JavaIllegalArgumentException,
  DCAP_JavaNullPointerException,
  DCAP_JavaDirectorPureVirtual,
  DCAP_JavaUnknownError,
  DCAP_JavaIllegalStateException,
} DCAP_JavaExceptionCodes;

typedef struct {
  DCAP_JavaExceptionCodes code;
  const char *java_exception;
} DCAP_JavaExceptions_t;


static void DCAP_JavaThrowException(JNIEnv *jenv, DCAP_JavaExceptionCodes code, const char *msg) {
  jclass excep;
  static const DCAP_JavaExceptions_t java_exceptions[] = {
    { DCAP_JavaOutOfMemoryError, "java/lang/OutOfMemoryError" },
    { DCAP_JavaIOException, "java/io/IOException" },
    { DCAP_JavaRuntimeException, "java/lang/RuntimeException" },
    { DCAP_JavaIndexOutOfBoundsException, "java/lang/IndexOutOfBoundsException" },
    { DCAP_JavaArithmeticException, "java/lang/ArithmeticException" },
    { DCAP_JavaIllegalArgumentException, "java/lang/IllegalArgumentException" },
    { DCAP_JavaNullPointerException, "java/lang/NullPointerException" },
    { DCAP_JavaDirectorPureVirtual, "java/lang/RuntimeException" },
    { DCAP_JavaUnknownError,  "java/lang/UnknownError" },
    { DCAP_JavaIllegalStateException, "java/lang/IllegalStateException" },
    { (DCAP_JavaExceptionCodes)0,  "java/lang/UnknownError" }
  };
  const DCAP_JavaExceptions_t *except_ptr = java_exceptions;

  while (except_ptr->code != code && except_ptr->code)
    except_ptr++;

  (*jenv)->ExceptionClear(jenv);
  excep = (*jenv)->FindClass(jenv, except_ptr->java_exception);
  if (excep)
    (*jenv)->ThrowNew(jenv, excep, msg);
}



#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief set the full path of QVE and QPL library
 * The function takes the enum and the corresponding full path
 * 
 * @param path_type Set type path of SGX_QV_QVE_PATH or SGX_QV_QPL_PATH
 * @param p_path It should be a valid full path
 * 
 * @return SGX_QL_SUCCESS  Successfully set the full path
 * @return SGX_QL_ERROR_INVALID_PARAMETER p_path is not a valid full path or the path is too long
 */
JNIEXPORT jint JNICALL Java_com_intel_sgx_SgxDcapVerifyQuoteJNI_sgx_1qv_1set_1path(JNIEnv *jenv, jobject jobj, jint jlibType,
                              jstring jpath) {
  (void)jenv;
  (void)jobj;
  quote3_error_t ret = SGX_QL_SUCCESS;

  const char *cpath = (*jenv)->GetStringUTFChars(jenv, jpath, NULL);
  if (NULL == cpath)
    return __LINE__;
  if (NULL == qvl_sgx_qv_set_path) {
    if (load_lib()){
			DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, "Unable to Link Error libsgx_dcap_quoteverify.so");
      return __LINE__;
    }  
  }

  if (jlibType == 0) {
    ret = qvl_sgx_qv_set_path(SGX_QV_QVE_PATH, cpath);
  } else if (jlibType == 1) {
    ret = qvl_sgx_qv_set_path(SGX_QV_QPL_PATH, cpath);
  }

  (*jenv)->ReleaseStringUTFChars(jenv, jpath, cpath); // release resources

  return ret;
}

/**
 * @brief Get SGX QvE identity and Root CA CRL
 * 
 * @param jenv 
 * @param jobj 
 * @return jobject 
 */
JNIEXPORT jobject JNICALL Java_com_intel_sgx_SgxDcapVerifyQuoteJNI_sgx_1qv_1get_1qve_1identity(JNIEnv *jenv, jobject jobj) {
  uint8_t *pp_qveid = NULL;
  jsize p_qveid_size = 0;
  uint8_t *pp_qveid_issue_chain = NULL;
  uint32_t p_qveid_issue_chain_size = 0;
  uint8_t *pp_root_ca_crl = NULL;
  uint16_t p_root_ca_crl_size = 0;

  jobject qveIdentityObj = NULL;
  jclass cls_QveIdentity =NULL;
  jmethodID meth_qveIdentityInit = NULL;
  (void)jobj;
  if (NULL == qvl_sgx_qv_get_qve_identity) {
    if (load_lib()){
      DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, "Unable to Link Error libsgx_dcap_quoteverify.so");
      return NULL;            
    }
  }

  quote3_error_t ret = qvl_sgx_qv_get_qve_identity(
      &pp_qveid, (uint32_t *)&p_qveid_size, &pp_qveid_issue_chain,
      &p_qveid_issue_chain_size, &pp_root_ca_crl, &p_root_ca_crl_size);
  if (ret != SGX_QL_SUCCESS) {
    return NULL;
  }

  jbyteArray tmp_identity_array = (*jenv)->NewByteArray(jenv, p_qveid_size);
  if ((*jenv)->GetArrayLength(jenv, tmp_identity_array) != p_qveid_size) {
    (*jenv)->DeleteLocalRef(jenv, tmp_identity_array);
    tmp_identity_array = (*jenv)->NewByteArray(jenv, p_qveid_size);
  }
  void *tmp_buf =
      (*jenv)->GetPrimitiveArrayCritical(jenv, (jarray)tmp_identity_array, 0);
  memcpy((void *)tmp_buf, (void *)pp_qveid, (size_t)p_qveid_size);
  (*jenv)->ReleasePrimitiveArrayCritical(jenv, tmp_identity_array, tmp_buf, 0);

  jbyteArray tmp_issue_chain_array =
      (*jenv)->NewByteArray(jenv, (int)p_qveid_issue_chain_size);
  if ((*jenv)->GetArrayLength(jenv, tmp_issue_chain_array) !=
      (int)p_qveid_issue_chain_size) {
    (*jenv)->DeleteLocalRef(jenv, tmp_issue_chain_array);
    tmp_issue_chain_array = (*jenv)->NewByteArray(jenv, (int)p_qveid_issue_chain_size);
  }
  tmp_buf =
      (*jenv)->GetPrimitiveArrayCritical(jenv, (jarray)tmp_issue_chain_array, 0);
  memcpy((void *)tmp_buf, (void *)pp_qveid_issue_chain,
         p_qveid_issue_chain_size);
  (*jenv)->ReleasePrimitiveArrayCritical(jenv, tmp_issue_chain_array, tmp_buf, 0);

  jbyteArray tmp_root_ca_crl_array =
      (*jenv)->NewByteArray(jenv, p_root_ca_crl_size);
  if ((*jenv)->GetArrayLength(jenv, tmp_root_ca_crl_array) !=
      p_root_ca_crl_size) {
    (*jenv)->DeleteLocalRef(jenv, tmp_root_ca_crl_array);
    tmp_root_ca_crl_array = (*jenv)->NewByteArray(jenv, p_root_ca_crl_size);
  }
  tmp_buf =
      (*jenv)->GetPrimitiveArrayCritical(jenv, (jarray)tmp_root_ca_crl_array, 0);
  memcpy((void *)tmp_buf, (void *)pp_root_ca_crl, p_root_ca_crl_size);
  (*jenv)->ReleasePrimitiveArrayCritical(jenv, tmp_root_ca_crl_array, tmp_buf, 0);

  // free the related memory
  if (NULL != pp_qveid && NULL != pp_qveid_issue_chain &&
      NULL != pp_root_ca_crl) {
    sgx_qv_free_qve_identity(pp_qveid, pp_qveid_issue_chain, pp_root_ca_crl);
  }

  cls_QveIdentity = (*jenv)->FindClass(jenv, "com/intel/sgx/identity/QveIdentity");
  if(NULL == cls_QveIdentity){
    DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, "Unable to find class com/intel/sgx/identity/QveIdentity");
    qveIdentityObj = NULL;
    goto FINI;
  }
  // Get the Method ID of the constructor which takes 3 bytes
  meth_qveIdentityInit =
      (*jenv)->GetMethodID(jenv, cls_QveIdentity, "<init>", "([B[B[B)V");
  if (NULL == meth_qveIdentityInit) {
    DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, "Unable to find init for com/intel/sgx/identity/QveIdentity");
    qveIdentityObj = NULL;
    goto FINI;
  }
  // Call back constructor to allocate a new instance, with an int argument
  qveIdentityObj =
      (*jenv)->NewObject(jenv, cls_QveIdentity, meth_qveIdentityInit, tmp_identity_array,
                        tmp_issue_chain_array, tmp_root_ca_crl_array);

FINI:
  // TODO release resource
  (*jenv)->DeleteLocalRef(jenv, tmp_identity_array);
  (*jenv)->DeleteLocalRef(jenv, tmp_issue_chain_array);
  (*jenv)->DeleteLocalRef(jenv, tmp_root_ca_crl_array);
  return qveIdentityObj;
}

/**
 * @brief 
 * When the Quoting Verification Library is linked to a process, it needs to know the proper enclave loading policy.
 * The library may be linked with a long lived process, such as a service, where it can load the enclaves and leave
 * them loaded (persistent). This better ensures that the enclaves will be available upon quote requests and not subject
 * to EPC limitations if loaded on demand. However, if the Quoting library is linked with an application process, there
 * may be many applications with the Quoting library and a better utilization of EPC is to load and unloaded the quoting
 * enclaves on demand (ephemeral).  The library will be shipped with a default policy of loading enclaves and leaving
 * them loaded until the library is unloaded (PERSISTENT). If the policy is set to EPHEMERAL, then the QE and PCE will
 * be loaded and unloaded on-demand.  If either enclave is already loaded when the policy is change to EPHEMERAL, the
 * enclaves will be unloaded before returning.
 * @param jenv 
 * @param jobj 
 * @param jpolicy  Sets the requested enclave loading policy to either SGX_QL_PERSISTENT, SGX_QL_EPHEMERAL or SGX_QL_DEFAULT
 * @return SGX_QL_SUCCESS Successfully set the enclave loading policy for the quoting library's enclaves.
 * @return SGX_QL_UNSUPPORTED_LOADING_POLICY The selected policy is not support by the quoting library.
 * @return SGX_QL_ERROR_UNEXPECTED Unexpected internal error.
 */
JNIEXPORT jint JNICALL Java_com_intel_sgx_SgxDcapVerifyQuoteJNI_sgx_1qv_1set_1enclave_1load_1policy(JNIEnv *jenv, jobject jobj,
                                             jint jpolicy) {
  (void)jenv;
  (void)jobj;

  quote3_error_t ret = SGX_QL_SUCCESS;
  if (NULL == qvl_sgx_qv_set_enclave_load_policy) {
    if (load_lib()){
      DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, "Unable to Link Error libsgx_dcap_quoteverify.so");
      return __LINE__;
    }
  }
  if (0 == jpolicy) {
    ret = qvl_sgx_qv_set_enclave_load_policy(SGX_QL_PERSISTENT);
  } else if (1 == jpolicy) {
    ret = qvl_sgx_qv_set_enclave_load_policy(SGX_QL_EPHEMERAL);
  }

  return ret;
}


/**
 * @brief Perform ECDSA quote verification
 * 
 * @param jenv 
 * @param jobj 
 * @param quote[IN] - Pointer to SGX Quote 
 * @param pck_crl[IN] - PCK crl 
 * @param pck_crl_issuer [IN] - PCK crl issuer
 * @param qe_identity [IN] - QE Identity 
 * @param qe_identity_issuer [IN] - QE Identity issuer
 * @param tcb_info [IN] - TCB Info 
 * @param tcb_info_issuer [IN] - TCB Info issuer
 * @param root_ca_crl [IN] - Root CA CRL 
 * @param jexpiration_check_date[IN] - This is the date that the QvE will use to determine if any of the inputted collateral have expired
 * @return jobject include Status code of the quote verification and quote verification result
 *      - status code should be one of
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_ERROR_INVALID_PARAMETER
 *      - SGX_QL_QUOTE_FORMAT_UNSUPPORTED
 *      - SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED
 *      - SGX_QL_UNABLE_TO_GENERATE_REPORT
 *      - SGX_QL_CRL_UNSUPPORTED_FORMAT
 */
JNIEXPORT jobject JNICALL Java_com_intel_sgx_SgxDcapVerifyQuoteJNI_sgx_1qv_1verify_1quote(JNIEnv *jenv, jobject jobj, jbyteArray quote,
                           jbyteArray pck_crl, jbyteArray pck_crl_issuer,
                           jbyteArray qe_identity,
                           jbyteArray qe_identity_issuer, jbyteArray tcb_info,
                           jbyteArray tcb_info_issuer, jbyteArray root_ca_crl,
                           jlong jexpiration_check_date) {

  quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
  uint32_t supplemental_data_size = 0;
  uint8_t *p_supplemental_data = NULL;
  sgx_ql_qve_collateral_t *p_quote_collateral = NULL;
  jobject obj_qe_report = NULL;
  jobject obj_supplemental = NULL;
  char exception_buf[BUFSIZ] = {'\0'};

  jbyteArray out_platform_instance_id_byte_array = NULL;
  jint dynamic_platform = 0;
  jint cached_keys = 0;
  jint smt_enabled = 0;

  (void)jobj;
  if (NULL == qvl_sgx_qv_verify_quote ||
      NULL == qvl_sgx_qv_get_quote_supplemental_data_size) {
    if (load_lib()){
      DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, "Unable to Link Error libsgx_dcap_quoteverify.so");
      return NULL;
    }
  }

  // critical error quote should not be NULL
  if (NULL == quote) {
    DCAP_JavaThrowException(jenv, DCAP_JavaIllegalArgumentException, "quote parameter should not be NULL");
    return NULL;
  }
  // Convert byte array to char array
  jbyte *quote_array = (*jenv)->GetByteArrayElements(jenv, quote, NULL);
  if (NULL == quote_array) {
    return NULL;
  }
  jsize quote_size = (*jenv)->GetArrayLength(jenv, quote);

  /*
   * if any element is NULL, will treat collateral be NULL
   *collateral can be NULL, if not NULL should be input for verification
   */
  if (NULL != pck_crl && NULL != pck_crl_issuer && NULL != qe_identity &&
      NULL != qe_identity_issuer && NULL != tcb_info &&
      NULL != tcb_info_issuer && NULL != root_ca_crl) {
    jsize tmp_len = 0;
    jbyte *tmp_byte = NULL;
    p_quote_collateral =
        (sgx_ql_qve_collateral_t *)malloc(sizeof(sgx_ql_qve_collateral_t));
    // hard code to 3, will be input from caller
    p_quote_collateral->version = 3;

    tmp_len = (*jenv)->GetArrayLength(jenv, pck_crl);
    tmp_byte = (*jenv)->GetByteArrayElements(jenv, pck_crl, NULL);
    p_quote_collateral->pck_crl =
        (char *)malloc((size_t)tmp_len + 1); // 1 byte for NULL
    p_quote_collateral->pck_crl_size = (uint32_t)(tmp_len + 1);
    memset(p_quote_collateral->pck_crl, 0,(size_t) tmp_len + 1);
    memcpy(p_quote_collateral->pck_crl, tmp_byte, (size_t)tmp_len);
    (*jenv)->ReleaseByteArrayElements(jenv, pck_crl, tmp_byte, 0);

    tmp_len = (*jenv)->GetArrayLength(jenv, pck_crl_issuer);
    tmp_byte = (*jenv)->GetByteArrayElements(jenv, pck_crl_issuer, NULL);
    p_quote_collateral->pck_crl_issuer_chain =
        (char *)malloc((size_t)tmp_len + 1); // 1 byte for NULL
    p_quote_collateral->pck_crl_issuer_chain_size = (uint32_t)(tmp_len + 1);
    memset(p_quote_collateral->pck_crl_issuer_chain, 0, (size_t)tmp_len + 1);
    memcpy(p_quote_collateral->pck_crl_issuer_chain, tmp_byte, (size_t)tmp_len);
    (*jenv)->ReleaseByteArrayElements(jenv, pck_crl_issuer, tmp_byte, 0);

    tmp_len = (*jenv)->GetArrayLength(jenv, qe_identity);
    tmp_byte = (*jenv)->GetByteArrayElements(jenv, qe_identity, NULL);
    p_quote_collateral->qe_identity =
        (char *)malloc((size_t)tmp_len + 1); // 1 byte for NULL
    p_quote_collateral->qe_identity_size = (uint32_t)(tmp_len + 1);
    memset(p_quote_collateral->qe_identity, 0, (size_t)tmp_len + 1);
    memcpy(p_quote_collateral->qe_identity, tmp_byte, (size_t)tmp_len);
    (*jenv)->ReleaseByteArrayElements(jenv, qe_identity, tmp_byte, 0);

    tmp_len = (*jenv)->GetArrayLength(jenv, qe_identity_issuer);
    tmp_byte = (*jenv)->GetByteArrayElements(jenv, qe_identity_issuer, NULL);
    p_quote_collateral->qe_identity_issuer_chain =
        (char *)malloc((size_t)tmp_len + 1); // 1 byte for NULL
    p_quote_collateral->qe_identity_issuer_chain_size = (uint32_t)(tmp_len + 1);
    memset(p_quote_collateral->qe_identity_issuer_chain, 0, (size_t)tmp_len + 1);
    memcpy(p_quote_collateral->qe_identity_issuer_chain, tmp_byte, (size_t)tmp_len);
    (*jenv)->ReleaseByteArrayElements(jenv, qe_identity_issuer, tmp_byte, 0);

    tmp_len = (*jenv)->GetArrayLength(jenv, tcb_info);
    tmp_byte = (*jenv)->GetByteArrayElements(jenv, tcb_info, NULL);
    p_quote_collateral->tcb_info =
        (char *)malloc((size_t)tmp_len + 1); // 1 byte for NULL
    p_quote_collateral->tcb_info_size = (uint32_t)(tmp_len + 1);
    memset(p_quote_collateral->tcb_info, 0, (size_t)tmp_len + 1);
    memcpy(p_quote_collateral->tcb_info, tmp_byte, (size_t)tmp_len);
    (*jenv)->ReleaseByteArrayElements(jenv, tcb_info, tmp_byte, 0);

    tmp_len = (*jenv)->GetArrayLength(jenv, tcb_info_issuer);
    tmp_byte = (*jenv)->GetByteArrayElements(jenv, tcb_info_issuer, NULL);
    p_quote_collateral->tcb_info_issuer_chain =
        (char *)malloc((size_t)tmp_len + 1); // 1 byte for NULL
    p_quote_collateral->tcb_info_issuer_chain_size = (uint32_t)(tmp_len + 1);
    memset(p_quote_collateral->tcb_info_issuer_chain, 0, (size_t)tmp_len + 1);
    memcpy(p_quote_collateral->tcb_info_issuer_chain, tmp_byte, (size_t)tmp_len);
    (*jenv)->ReleaseByteArrayElements(jenv, tcb_info_issuer, tmp_byte, 0);

    tmp_len = (*jenv)->GetArrayLength(jenv, root_ca_crl);
    tmp_byte = (*jenv)->GetByteArrayElements(jenv, root_ca_crl, NULL);
    p_quote_collateral->root_ca_crl =
        (char *)malloc((size_t)tmp_len + 1); // 1 byte for NULL
    p_quote_collateral->root_ca_crl_size = (uint32_t)(tmp_len + 1);
    memset(p_quote_collateral->root_ca_crl, 0, (size_t)tmp_len + 1);
    memcpy(p_quote_collateral->root_ca_crl, tmp_byte, (size_t)tmp_len);
    (*jenv)->ReleaseByteArrayElements(jenv, root_ca_crl, tmp_byte, 0);
  }
  // call DCAP quote verify library to get supplemental data size
  //
  dcap_ret = qvl_sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
  if (SGX_QL_SUCCESS == dcap_ret) {
    p_supplemental_data = (uint8_t *)malloc(supplemental_data_size);
    if (NULL == p_supplemental_data) {
      supplemental_data_size = 0;
    }
  }

  uint32_t collateral_expiration_status;
  sgx_ql_qv_result_t quote_verification_result;

  // call sgx_qv_verify_quote from library
  quote3_error_t qvl_ret = qvl_sgx_qv_verify_quote(
      (const uint8_t *)quote_array, (uint32_t)quote_size, p_quote_collateral, jexpiration_check_date,
      &collateral_expiration_status, &quote_verification_result, NULL,                //p_qve_report_info always is NULL, and always use QVL library to perform quote verfication
      supplemental_data_size, p_supplemental_data);

  if (SGX_QL_SUCCESS != qvl_ret) {
    if ((*jenv)->ExceptionCheck(jenv)) {
      (*jenv)->ExceptionClear(jenv);
      /* code to handle exception */
    }
    sprintf(exception_buf, "Quote verify failed with 0x%x", qvl_ret);
	DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, exception_buf);
    return NULL;
  }
  // Get SgxDcapQuoteVerifyResult class
  jclass cls_dcap_quote_verify_result =
      (*jenv)->FindClass(jenv, "com/intel/sgx/result/SgxDcapQuoteVerifyResult");
  if (NULL == cls_dcap_quote_verify_result) {
		  DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, "Unable to find class com/intel/sgx/result/SgxDcapQuoteVerifyResult");
    return NULL;
  }
  // Get the method ID of the constructor of CollateralExpiration class
  jmethodID meth_dcap_quote_verify_result_init = (*jenv)->GetMethodID(
    jenv, cls_dcap_quote_verify_result, "<init>", "(ILcom/intel/sgx/collateral/CollateralExpiration;Lcom/intel/sgx/result/SgxQlQvResult;Lcom/intel/sgx/report/SgxQlQeReportInfo;Lcom/intel/sgx/supplement/Supplemental;)V");
  if (NULL == meth_dcap_quote_verify_result_init) return NULL;

    // Get CollateralExpiration class
    jclass cls_collateral_expiration_status =
        (*jenv)->FindClass(jenv, "com/intel/sgx/collateral/CollateralExpiration");
    if (NULL == cls_collateral_expiration_status) {
		  DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, "Unable to find class com/intel/sgx/collateral/CollateralExpiration");
      return NULL;
    }
    // Get the method ID of the constructor of CollateralExpiration class
    jmethodID meth_collateral_expiration_status_init = (*jenv)->GetMethodID(
        jenv, cls_collateral_expiration_status, "<init>", "(I)V");
    if (NULL == meth_collateral_expiration_status_init) {
      sprintf(exception_buf, "Can't find function init");
	  DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, exception_buf);
      return NULL;
    }
    // call back constructor to allocate a new instance
    jobject obj_collateral_expiration_status = (*jenv)->NewObject(
        jenv, cls_collateral_expiration_status,
        meth_collateral_expiration_status_init, collateral_expiration_status);

    // Get SgxQlQvResult class
    jclass cls_ql_qv_result =
        (*jenv)->FindClass(jenv, "com/intel/sgx/result/SgxQlQvResult");
    if (NULL == cls_ql_qv_result) {
		  DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, "Unable to find class com/intel/sgx/result/SgxQlQvResult");
      return NULL;
    }
    // Get the method ID of the constructor of SgxQlQvResult class
    jmethodID meth_ql_qv_result_static = (*jenv)->GetStaticMethodID(
        jenv, cls_ql_qv_result, "fromStatus", "(I)Lcom/intel/sgx/result/SgxQlQvResult;");
    if (NULL == meth_ql_qv_result_static) {
      sprintf(exception_buf, "Can't find function fromStatus");
	  DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, exception_buf);
      return NULL;
    }
    // call back function to get a new instance
    jobject obj_ql_qv_result = (*jenv)->CallStaticObjectMethod(
        jenv, cls_ql_qv_result, meth_ql_qv_result_static,
        quote_verification_result);

    if (SGX_QL_SUCCESS == qvl_ret && 0 != supplemental_data_size) {
      // Get Supplemental class
      jclass cls_supplemental =
          (*jenv)->FindClass(jenv, "com/intel/sgx/supplement/Supplemental");
      if (NULL == cls_supplemental) {
		  DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, "Unable to find class com/intel/sgx/supplement/Supplemental");
        return NULL;
      }
      // Get the method ID of the constructor of Supplemental class
      jmethodID meth_supplemental_init = (*jenv)->GetMethodID(
          jenv, cls_supplemental, "<init>",
          "(SSJJJJIII[B[BLcom/intel/sgx/report/SgxCpuSvn;SSIB[BIIILjava/lang/String;)V");
      if (NULL == meth_supplemental_init) {
        sprintf(exception_buf, "Can't find constructor function ");
		DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, exception_buf);
        return NULL;
      }

      // Get SgxCpuSvn class
      jclass cls_sgx_cpu_svn =
          (*jenv)->FindClass(jenv, "com/intel/sgx/report/SgxCpuSvn");
      if (NULL == cls_sgx_cpu_svn) {
		  DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, "Unable to find class com/intel/sgx/report/SgxCpuSvn");
        return NULL;
      }
      // get byte array for rootKeyId
      jbyteArray out_root_key_id_byte_array = (*jenv)->NewByteArray(jenv, ROOT_KEY_ID_SIZE);
      if (NULL == out_root_key_id_byte_array) return NULL;
      (*jenv)->SetByteArrayRegion(jenv, out_root_key_id_byte_array, 0, ROOT_KEY_ID_SIZE, (const signed char *)(((sgx_ql_qv_supplemental_t *)p_supplemental_data)->root_key_id));


      // get byte array for pck_ppid
      jbyteArray out_pck_ppid_byte_array = (*jenv)->NewByteArray(jenv, 16);  // 16 bytes for PPID
      if (NULL == out_pck_ppid_byte_array) return NULL;
      (*jenv)->SetByteArrayRegion(jenv, out_pck_ppid_byte_array, 0, 16, (const signed char *)(((sgx_ql_qv_supplemental_t *)p_supplemental_data)->pck_ppid));

      // Get the method ID of the constructor of SgxCpuSvn class
      jmethodID meth_sgx_cpu_svn_init =
          (*jenv)->GetMethodID(jenv, cls_sgx_cpu_svn, "<init>", "([B)V");
      // get byte array for SgxCpuSvn
      jbyteArray tmp_cpu_svn_byte_array = (*jenv)->NewByteArray(jenv, SGX_CPUSVN_SIZE);
      if (NULL == tmp_cpu_svn_byte_array) return NULL;
      (*jenv)->SetByteArrayRegion(jenv, tmp_cpu_svn_byte_array, 0, SGX_CPUSVN_SIZE, (const signed char *)(((sgx_ql_qv_supplemental_t *)p_supplemental_data)->tcb_cpusvn.svn));
      // call back constructor to allocate a new SgxCpuSvn object
      jobject obj_sgx_cpu_svn = (*jenv)->NewObject(jenv, cls_sgx_cpu_svn, meth_sgx_cpu_svn_init, tmp_cpu_svn_byte_array);

      
      //<<// Multi-Package PCK cert related flags, they are only relevant to PCK Certificates issued by PCK Platform CA
      // get byte array for platform_instance_id
      #define x509_scalable 1
      #define x509_scalableWithIntegrity 2
      if ((((sgx_ql_qv_supplemental_t *)p_supplemental_data)->sgx_type) == x509_scalable || (((sgx_ql_qv_supplemental_t *)p_supplemental_data)->sgx_type) == x509_scalableWithIntegrity)
      {
        out_platform_instance_id_byte_array = (*jenv)->NewByteArray(jenv, PLATFORM_INSTANCE_ID_SIZE);
        if (NULL == out_platform_instance_id_byte_array)
          return NULL;
        (*jenv)->SetByteArrayRegion(jenv, out_platform_instance_id_byte_array, 0, PLATFORM_INSTANCE_ID_SIZE, (const signed char *)(((sgx_ql_qv_supplemental_t *)p_supplemental_data)->platform_instance_id));
        dynamic_platform = ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->dynamic_platform;
        cached_keys = ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->cached_keys;
        smt_enabled = ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->smt_enabled;
      }

      //call back constructor of Supplemental class
      obj_supplemental = (*jenv)->NewObject(jenv, cls_supplemental, meth_supplemental_init,
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->major_version,    //tricky code to set version, suppose version less than uint16_t
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->minor_version,
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->earliest_issue_date,
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->latest_issue_date,
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->earliest_expiration_date,
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->tcb_level_date_tag,
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->pck_crl_num,
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->root_ca_crl_num,
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->tcb_eval_ref_num,
      out_root_key_id_byte_array,
      out_pck_ppid_byte_array,
      obj_sgx_cpu_svn,
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->tcb_pce_isvsvn,
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->pce_id,
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->tee_type,
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->sgx_type,
      out_platform_instance_id_byte_array,
      dynamic_platform,
      cached_keys,
      smt_enabled,
      NULL             // for old api alway return null for sa_list
      );
    }


  // call back constructor to allocate a new instance of SgxDcapQuoteVerifyResult
    jobject obj_dcap_quote_verify_result = (*jenv)->NewObject(
        jenv, cls_dcap_quote_verify_result,
        meth_dcap_quote_verify_result_init, qvl_ret, obj_collateral_expiration_status, obj_ql_qv_result, obj_qe_report, obj_supplemental);

  (*jenv)->ReleaseByteArrayElements(jenv, quote, quote_array, 0);
  if (NULL != p_quote_collateral) {
    if (NULL != p_quote_collateral->pck_crl) {
      free(p_quote_collateral->pck_crl);
    }
    if (NULL != p_quote_collateral->pck_crl_issuer_chain) {
      free(p_quote_collateral->pck_crl_issuer_chain);
    }
    if (NULL != p_quote_collateral->qe_identity) {
      free(p_quote_collateral->qe_identity);
    }
    if (NULL != p_quote_collateral->qe_identity_issuer_chain) {
      free(p_quote_collateral->qe_identity_issuer_chain);
    }
    if (NULL != p_quote_collateral->tcb_info) {
      free(p_quote_collateral->tcb_info);
    }
    if (NULL != p_quote_collateral->tcb_info_issuer_chain) {
      free(p_quote_collateral->tcb_info_issuer_chain);
    }
    if (NULL != p_quote_collateral->root_ca_crl) {
      free(p_quote_collateral->root_ca_crl);
    }
    free(p_quote_collateral);
  }
  if (NULL != p_supplemental_data) {
    free(p_supplemental_data);
  }
  return obj_dcap_quote_verify_result;
}


/**
 * @brief Return collater of quote
 * 
 * @param jenv 
 * @param jobj 
 * @param quote 
 * @return 
 */
JNIEXPORT jobject JNICALL Java_com_intel_sgx_SgxDcapVerifyQuoteJNI_tee_1qv_1get_1collateral(JNIEnv *jenv, jobject jobj, jbyteArray quote)
{
  char exception_buf[BUFSIZ] = {'\0'};
  quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
  unsigned char * p_quote_collateral = NULL;
  uint32_t collateral_size = 0;
  uint16_t major_version = 0;
  uint16_t minor_version = 0;
  jstring pck_crl_issuer_chain;
  jstring root_ca_crl;
  jstring pck_crl;
  jstring tcb_info_issuer_chain;
  jstring tcb_info;
  jstring qe_identity_issuer_chain;
  jstring qe_identity;

  uint32_t tee_type;

  (void)jobj;
  // critical error quote should not be NULL
  if (NULL == quote)
  {
		  DCAP_JavaThrowException(jenv, DCAP_JavaIllegalArgumentException, "quote parameter should not be NULL");
    return NULL;
  }
  if (NULL == qvl_tee_qv_get_collateral || NULL == qvl_tee_qv_free_collateral) {
    if (load_lib()){
			DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, "Unable to Link Error libsgx_dcap_quoteverify.so");
      return NULL;
    }
  }
  jclass jexceptionCls = (*jenv)->FindClass(jenv, "java/lang/Exception");
  if (NULL == jexceptionCls) {
    return NULL;
  }
  // Convert byte array to char array
  jbyte *quote_array = (*jenv)->GetByteArrayElements(jenv, quote, NULL);
  if (NULL == quote_array)
  {
    return NULL;
  }
  jsize quote_size = (*jenv)->GetArrayLength(jenv, quote);

  // call tee_qv_get_collateral from library
  dcap_ret = qvl_tee_qv_get_collateral((const unsigned char *)quote_array, (uint32_t)quote_size, &p_quote_collateral,
                                   &collateral_size);
  if (SGX_QL_SUCCESS != dcap_ret && NULL != p_quote_collateral) {
    if ((*jenv)->ExceptionCheck(jenv)) {
      (*jenv)->ExceptionClear(jenv);
      /* code to handle exception */
    }
    sprintf(exception_buf, "Get supplement data failed with 0x%x", dcap_ret);
	DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, exception_buf);
    return NULL;
  }

  // Get Collateral class
  jclass cls_collateral =
      (*jenv)->FindClass(jenv, "com/intel/sgx/collateral/Collateral");
  if (NULL == cls_collateral) {
		  DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, "Unable to find class com/intel/sgx/collateral/Collateral");
    return NULL;
  }
  // Get the method ID of the constructor of CollateralExpiration class
  jmethodID meth_collateral_init = (*jenv)->GetMethodID(
    jenv, cls_collateral, "<init>", "(SSILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");
  if (NULL == meth_collateral_init) return NULL;

  sgx_ql_qve_collateral_t* p_sgx_collateral = NULL;

  p_sgx_collateral = (sgx_ql_qve_collateral_t*)p_quote_collateral;

  if(p_sgx_collateral->version >= 3){
    // suppose the version should no never more than uint16
    major_version = p_sgx_collateral->major_version;
    minor_version = p_sgx_collateral->minor_version;;
  }else{ 
    // if version less than 3, the minor version should be 0
    // a little trick here, the version suppose no more than 2^15, then is safe to convert to uint16_t
    major_version = (uint16_t)(p_sgx_collateral->version);
    minor_version = 0;
  }
  tee_type = p_sgx_collateral->tee_type;
  pck_crl_issuer_chain = (*jenv)->NewStringUTF(jenv, p_sgx_collateral->pck_crl_issuer_chain);
  root_ca_crl= (*jenv)->NewStringUTF(jenv, p_sgx_collateral->root_ca_crl);
  pck_crl = (*jenv)->NewStringUTF(jenv, p_sgx_collateral->pck_crl);
  tcb_info = (*jenv)->NewStringUTF(jenv, p_sgx_collateral->tcb_info);
  qe_identity_issuer_chain = (*jenv)->NewStringUTF(jenv, p_sgx_collateral->qe_identity_issuer_chain);
  qe_identity = (*jenv)->NewStringUTF(jenv, p_sgx_collateral->qe_identity);
  tcb_info_issuer_chain = (*jenv)->NewStringUTF(jenv, p_sgx_collateral->tcb_info_issuer_chain);
  
  // call back constructor to allocate a new instance of Collateral
  jobject obj_collateral = (*jenv)->NewObject(
        jenv, cls_collateral,
        meth_collateral_init, major_version, minor_version, tee_type, pck_crl_issuer_chain, root_ca_crl, pck_crl, tcb_info_issuer_chain, tcb_info, qe_identity_issuer_chain, qe_identity);
  // clean up
  qvl_tee_qv_free_collateral(p_quote_collateral);
  return obj_collateral;
}

/**
 * @brief Perform ECDSA quote verification
 * 
 * @param jenv 
 * @param jobj 
 * @param quote 
 * @param pck_crl 
 * @param pck_crl_issuer 
 * @param qe_identity 
 * @param qe_identity_issuer 
 * @param tcb_info 
 * @param tcb_info_issuer 
 * @param root_ca_crl 
 * @param jexpiration_check_date 
 * @param suppl_version 
 * @param suppl_size 
 * @return jobject include Status code of the quote verification and quote verification result
 *      - status code should be one of
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_ERROR_INVALID_PARAMETER
 *      - SGX_QL_QUOTE_FORMAT_UNSUPPORTED
 *      - SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED
 *      - SGX_QL_UNABLE_TO_GENERATE_REPORT
 *      - SGX_QL_CRL_UNSUPPORTED_FORMAT
 */
JNIEXPORT jobject JNICALL Java_com_intel_sgx_SgxDcapVerifyQuoteJNI_tee_1verify_1quote(JNIEnv *jenv, jobject jobj, jbyteArray quote,
                           jbyteArray pck_crl, jbyteArray pck_crl_issuer,
                           jbyteArray qe_identity,
                           jbyteArray qe_identity_issuer, jbyteArray tcb_info,
                           jbyteArray tcb_info_issuer, jbyteArray root_ca_crl,
                           jlong jexpiration_check_date, jshort suppl_version, jint suppl_size)
 {
  char exception_buf[BUFSIZ] = {'\0'};

  quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
  uint8_t *p_supplemental_data = NULL;
  sgx_ql_qve_collateral_t *p_quote_collateral = NULL;
  jobject obj_qe_report = NULL;
  jobject obj_supplemental = NULL;
  uint32_t latest_suppl_version = 0;
  uint32_t latest_suppl_size = 0;
  jstring sa_list= NULL;
  jbyteArray out_platform_instance_id_byte_array = NULL;
  jint dynamic_platform = 0;
  jint cached_keys = 0;
  jint smt_enabled = 0;

  (void)jobj;
  if (NULL == qvl_sgx_qv_verify_quote ||
      NULL == qvl_sgx_qv_get_quote_supplemental_data_size) {
    if (load_lib()){
			DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, "Unable to Link Error libsgx_dcap_quoteverify.so");
      return NULL;
    }
  }
  jclass jexceptionCls = (*jenv)->FindClass(jenv, "java/lang/Exception");
  if (NULL == jexceptionCls) {
    return NULL;
  }

  // critical error quote should not be NULL
  if (NULL == quote) {
		  DCAP_JavaThrowException(jenv, DCAP_JavaIllegalArgumentException, "quote parameter should not be NULL");
    return NULL;
  }
  // Convert byte array to char array
  jbyte *quote_array = (*jenv)->GetByteArrayElements(jenv, quote, NULL);
  if (NULL == quote_array) {
    return NULL;
  }
  jsize quote_size = (*jenv)->GetArrayLength(jenv, quote);

  /*
   * if any element is NULL, will treat collateral be NULL
   *collateral can be NULL, if not NULL should be input for verification
   */
  if (NULL != pck_crl && NULL != pck_crl_issuer && NULL != qe_identity &&
      NULL != qe_identity_issuer && NULL != tcb_info &&
      NULL != tcb_info_issuer && NULL != root_ca_crl) {
    jsize tmp_len = 0;
    jbyte *tmp_byte = NULL;
    p_quote_collateral =
        (sgx_ql_qve_collateral_t *)malloc(sizeof(sgx_ql_qve_collateral_t));
    // hard code to 3, will be input from caller
    p_quote_collateral->version = 3;

    tmp_len = (*jenv)->GetArrayLength(jenv, pck_crl);
    tmp_byte = (*jenv)->GetByteArrayElements(jenv, pck_crl, NULL);
    p_quote_collateral->pck_crl =
        (char *)malloc((size_t)tmp_len + 1); // 1 byte for NULL
    p_quote_collateral->pck_crl_size = (uint32_t)(tmp_len + 1);
    memset(p_quote_collateral->pck_crl, 0, (size_t)tmp_len + 1);
    memcpy(p_quote_collateral->pck_crl, tmp_byte, (size_t)tmp_len);
    (*jenv)->ReleaseByteArrayElements(jenv, pck_crl, tmp_byte, 0);

    tmp_len = (*jenv)->GetArrayLength(jenv, pck_crl_issuer);
    tmp_byte = (*jenv)->GetByteArrayElements(jenv, pck_crl_issuer, NULL);
    p_quote_collateral->pck_crl_issuer_chain =
        (char *)malloc((size_t)tmp_len + 1); // 1 byte for NULL
    p_quote_collateral->pck_crl_issuer_chain_size = (uint32_t)(tmp_len + 1);
    memset(p_quote_collateral->pck_crl_issuer_chain, 0, (size_t)tmp_len + 1);
    memcpy(p_quote_collateral->pck_crl_issuer_chain, tmp_byte, (size_t)tmp_len);
    (*jenv)->ReleaseByteArrayElements(jenv, pck_crl_issuer, tmp_byte, 0);

    tmp_len = (*jenv)->GetArrayLength(jenv, qe_identity);
    tmp_byte = (*jenv)->GetByteArrayElements(jenv, qe_identity, NULL);
    p_quote_collateral->qe_identity =
        (char *)malloc((size_t)tmp_len + 1); // 1 byte for NULL
    p_quote_collateral->qe_identity_size = (uint32_t)(tmp_len + 1);
    memset(p_quote_collateral->qe_identity, 0, (size_t)tmp_len + 1);
    memcpy(p_quote_collateral->qe_identity, tmp_byte, (size_t)tmp_len);
    (*jenv)->ReleaseByteArrayElements(jenv, qe_identity, tmp_byte, 0);

    tmp_len = (*jenv)->GetArrayLength(jenv, qe_identity_issuer);
    tmp_byte = (*jenv)->GetByteArrayElements(jenv, qe_identity_issuer, NULL);
    p_quote_collateral->qe_identity_issuer_chain =
        (char *)malloc((size_t)tmp_len + 1); // 1 byte for NULL
    p_quote_collateral->qe_identity_issuer_chain_size = (uint32_t)(tmp_len + 1);
    memset(p_quote_collateral->qe_identity_issuer_chain, 0, (size_t)tmp_len + 1);
    memcpy(p_quote_collateral->qe_identity_issuer_chain, tmp_byte, (size_t)tmp_len);
    (*jenv)->ReleaseByteArrayElements(jenv, qe_identity_issuer, tmp_byte, 0);

    tmp_len = (*jenv)->GetArrayLength(jenv, tcb_info);
    tmp_byte = (*jenv)->GetByteArrayElements(jenv, tcb_info, NULL);
    p_quote_collateral->tcb_info =
        (char *)malloc((size_t)tmp_len + 1); // 1 byte for NULL
    p_quote_collateral->tcb_info_size = (uint32_t)(tmp_len + 1);
    memset(p_quote_collateral->tcb_info, 0, (size_t)tmp_len + 1);
    memcpy(p_quote_collateral->tcb_info, tmp_byte, (size_t)tmp_len);
    (*jenv)->ReleaseByteArrayElements(jenv, tcb_info, tmp_byte, 0);

    tmp_len = (*jenv)->GetArrayLength(jenv, tcb_info_issuer);
    tmp_byte = (*jenv)->GetByteArrayElements(jenv, tcb_info_issuer, NULL);
    p_quote_collateral->tcb_info_issuer_chain =
        (char *)malloc((size_t)tmp_len + 1); // 1 byte for NULL
    p_quote_collateral->tcb_info_issuer_chain_size = (uint32_t)(tmp_len + 1);
    memset(p_quote_collateral->tcb_info_issuer_chain, 0, (size_t)tmp_len + 1);
    memcpy(p_quote_collateral->tcb_info_issuer_chain, tmp_byte, (size_t)tmp_len);
    (*jenv)->ReleaseByteArrayElements(jenv, tcb_info_issuer, tmp_byte, 0);

    tmp_len = (*jenv)->GetArrayLength(jenv, root_ca_crl);
    tmp_byte = (*jenv)->GetByteArrayElements(jenv, root_ca_crl, NULL);
    p_quote_collateral->root_ca_crl =
        (char *)malloc((size_t)tmp_len + 1); // 1 byte for NULL
    p_quote_collateral->root_ca_crl_size = (uint32_t)(tmp_len + 1);
    memset(p_quote_collateral->root_ca_crl, 0, (size_t)tmp_len + 1);
    memcpy(p_quote_collateral->root_ca_crl, tmp_byte, (size_t)tmp_len);
    (*jenv)->ReleaseByteArrayElements(jenv, root_ca_crl, tmp_byte, 0);
  }
  // call DCAP quote verify library to get supplemental data size and version
  //
  dcap_ret =tee_get_supplemental_data_version_and_size((const unsigned char *)quote_array, (uint32_t)quote_size, &latest_suppl_version, &latest_suppl_size);
  if (SGX_QL_SUCCESS == dcap_ret) {
    if((suppl_version == 0 || (uint32_t)suppl_version == latest_suppl_version) &&  (uint32_t)suppl_size == latest_suppl_size)
    p_supplemental_data = (uint8_t *)malloc(latest_suppl_size);
    if (NULL == p_supplemental_data) {
      latest_suppl_size = 0;
    }
  }else {
    //something worng and unable to get supplement data size and version
    DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, "Unable to get supplement data size and verson");
    return NULL;
  }

  uint32_t collateral_expiration_status;
  sgx_ql_qv_result_t quote_verification_result;

  // call sgx_qv_verify_quote from library
  quote3_error_t qvl_ret = qvl_sgx_qv_verify_quote(
      (const unsigned char *)quote_array, (unsigned int)quote_size, p_quote_collateral, jexpiration_check_date,
      &collateral_expiration_status, &quote_verification_result, NULL,                //p_qve_report_info always is NULL, and always use QVL library to perform quote verfication
      latest_suppl_size, p_supplemental_data);

  if (SGX_QL_SUCCESS != qvl_ret) {
    if ((*jenv)->ExceptionCheck(jenv)) {
      (*jenv)->ExceptionClear(jenv);
      /* code to handle exception */
    }
    sprintf(exception_buf, "Quote verify failed with 0x%x", qvl_ret);
	  DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, exception_buf );
    return NULL;
  }
  // Get SgxDcapQuoteVerifyResult class
  jclass cls_tee_dcap_quote_verify_result =
      (*jenv)->FindClass(jenv, "com/intel/sgx/result/TeeDcapQuoteVerifyResult");
  if (NULL == cls_tee_dcap_quote_verify_result) {
		  DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, "Unable to find class com/intel/sgx/result/TeeDcapQuoteVerifyResult");
    return NULL;
  }
  // Get the method ID of the constructor of CollateralExpiration class
  jmethodID meth_tee_dcap_quote_verify_result_init = (*jenv)->GetMethodID(
    jenv, cls_tee_dcap_quote_verify_result, "<init>", "(ILcom/intel/sgx/collateral/CollateralExpiration;Lcom/intel/sgx/result/SgxQlQvResult;Lcom/intel/sgx/report/SgxQlQeReportInfo;Lcom/intel/sgx/supplement/TeeSupplemental;)V");
  if (NULL == meth_tee_dcap_quote_verify_result_init) return NULL;

    // Get CollateralExpiration class
    jclass cls_collateral_expiration_status =
        (*jenv)->FindClass(jenv, "com/intel/sgx/collateral/CollateralExpiration");
    if (NULL == cls_collateral_expiration_status) {
		  DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, "Unable to find class com/intel/sgx/collateral/CollateralExpiration");
      return NULL;
    }
    // Get the method ID of the constructor of CollateralExpiration class
    jmethodID meth_collateral_expiration_status_init = (*jenv)->GetMethodID(
        jenv, cls_collateral_expiration_status, "<init>", "(I)V");
    if (NULL == meth_collateral_expiration_status_init) {
      sprintf(exception_buf, "Can't find function init");
	    DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, exception_buf);
      return NULL;
    }
    // call back constructor to allocate a new instance
    jobject obj_collateral_expiration_status = (*jenv)->NewObject(
        jenv, cls_collateral_expiration_status,
        meth_collateral_expiration_status_init, collateral_expiration_status);

    // Get SgxQlQvResult class
    jclass cls_ql_qv_result =
        (*jenv)->FindClass(jenv, "com/intel/sgx/result/SgxQlQvResult");
    if (NULL == cls_ql_qv_result) {
		  DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, "Unable to find class com/intel/sgx/result/SgxQlQvResult");
      return NULL;
    }
    // Get the method ID of the constructor of SgxQlQvResult class
    jmethodID meth_ql_qv_result_static = (*jenv)->GetStaticMethodID(
        jenv, cls_ql_qv_result, "fromStatus", "(I)Lcom/intel/sgx/result/SgxQlQvResult;");
    if (NULL == meth_ql_qv_result_static) {
      sprintf(exception_buf, "Can't find function fromStatus");
	  DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, exception_buf);
      return NULL;
    }
    // call back function to get a new instance
    jobject obj_ql_qv_result = (*jenv)->CallStaticObjectMethod(
        jenv, cls_ql_qv_result, meth_ql_qv_result_static,
        quote_verification_result);

    if (SGX_QL_SUCCESS == qvl_ret && 0 != latest_suppl_size) {
      // Get Supplemental class
      jclass cls_supplemental =
          (*jenv)->FindClass(jenv, "com/intel/sgx/supplement/Supplemental");
      if (NULL == cls_supplemental) {
		  DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, "Unable to find class com/intel/sgx/supplement/Supplemental");
        return NULL;
      }
      // Get the method ID of the constructor of Supplemental class
      jmethodID meth_supplemental_init = (*jenv)->GetMethodID(
          jenv, cls_supplemental, "<init>",
          "(SSJJJJIII[B[BLcom/intel/sgx/report/SgxCpuSvn;SSIB[BIIILjava/lang/String;)V");
      if (NULL == meth_supplemental_init) {
        sprintf(exception_buf, "Can't find constructor function ");
		DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, exception_buf);
        return NULL;
      }

      // Get SgxCpuSvn class
      jclass cls_sgx_cpu_svn =
          (*jenv)->FindClass(jenv, "com/intel/sgx/report/SgxCpuSvn");
      if (NULL == cls_sgx_cpu_svn) {
		  DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, "com/intel/sgx/report/SgxCpuSvn");
        return NULL;
      }
      // get byte array for rootKeyId
      jbyteArray out_root_key_id_byte_array = (*jenv)->NewByteArray(jenv, ROOT_KEY_ID_SIZE);
      if (NULL == out_root_key_id_byte_array) return NULL;
      (*jenv)->SetByteArrayRegion(jenv, out_root_key_id_byte_array, 0, ROOT_KEY_ID_SIZE, (const signed char *)(((sgx_ql_qv_supplemental_t *)p_supplemental_data)->root_key_id));


      // get byte array for pck_ppid
      jbyteArray out_pck_ppid_byte_array = (*jenv)->NewByteArray(jenv, 16);  // 16 bytes for PPID
      if (NULL == out_pck_ppid_byte_array) return NULL;
      (*jenv)->SetByteArrayRegion(jenv, out_pck_ppid_byte_array, 0, 16, (const signed char *)(((sgx_ql_qv_supplemental_t *)p_supplemental_data)->pck_ppid));

      // Get the method ID of the constructor of SgxCpuSvn class
      jmethodID meth_sgx_cpu_svn_init =
          (*jenv)->GetMethodID(jenv, cls_sgx_cpu_svn, "<init>", "([B)V");
      // get byte array for SgxCpuSvn
      jbyteArray tmp_cpu_svn_byte_array = (*jenv)->NewByteArray(jenv, SGX_CPUSVN_SIZE);
      if (NULL == tmp_cpu_svn_byte_array) return NULL;
      (*jenv)->SetByteArrayRegion(jenv, tmp_cpu_svn_byte_array, 0, SGX_CPUSVN_SIZE, (const signed char *)(((sgx_ql_qv_supplemental_t *)p_supplemental_data)->tcb_cpusvn.svn));
      // call back constructor to allocate a new SgxCpuSvn object
      jobject obj_sgx_cpu_svn = (*jenv)->NewObject(jenv, cls_sgx_cpu_svn, meth_sgx_cpu_svn_init, tmp_cpu_svn_byte_array);

      //<<// Multi-Package PCK cert related flags, they are only relevant to PCK Certificates issued by PCK Platform CA
      // get byte array for platform_instance_id
      if ((((sgx_ql_qv_supplemental_t *)p_supplemental_data)->sgx_type) == x509_scalable || (((sgx_ql_qv_supplemental_t *)p_supplemental_data)->sgx_type) == x509_scalableWithIntegrity)
      {
        out_platform_instance_id_byte_array = (*jenv)->NewByteArray(jenv, PLATFORM_INSTANCE_ID_SIZE);
        if (NULL == out_platform_instance_id_byte_array)
          return NULL;
        (*jenv)->SetByteArrayRegion(jenv, out_platform_instance_id_byte_array, 0, PLATFORM_INSTANCE_ID_SIZE, (const signed char *)(((sgx_ql_qv_supplemental_t *)p_supplemental_data)->platform_instance_id));
        dynamic_platform = ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->dynamic_platform;
        cached_keys = ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->cached_keys;
        smt_enabled = ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->smt_enabled;
      }

      //get sa_list
      if(NULL != ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->sa_list){
        sa_list = (*jenv)->NewStringUTF(jenv, ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->sa_list);
      }
      //call back constructor of Supplemental class
      obj_supplemental = (*jenv)->NewObject(jenv, cls_supplemental, meth_supplemental_init,
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->major_version,    //tricky code to set version, suppose version less than uint16_t
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->minor_version,
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->earliest_issue_date,
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->latest_issue_date,
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->earliest_expiration_date,
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->tcb_level_date_tag,
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->pck_crl_num,
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->root_ca_crl_num,
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->tcb_eval_ref_num,
      out_root_key_id_byte_array,
      out_pck_ppid_byte_array,
      obj_sgx_cpu_svn,
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->tcb_pce_isvsvn,
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->pce_id,
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->tee_type,
      ((sgx_ql_qv_supplemental_t *)p_supplemental_data)->sgx_type,
      out_platform_instance_id_byte_array,
      dynamic_platform,
      cached_keys,
      smt_enabled,
      sa_list
      );
    }


         // Get Supplemental class
      jclass cls_tee_supplemental =
          (*jenv)->FindClass(jenv, "com/intel/sgx/supplement/TeeSupplemental");
      if (NULL == cls_tee_supplemental) {
		  DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, "com/intel/sgx/supplement/TeeSupplemental");
        return NULL;
      }
      // Get the method ID of the constructor of Supplemental class
      jmethodID meth_tee_supplemental_init = (*jenv)->GetMethodID(
          jenv, cls_tee_supplemental, "<init>",
          "(SLcom/intel/sgx/supplement/Supplemental;)V");
      if (NULL == meth_tee_supplemental_init) {
        sprintf(exception_buf, "Can't find constructor function ");
		    DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, exception_buf);
        return NULL;
      }
      jobject obj_tee_supplemental = (*jenv)->NewObject(jenv, cls_tee_supplemental, meth_tee_supplemental_init, (uint16_t)latest_suppl_version, obj_supplemental);

  // call back constructor to allocate a new instance of SgxDcapQuoteVerifyResult
    jobject obj_dcap_quote_verify_result = (*jenv)->NewObject(
        jenv, cls_tee_dcap_quote_verify_result,
        meth_tee_dcap_quote_verify_result_init, qvl_ret, obj_collateral_expiration_status, obj_ql_qv_result, obj_qe_report, obj_tee_supplemental);

  (*jenv)->ReleaseByteArrayElements(jenv, quote, quote_array, 0);
  if (NULL != p_quote_collateral) {
    if (NULL != p_quote_collateral->pck_crl) {
      free(p_quote_collateral->pck_crl);
    }
    if (NULL != p_quote_collateral->pck_crl_issuer_chain) {
      free(p_quote_collateral->pck_crl_issuer_chain);
    }
    if (NULL != p_quote_collateral->qe_identity) {
      free(p_quote_collateral->qe_identity);
    }
    if (NULL != p_quote_collateral->qe_identity_issuer_chain) {
      free(p_quote_collateral->qe_identity_issuer_chain);
    }
    if (NULL != p_quote_collateral->tcb_info) {
      free(p_quote_collateral->tcb_info);
    }
    if (NULL != p_quote_collateral->tcb_info_issuer_chain) {
      free(p_quote_collateral->tcb_info_issuer_chain);
    }
    if (NULL != p_quote_collateral->root_ca_crl) {
      free(p_quote_collateral->root_ca_crl);
    }
    free(p_quote_collateral);
  }
  if (NULL != p_supplemental_data) {
    free(p_supplemental_data);
  }
  return obj_dcap_quote_verify_result;
}

          
JNIEXPORT jobject JNICALL Java_com_intel_sgx_SgxDcapVerifyQuoteJNI_tee_1get_1supplemental_1data_1version_1and_1size(JNIEnv *jenv, jobject jobj, jbyteArray quote)
{
    char exception_buf[BUFSIZ] = {'\0'};

  quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
  uint32_t supplemental_data_size = 0;
  uint32_t supplemental_data_version = 0;

  (void)jobj;
  if (NULL == qvl_tee_get_supplemental_data_version_and_size) {
    if (load_lib()){
      DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, "Unable to Link Error libsgx_dcap_quoteverify.so");
      return NULL;
    }
  }
  jclass jexceptionCls = (*jenv)->FindClass(jenv, "java/lang/Exception");
  if (NULL == jexceptionCls) {
    return NULL;
  }

  // critical error quote should not be NULL
  if (NULL == quote) {
		  DCAP_JavaThrowException(jenv, DCAP_JavaIllegalArgumentException, "quote parameter should not be NULL");
    return NULL;
  }
  // Convert byte array to char array
  jbyte *quote_array = (*jenv)->GetByteArrayElements(jenv, quote, NULL);
  if (NULL == quote_array) {
    return NULL;
  }
  jsize quote_size = (*jenv)->GetArrayLength(jenv, quote);

  // call tee_get_supplemental_data_version_and_size to get size and version
  dcap_ret = qvl_tee_get_supplemental_data_version_and_size((const uint8_t *)quote_array, (uint32_t)quote_size, &supplemental_data_version, &supplemental_data_size);
  if (SGX_QL_SUCCESS != dcap_ret) {
    if ((*jenv)->ExceptionCheck(jenv)) {
      (*jenv)->ExceptionClear(jenv);
      /* code to handle exception */
    }
    sprintf(exception_buf, "Get supplement data failed with 0x%x", dcap_ret);
	  DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, exception_buf);
    return NULL;
  }

  // Get supplementalResult class
  jclass cls_supplementResult =
      (*jenv)->FindClass(jenv, "com/intel/sgx/result/supplementalResult");
  if (NULL == cls_supplementResult) {
		  DCAP_JavaThrowException(jenv, DCAP_JavaRuntimeException, "Unable to find class com/intel/sgx/result/supplementalResult");
    return NULL;
  }
  // Get the method ID of the constructor of CollateralExpiration class
  jmethodID meth_supplementResult_init = (*jenv)->GetMethodID(
    jenv, cls_supplementResult, "<init>", "(II)V");
  if (NULL == meth_supplementResult_init) return NULL;
  // call back constructor to allocate a new instance of Collateral
  jobject obj_supplementResult = (*jenv)->NewObject(
        jenv, cls_supplementResult,
        meth_supplementResult_init, supplemental_data_version, supplemental_data_size);

  return obj_supplementResult;
}
#ifdef __cplusplus
}
#endif
