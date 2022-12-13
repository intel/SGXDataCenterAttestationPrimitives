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

/* Header for class com_intel_sgx_SgxDcapVerifyQuoteJNI */
#include <jni.h>

#ifndef _Included_com_intel_sgx_SgxDcapVerifyQuoteJNI
#define _Included_com_intel_sgx_SgxDcapVerifyQuoteJNI
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_intel_sgx_SgxDcapVerifyQuoteJNI
 * Method:    sgx_qv_verify_quote
 * Signature: ([B[B[B[B[B[B[B[BJ)Lcom/intel/sgx/result/SgxDcapQuoteVerifyResult;
 */
JNIEXPORT jobject JNICALL Java_com_intel_sgx_SgxDcapVerifyQuoteJNI_sgx_1qv_1verify_1quote
  (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jlong);

/*
 * Class:     com_intel_sgx_SgxDcapVerifyQuoteJNI
 * Method:    sgx_qv_get_qve_identity
 * Signature: ()Lcom/intel/sgx/identity/QveIdentity;
 */
JNIEXPORT jobject JNICALL Java_com_intel_sgx_SgxDcapVerifyQuoteJNI_sgx_1qv_1get_1qve_1identity
  (JNIEnv *, jobject);

/*
 * Class:     com_intel_sgx_SgxDcapVerifyQuoteJNI
 * Method:    sgx_qv_set_path
 * Signature: (ILjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_com_intel_sgx_SgxDcapVerifyQuoteJNI_sgx_1qv_1set_1path
  (JNIEnv *, jobject, jint, jstring);

/*
 * Class:     com_intel_sgx_SgxDcapVerifyQuoteJNI
 * Method:    sgx_qv_set_enclave_load_policy
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_com_intel_sgx_SgxDcapVerifyQuoteJNI_sgx_1qv_1set_1enclave_1load_1policy
  (JNIEnv *, jobject, jint);

/*
 * Class:     com_intel_sgx_SgxDcapVerifyQuoteJNI
 * Method:    tee_qv_get_collateral
 * Signature: ([B)Lcom/intel/sgx/collateral/Collateral;
 */
JNIEXPORT jobject JNICALL Java_com_intel_sgx_SgxDcapVerifyQuoteJNI_tee_1qv_1get_1collateral
  (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     com_intel_sgx_SgxDcapVerifyQuoteJNI
 * Method:    tee_verify_quote
 * Signature: ([B[B[B[B[B[B[B[BJSI)Lcom/intel/sgx/result/TeeDcapQuoteVerifyResult;
 */
JNIEXPORT jobject JNICALL Java_com_intel_sgx_SgxDcapVerifyQuoteJNI_tee_1verify_1quote
  (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jlong, jshort, jint);

/*
 * Class:     com_intel_sgx_SgxDcapVerifyQuoteJNI
 * Method:    tee_get_supplemental_data_version_and_size
 * Signature: ([B)Lcom/intel/sgx/result/supplementalResult;
 */
JNIEXPORT jobject JNICALL Java_com_intel_sgx_SgxDcapVerifyQuoteJNI_tee_1get_1supplemental_1data_1version_1and_1size
  (JNIEnv *, jobject, jbyteArray);

#ifdef __cplusplus
}
#endif
#endif
