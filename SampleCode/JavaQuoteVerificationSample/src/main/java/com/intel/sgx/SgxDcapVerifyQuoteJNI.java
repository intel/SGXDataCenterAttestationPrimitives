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


package com.intel.sgx;


import com.intel.sgx.identity.QveIdentity;
import com.intel.sgx.result.SgxDcapQuoteVerifyResult;
import com.intel.sgx.result.TeeDcapQuoteVerifyResult;
import com.intel.sgx.result.supplementalResult;
import com.intel.sgx.collateral.Collateral;


public class SgxDcapVerifyQuoteJNI {

  public SgxDcapVerifyQuoteJNI() {}


  public QveIdentity sgxQvGetQveIdentity() {
    QveIdentity qveidentity = sgx_qv_get_qve_identity();
    return qveidentity;
  }


  public int sgxQvSetPath(int type, String path) {
    return sgx_qv_set_path(type, path);
  }

  public int sgxQvSetEnclaveLoadPolicy(int policy) {
    return sgx_qv_set_enclave_load_policy(policy);
  }


  public SgxDcapQuoteVerifyResult sgxQvVerifyQuote(byte[] quoteBytes) {
    long expireTime = System.currentTimeMillis() / 1000;
    return sgxQvVerifyQuote(quoteBytes, expireTime);
  }

  public SgxDcapQuoteVerifyResult sgxQvVerifyQuote(byte[] quoteFilePath, long expireTime) {
    return sgxQvVerifyQuote(quoteFilePath, null, null, null, null, null,
                                 null, null, expireTime);
  }
  public SgxDcapQuoteVerifyResult sgxQvVerifyQuote(byte[] quoteBytes, byte[] pckBytes,
                                   byte[] pckIssuerBytes, byte[] tcbBytes,
                                   byte[] tcbIssuerBytes,
                                   byte[] qeIdentityBytes,
                                   byte[] qeIdentityIssuerBytes,
                                   byte[] rootCaBytes, long expirationData) {
    return sgx_qv_verify_quote(
        quoteBytes, pckBytes, pckIssuerBytes, tcbBytes, tcbIssuerBytes,
        qeIdentityBytes, qeIdentityIssuerBytes, rootCaBytes, expirationData);
  }

  public TeeDcapQuoteVerifyResult tee_verify_quote(byte[] quoteBytes) {
    long expireTime = System.currentTimeMillis() / 1000;
    short default_version = 0;
    int default_suppl_size = 0;
    return tee_verify_quote(quoteBytes, expireTime, default_version, default_suppl_size);
  }

  public TeeDcapQuoteVerifyResult tee_verify_quote(byte[] quoteBytes, short version, int suppl_size) {
    long expireTime = System.currentTimeMillis() / 1000;
    return tee_verify_quote(quoteBytes, expireTime, version, suppl_size);
  }

  public TeeDcapQuoteVerifyResult tee_verify_quote(byte[] quoteBytes, long expireTime, short version, int suppl_size) {
    return tee_verify_quote(quoteBytes, null, null, null, null, null,
                                 null, null, expireTime, version, suppl_size);
  }

  public Collateral teeQvGetCollateral(byte[] quoteBytes) {
    return tee_qv_get_collateral(quoteBytes);
  }

  static {

    try {
      System.loadLibrary("jni_dcap_quoteverify");
    } catch (UnsatisfiedLinkError e) {
      e.printStackTrace();
      System.exit(0);
    }
  }

  private native SgxDcapQuoteVerifyResult sgx_qv_verify_quote(
      byte[] quote, byte[] pckfile, byte[] pckissuer, byte[] tcb,
      byte[] tcbissuer, byte[] qeIdentity, byte[] qeIdentityissuer,
      byte[] rootCA, long expirationData);

  private native QveIdentity sgx_qv_get_qve_identity();

  private native int sgx_qv_set_path(int type, String path);

  private native int sgx_qv_set_enclave_load_policy(int policy);

  private native Collateral tee_qv_get_collateral(byte[] quote);

  private native TeeDcapQuoteVerifyResult tee_verify_quote(
    byte[] quote, byte[] pckfile, byte[] pckissuer, byte[] tcb,
    byte[] tcbissuer, byte[] qeIdentity, byte[] qeIdentityissuer,
    byte[] rootCA, long expirationData, short version, int suppl_size);

  private native supplementalResult tee_get_supplemental_data_version_and_size(byte[] quote);
}
