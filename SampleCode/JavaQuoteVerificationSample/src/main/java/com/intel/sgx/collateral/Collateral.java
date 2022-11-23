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


package com.intel.sgx.collateral;

public class Collateral{
    private short major_version;
    private short minor_version;
    private int tee_type;
    
    private String pck_crl_issuer_chain;
//		int pck_crl_issuer_chain_size;
    
    private String root_ca_crl;
//		int root_ca_crl_size;
    
    private String pck_crl;
//		int pck_crl_size;
    
    private String tcb_info_issuer_chain;
//		int tcb_info_issuer_chain_size;

    private String tcb_info;
//		int tcb_info_size;

    private String qe_identity_issuer_chain;
//		int qe_identity_issuer_chain_size;

    private String qe_identity;
//		int qe_identity_size;

    public Collateral(short major_version, short minor_version, int tee_type, String pck_crl_issuer_chain,
            String root_ca_crl, String pck_crl, String tcb_info_issuer_chain, String tcb_info,
            String qe_identity_issuer_chain, String qe_identity) {
        this.major_version = major_version;
        this.minor_version = minor_version;
        this.tee_type = tee_type;
        this.pck_crl_issuer_chain = pck_crl_issuer_chain;
        this.root_ca_crl = root_ca_crl;
        this.pck_crl = pck_crl;
        this.tcb_info_issuer_chain = tcb_info_issuer_chain;
        this.tcb_info = tcb_info;
        this.qe_identity_issuer_chain = qe_identity_issuer_chain;
        this.qe_identity = qe_identity;
    }

    public short getMajor_version() {
        return major_version;
    }

    public short getMinor_version() {
        return minor_version;
    }

    public String getPck_crl() {
        return pck_crl;
    }

    public String getPck_crl_issuer_chain() {
        return pck_crl_issuer_chain;
    }

    public String getQe_identity() {
        return qe_identity;
    }

    public String getQe_identity_issuer_chain() {
        return qe_identity_issuer_chain;
    }

    public String getRoot_ca_crl() {
        return root_ca_crl;
    }

    public String getTcb_info() {
        return tcb_info;
    }

    public String getTcb_info_issuer_chain() {
        return tcb_info_issuer_chain;
    }

    public int getTee_type() {
        return tee_type;
    }

    @Override
	public String toString() {
		return "Collateral [major_version=" + major_version + ", minor_version=" + minor_version + ", tee_type="
				+ tee_type + ", pck_crl_issuer_chain=" + pck_crl_issuer_chain + ", root_ca_crl=" + root_ca_crl
				+ ", pck_crl=" + pck_crl + ", tcb_info_issuer_chain=" + tcb_info_issuer_chain + ", tcb_info=" + tcb_info
				+ ", qe_identity_issuer_chain=" + qe_identity_issuer_chain + ", qe_identity=" + qe_identity + "]";
	}

}
