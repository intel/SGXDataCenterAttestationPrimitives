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


package com.intel.sgx.supplement;

import com.intel.sgx.report.SgxCpuSvn;

/**
 * 
 */
public class Supplemental {

	/**
	 * Supplemental data version
	 */
    private short major_version;
    private short minor_version;

    /**
     * Earliest issue date of all the collateral (UTC)
     */
    private long earliestIssueDate;

    /**
     * Latest issue date of all the collateral (UTC)
     */
    private long latestIssueDate;

    /**
     * Earliest expiration date of all the collateral (UTC)
     */
    private long earliestExpirationDate;

	/**
     * The SGX TCB of the platform that generated the quote is not vulnerable
	 * to any Security Advisory with an SGX TCB impact released on or before this date
	 * See Intel Security Center Advisories
     */
    private long tcbLevelDateTag;

    /**
     * CRL Num from PCK Cert CRL
     */
    private int pckCrlNum;

    /**
     * CRL Num from Root CA CRL
	 */
    private int rootCaCrlNum;

    /**
     * Lower number of the TCBInfo and QEIdentity
     */
    private int tcbEvalRefNum;

    /**
     * #define ROOT_KEY_ID_SIZE    48
	 * ID of the collateral's root signer (hash of Root CA's public key SHA-384)
     */
    private byte[] rootKeyId;

	/**
     * typedef uint8_t                    sgx_key_128bit_t[16]
	 * PPID from remote platform.  Can be used for platform ownership checks
     */
    private byte[] pckPPID;

	/**
     * CPUSVN of the remote platform's PCK Cert
     */
    private SgxCpuSvn tcb_cpusvn;

	/**
     * PCE_ISVNSVN of the remote platform's PCK Cert
     */
    private short tcbPceIsvsvn;

	/**
     * PCE_ID of the remote platform
     */
    private short pceId;

	/**
     *  0x00000000: SGX or 0x00000081: TDX
     */
    private int teeType;

	/**
     * Indicate the type of memory protection available on the platform, it should be one of
	 * Standard (0), Scalable (1) and Scalable with Integrity (2)
     */
    private byte sgxType;

	// Multi-Package PCK cert related flags, they are only relevant to PCK Certificates issued by PCK Platform CA
    /**
     * #define PLATFORM_INSTANCE_ID_SIZE    48
	 * IValue of Platform Instance ID, 16 bytes
     */
    private byte[] platformInstanceID;
	/**
	 * Indicate whether a platform can be extended with additional packages - via Package Add calls to SGX Registration Backend
	 */
	private int dynamicPlatform;

	/**
	 * Indicate whether platform root keys are cached by SGX Registration Backend
	 */
	private int cachedKeys;

	/**
	 * Indicate whether a plat form has SMT (simultaneous multithreading) enabled
	 */
	private int smtEnabled;


	//String of comma separated list of Security Advisory IDs

	private String saList;


	public Supplemental(short major_version, short minor_version, long earliestIssueDate, long latestIssueDate,
			long earliestExpirationDate, long tcbLevelDateTag, int pckCrlNum, int rootCaCrlNum, int tcbEvalRefNum,
			byte[] rootKeyId, byte[] pckPPID, SgxCpuSvn tcb_cpusvn, short tcbPceIsvsvn, short pceId, int teeType,
			byte sgxType, byte[] platformInstanceID, int dynamicPlatform, int cachedKeys, int smtEnabled,
			String saList) {
		super();
		this.major_version = major_version;
		this.minor_version = minor_version;
		this.earliestIssueDate = earliestIssueDate;
		this.latestIssueDate = latestIssueDate;
		this.earliestExpirationDate = earliestExpirationDate;
		this.tcbLevelDateTag = tcbLevelDateTag;
		this.pckCrlNum = pckCrlNum;
		this.rootCaCrlNum = rootCaCrlNum;
		this.tcbEvalRefNum = tcbEvalRefNum;
		this.rootKeyId = rootKeyId;
		this.pckPPID = pckPPID;
		this.tcb_cpusvn = tcb_cpusvn;
		this.tcbPceIsvsvn = tcbPceIsvsvn;
		this.pceId = pceId;
		this.teeType = teeType;
		this.sgxType = sgxType;
		this.platformInstanceID = platformInstanceID;
		this.dynamicPlatform = dynamicPlatform;
		this.cachedKeys = cachedKeys;
		this.smtEnabled = smtEnabled;
		this.saList = saList;
	}


	public int getCachedKeys() {
		return cachedKeys;
	}


	public int getDynamicPlatform() {
		return dynamicPlatform;
	}


	public long getEarliestExpirationDate() {
		return earliestExpirationDate;
	}


	public long getEarliestIssueDate() {
		return earliestIssueDate;
	}


	public long getLatestIssueDate() {
		return latestIssueDate;
	}


	public short getMajor_version() {
		return major_version;
	}


	public short getMinor_version() {
		return minor_version;
	}


	public short getPceId() {
		return pceId;
	}


	public int getPckCrlNum() {
		return pckCrlNum;
	}

	public byte[] getPckPPID() {
		return pckPPID;
	}

	public byte[] getPlatformInstanceID() {
		return platformInstanceID;
	}

	public int getRootCaCrlNum() {
		return rootCaCrlNum;
	}

	public byte[] getRootKeyId() {
		return rootKeyId;
	}

	public String getSaList() {
		return saList;
	}

	public byte getSgxType() {
		return sgxType;
	}

	public int getSmtEnabled() {
		return smtEnabled;
	}

	public SgxCpuSvn getTcb_cpusvn() {
		return tcb_cpusvn;
	}

	public int getTcbEvalRefNum() {
		return tcbEvalRefNum;
	}

	public long getTcbLevelDateTag() {
		return tcbLevelDateTag;
	}

	public short getTcbPceIsvsvn() {
		return tcbPceIsvsvn;
	}

	public int getTeeType() {
		return teeType;
	}
}
