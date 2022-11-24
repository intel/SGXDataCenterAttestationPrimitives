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


package com.intel.sgx.report;


/**
 * 
 */
public class SgxReport {

    /**
     * 
     */
    private SgxCpuSvn cpuSvn;

    /**
     * typedef uint32_t    sgx_misc_select_t;
     */
    private int miscSelect;

    /**
     * 
     */
    private byte[] IsvExtProdID;

    /**
     * 
     */
    private SgxAttributes attributes;

	/**
     * 
     */
    private SgxMeasurement mrEnclave;

	/**
     * 
     */
    private SgxMeasurement mrSigner;

	/**
     * 
     */
    private byte[] configID;

	/**
     * 
     */
    private short isvProdID;

	/**
     * 
     */
    private short isvSvn;

	/**
     * 
     */
    private short configSvn;

	/**
     * 
     */
    private byte[] isvFamilyID;

	/**
     * 
     */
    private SgxReportData reportData;

	/**
     * Default constructor
     */
    public SgxReport() {
    }

	public SgxAttributes getAttributes() {
		return attributes;
	}

	public byte[] getConfigID() {
		return configID;
	}

	public short getConfigSvn() {
		return configSvn;
	}

	public SgxCpuSvn getCpuSvn() {
		return cpuSvn;
	}

	public byte[] getIsvExtProdID() {
		return IsvExtProdID;
	}

	public byte[] getIsvFamilyID() {
		return isvFamilyID;
	}

	public short getIsvProdID() {
		return isvProdID;
	}

	public short getIsvSvn() {
		return isvSvn;
	}

	public int getMiscSelect() {
		return miscSelect;
	}

	public SgxMeasurement getMrEnclave() {
		return mrEnclave;
	}

	public SgxMeasurement getMrSigner() {
		return mrSigner;
	}

	public SgxReportData getReportData() {
		return reportData;
	}

	public void setAttributes(SgxAttributes attributes) {
		this.attributes = attributes;
	}

	public void setConfigID(byte[] configID) {
		this.configID = configID;
	}

	public void setConfigSvn(short configSvn) {
		this.configSvn = configSvn;
	}

    public void setCpuSvn(SgxCpuSvn cpuSvn) {
		this.cpuSvn = cpuSvn;
	}

    public void setIsvExtProdID(byte[] isvExtProdID) {
		IsvExtProdID = isvExtProdID;
	}

    public void setIsvFamilyID(byte[] isvFamilyID) {
		this.isvFamilyID = isvFamilyID;
	}

    public void setIsvProdID(short isvProdID) {
		this.isvProdID = isvProdID;
	}

    public void setIsvSvn(short isvSvn) {
		this.isvSvn = isvSvn;
	}

    public void setMiscSelect(int miscSelect) {
		this.miscSelect = miscSelect;
	}

    public void setMrEnclave(SgxMeasurement mrEnclave) {
		this.mrEnclave = mrEnclave;
	}

    public void setMrSigner(SgxMeasurement mrSigner) {
		this.mrSigner = mrSigner;
	}

    public void setReportData(SgxReportData reportData) {
		this.reportData = reportData;
	}

}
