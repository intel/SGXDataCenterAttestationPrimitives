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


package com.intel.sgx.result;

public enum SgxQlQvResult {
    SGX_QL_QV_RESULT_OK(0x0000), /// < The Quote verification passed and is at the latest TCB level
    SGX_QL_QV_RESULT_MIN(0xA001), 
    SGX_QL_QV_RESULT_CONFIG_NEEDED(0xA001), /// < The Quote verification passed and the
                                                                            /// platform is patched to
    /// < the latest TCB level but additional configuration of the SGX
    /// < platform may be needed
    SGX_QL_QV_RESULT_OUT_OF_DATE(0xA002), /// < The Quote is good but TCB level of the platform is out of date.
    /// < The platform needs patching to be at the latest TCB level
    SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED(0xA003), /// < The Quote is good but the TCB level of the platform is out
                                                        /// of
    /// < date and additional configuration of the SGX Platform at its
    /// < current patching level may be needed. The platform needs
    /// < patching to be at the latest TCB level
    SGX_QL_QV_RESULT_INVALID_SIGNATURE(0xA004), /// < The signature over the application report is invalid
    SGX_QL_QV_RESULT_REVOKED(0xA005), /// < The attestation key or platform has been revoked
    SGX_QL_QV_RESULT_UNSPECIFIED(0xA006), /// < The Quote verification failed due to an error in one of the input
    SGX_QL_QV_RESULT_SW_HARDENING_NEEDED(0xA007), /// < The TCB level of the platform is up to date, but SGX SW
                                                    /// Hardening
    /// < is needed
    SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED(0xA008), /// < The TCB level of the platform is up to date, but
                                                                /// additional
    /// < configuration of the platform at its current patching level
    /// < may be needed. Moreove, SGX SW Hardening is also needed

    SGX_QL_QV_RESULT_MAX(0xA0FF);

    private SgxQlQvResult(final int status) {
        this.status = status;
    }

    private int status;

    public int getQlQvResult() {
        return this.status;
    }

	public void setQlQvResult(int status) 
	{
		this.status = status;
	}

    public static SgxQlQvResult fromStatus(int status) {
        for (SgxQlQvResult type : values()) {
            if (type.getQlQvResult() == status) {
                return type;
            }
        }
        return null;
    }
}

