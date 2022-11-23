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

import com.intel.sgx.collateral.CollateralExpiration;
import com.intel.sgx.report.SgxQlQeReportInfo;
import com.intel.sgx.supplement.Supplemental;

public class SgxDcapQuoteVerifyResult {
  //
  private int verifyResult;
  private CollateralExpiration collExpire;
  private SgxQlQvResult qlQvResult;

  private SgxQlQeReportInfo qeReport;

  private Supplemental supplement;

  public SgxDcapQuoteVerifyResult(int verifyResult,
                                  CollateralExpiration collExpire,
                                  SgxQlQvResult qlQvResult,
                                  SgxQlQeReportInfo qeReport,
                                  Supplemental supplement) {

    this.verifyResult = verifyResult;
    this.collExpire = collExpire;
    this.qlQvResult = qlQvResult;
    this.qeReport = qeReport;
    this.supplement = supplement;
  }

  public CollateralExpiration getCollExpire() { return collExpire; }
  public SgxQlQeReportInfo getQeReport() { return qeReport; }

  public SgxQlQvResult getQlQvResult() { return qlQvResult; }

  public Supplemental getSupplement() { return supplement; }

  public int getVerifyResult() { return verifyResult; }

  public void setCollExpire(CollateralExpiration collExpire) {
    this.collExpire = collExpire;
  }

  public void setQeReport(SgxQlQeReportInfo qeReport) {
    this.qeReport = qeReport;
  }

  public void setQlQvResult(SgxQlQvResult qlQvResult) {
    this.qlQvResult = qlQvResult;
  }

  public void setSupplement(Supplemental supplement) {
    this.supplement = supplement;
  }

  public void setVerifyResult(int verifyResult) {
    this.verifyResult = verifyResult;
  }
}
