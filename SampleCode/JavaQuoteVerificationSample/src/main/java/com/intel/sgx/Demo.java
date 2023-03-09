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

import com.intel.sgx.collateral.Collateral;
import com.intel.sgx.result.SgxDcapQuoteVerifyResult;
import com.intel.sgx.result.TeeDcapQuoteVerifyResult;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;

/**
 * Demo for do quote verification and get quote collateral
 *
 */
public class Demo {
  public static void main(String[] args) throws IOException {
    byte[] quoteBytes = null;

    ArgumentParser parser =
        ArgumentParsers.newFor("Demo").build().defaultHelp(true);
    parser.addArgument("-q", "--quote")
        .required(true)
        .type(Arguments.fileType().acceptSystemIn().verifyCanRead())
        .help("Please specify quote path to do verify");
    try {
      Namespace ns = parser.parseArgs(args);
      File quote = ns.get("quote");
      quoteBytes = Files.readAllBytes(quote.toPath());
    } catch (ArgumentParserException e) {
      parser.handleError(e);
    }
    System.out.println("Do quote verfication:\n");
    SgxDcapVerifyQuoteJNI Verifer = new SgxDcapVerifyQuoteJNI();

    SgxDcapQuoteVerifyResult result = Verifer.sgxQvVerifyQuote(quoteBytes);
    System.out.println("Quote verify result is " + result.getVerifyResult());
    if (result.getSupplement() != null) {
      byte[] cpu_svn = result.getSupplement().getTcb_cpusvn().getSvn();
      for (int i = 0; i < cpu_svn.length; i++) {
        System.out.print(cpu_svn[i] + " ");
      }
    }

    System.out.println("Get quote collateral:\n");
    Collateral collat = Verifer.teeQvGetCollateral(quoteBytes);
    System.out.print(collat.toString());
    TeeDcapQuoteVerifyResult teeReult = Verifer.tee_verify_quote(quoteBytes, (short) 3, 0);
    System.out.print(teeReult.getSupplement().toString());

  }
}
