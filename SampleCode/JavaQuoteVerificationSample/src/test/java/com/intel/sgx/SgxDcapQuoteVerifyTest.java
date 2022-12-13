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

import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.intel.sgx.identity.QveIdentity;
import com.intel.sgx.result.SgxDcapQuoteVerifyResult;

import org.junit.Test;
/**
 * Unit test for simple App.
 */
public class SgxDcapQuoteVerifyTest {
    private int retExpected = 0;

    @Test
    public void testsgxQeGetTargetInfo() {
        SgxDcapVerifyQuoteJNI c = new SgxDcapVerifyQuoteJNI();
        QveIdentity qveidentity = c.sgxQvGetQveIdentity();
        assertNotNull(qveidentity);
    }

    @Test
    public void testsgxQvSetPath() {
        SgxDcapVerifyQuoteJNI c = new SgxDcapVerifyQuoteJNI();
        int ret = c.sgxQvSetPath(0, "/usr/lib/x86_64-linux-gnu/libsgx_qve.signed.so.1");
        assertEquals(retExpected, ret);
    }

    @Test
    public void testsgxQvSetEnclaveLoadPolicy() {
        SgxDcapVerifyQuoteJNI c = new SgxDcapVerifyQuoteJNI();
        int ret = c.sgxQvSetEnclaveLoadPolicy(0);
        assertEquals(retExpected, ret);
    }


    // @Test
    // //shoulbe be enable after set the quotePATH
    // public void testsgxQvVerifyQuote() {
    //     String quotePATH = <PATH TO QUOTE>;
    //     Path path = Paths.get(quotePATH);
    //     SgxDcapVerifyQuoteJNI c = new SgxDcapVerifyQuoteJNI();
    //     byte[] quoteBytes = null;
    //     try {
    //         quoteBytes = Files.readAllBytes(path);
    //         SgxDcapQuoteVerifyResult ret = c.sgxQvVerifyQuote(quoteBytes);
    //         assertEquals(retExpected, ret.getVerifyResult());
    //     } catch (IOException e) {
    //         // TODO Auto-generated catch block
    //         e.printStackTrace();
    //     }   
        
    // }

}
