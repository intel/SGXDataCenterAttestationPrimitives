/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
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

#ifndef COLLATERAL_FILES_H_
#define COLLATERAL_FILES_H_


#ifndef INTERMEDIATE_CA_CRL
#define INTERMEDIATE_CA_CRL "../sampleData/intermediateCaCrl.pem"
#endif //INTERMEDIATE_CA_CRL

#ifndef PCK_CERT
#define PCK_CERT "../sampleData/pckCert.pem"
#endif //PCK_CERT

#ifndef PCK_SIGN_CHAIN
#define PCK_SIGN_CHAIN "../sampleData/pckSignChain.pem"
#endif //PCK_SIGN_CHAIN

#ifndef QUOTE
#ifndef _MSC_VER
#define QUOTE "../sampleData/quote.dat"
#else //_MSC_VER
#define QUOTE "../../../sampleData/quote.dat"
#endif //_MSC_VER
#endif //QUOTE

#ifndef ROOT_CA_CRL
#define ROOT_CA_CRL "../sampleData/rootCaCrl.pem"
#endif //ROOT_CA_CRL

#ifndef PCK_CRL
#define PCK_CRL "../sampleData/pckCrl.pem"
#endif //PCK_CRL

#ifndef TCBINFO
#define TCBINFO "../sampleData/tcbInfo.json"
#endif //TCBINFO

#ifndef TCB_SIGN_CHAIN
#define TCB_SIGN_CHAIN "../sampleData/tcbSignChain.pem"
#endif //TCB_SIGN_CHAIN

#ifndef QE_IDENTITY
#define QE_IDENTITY "../sampleData/qeIdentity.json"
#endif //QE_IDENTITY 

#ifndef QE_SIGN_CHAIN
#define QE_SIGN_CHAIN "../sampleData/qeSignChain.pem"
#endif //QE_SIGN_CHAIN


#endif //COLLATERAL_FILES_H_
