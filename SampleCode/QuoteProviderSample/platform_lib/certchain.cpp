/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
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
/*
 * File: platform.cpp
 *
 * Description: Sample platform library
 */


#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "certchain.h"

#define BREAK_IF(con, retcode) 	\
	if (con)		\
	{			\
		ret = retcode;	\
		break;		\
	}

#define GET_FILE_SIZE(pfile, size) 	\
	do				\
	{				\
		fseek(pfile, 0L, SEEK_END);	\
		size = ftell(pfile);		\
		fseek(pfile, 0L, SEEK_SET);	\
	}while(0);

#define SAFE_FREE(p) do { if(p) {free(p); (p) = NULL;} } while(0);

static sgx_cpu_svn_t m_pckcert_cpusvn =
{
	        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}
};

static sgx_isv_svn_t m_pckcert_pce_isvsvn = 0;

int reversecert(char * chain, size_t len, char ** reversedbuf)
{
	/* split the content*/
	const char* begCert = "-----BEGIN CERTIFICATE-----";
        const char* endCert = "-----END CERTIFICATE-----";

	assert(chain != NULL && len > 0 && reversedbuf != NULL);

        const char* begPos_1 = strstr(chain, begCert);
        const char* endPos_1 = strstr(chain, endCert);
	if (!begPos_1 || !endPos_1){
		return CERT_ERROR_FILE_ACCESS;
	}

	unsigned int certsize1 = endPos_1 + strlen(endCert) + 1 - begPos_1;

	const char* newPos = endPos_1 + strlen(endCert);
	const char* begPos_2 = strstr(newPos, begCert);
        const char* endPos_2 = strstr(newPos, endCert);
        unsigned int certsize2 = endPos_2 + strlen(endCert) + 1 - begPos_2;
	if (!begPos_1 || !endPos_1){
		return CERT_ERROR_FILE_ACCESS;
	}

	char *certbuf = (char*)malloc(len);
	if (!certbuf){
		return CERT_ERROR_UNEXPECTED;
	}

	memcpy(certbuf, begPos_2, certsize2);
	memcpy(certbuf + certsize2, begPos_1, certsize1);

	*reversedbuf = certbuf;

	return CERT_SUCCESS;	
}

int getpckchain(char **certchain, size_t &size, sgx_cpu_svn_t * cpusvn, sgx_isv_svn_t *pce_isvsvn)
{
	size_t chainsize, certsize;
	char * tmp = NULL, *chainbuf = NULL, *certbuf = NULL;
	int ret = CERT_SUCCESS;

	assert((certchain != NULL) && (cpusvn != NULL) &&(pce_isvsvn != NULL));

	FILE *fleafcert = fopen(PCKCERT_FILE, "rb");
	if (!fleafcert)
		return CERT_ERROR_FILE_ACCESS;

	FILE *fchain = fopen(CERTCHAIN_FILE, "rb");
	if (!fchain){
		fclose(fleafcert);
		return CERT_ERROR_FILE_ACCESS;
	}

	GET_FILE_SIZE(fleafcert, certsize);	
	GET_FILE_SIZE(fchain, chainsize);

	do
	{
		tmp = (char *)malloc(chainsize);
		BREAK_IF(tmp == NULL, CERT_ERROR_UNEXPECTED);

		BREAK_IF(fread(tmp, 1, chainsize, fchain) != chainsize, CERT_ERROR_FILE_ACCESS);

		BREAK_IF(reversecert(tmp, chainsize, &chainbuf) != CERT_SUCCESS, CERT_ERROR_UNEXPECTED);

		size = chainsize + certsize;

		certbuf = (char *)malloc(size);
		BREAK_IF(certbuf == NULL, CERT_ERROR_UNEXPECTED);

		BREAK_IF(fread(certbuf, 1, certsize, fleafcert) != certsize, CERT_ERROR_FILE_ACCESS);
		
		memcpy(certbuf + certsize, chainbuf, chainsize);
		
		*certchain = certbuf;

		memcpy(cpusvn, &m_pckcert_cpusvn, sizeof(sgx_cpu_svn_t));
		memcpy(pce_isvsvn, &m_pckcert_pce_isvsvn, sizeof(sgx_isv_svn_t));
	}while (0);

	fclose(fleafcert);
	fclose(fchain);
	SAFE_FREE(tmp);
	SAFE_FREE(chainbuf);

	return ret;
}
