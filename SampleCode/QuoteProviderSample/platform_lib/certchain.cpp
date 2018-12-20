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

int getpckchain(char **certchain, size_t &size, sgx_cpu_svn_t * cpusvn, sgx_isv_svn_t *pce_isvsvn)
{
	size_t chainsize, certsize;
	char *certbuf = NULL;
	int ret = CERT_SUCCESS;

	assert((certchain != NULL) && (cpusvn != NULL) &&(pce_isvsvn != NULL));

	FILE *fleafcert = fopen(PCKCERT_FILE, "rb");
	if (NULL == fleafcert)
		return CERT_ERROR_FILE_ACCESS;

	FILE *fchain = fopen(CERTCHAIN_FILE, "rb");
	if (NULL == fchain) {
		fclose(fleafcert);
		return CERT_ERROR_FILE_ACCESS;
	}

	GET_FILE_SIZE(fleafcert, certsize);	
	GET_FILE_SIZE(fchain, chainsize);

	do
	{		
		size = chainsize + certsize;

		certbuf = (char *)malloc(size);
		BREAK_IF(certbuf == NULL, CERT_ERROR_UNEXPECTED);

		BREAK_IF(fread(certbuf, 1, certsize, fleafcert) != certsize, CERT_ERROR_FILE_ACCESS);

		BREAK_IF(fread(certbuf + certsize, 1, chainsize, fchain) != chainsize, CERT_ERROR_FILE_ACCESS);
				
		*certchain = certbuf;

		memcpy(cpusvn, &m_pckcert_cpusvn, sizeof(sgx_cpu_svn_t));
		memcpy(pce_isvsvn, &m_pckcert_pce_isvsvn, sizeof(sgx_isv_svn_t));
	}while (0);

	fclose(fleafcert);
	fclose(fchain);
	
	return ret;
}
