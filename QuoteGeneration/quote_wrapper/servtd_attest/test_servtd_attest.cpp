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
/* This is the file for testing ServTD Attestation Lib in TD Guest OS */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <fstream>
#include <iostream>
#include <string.h>
#include <string>
#include <vector>

#include "servtd_external.h"
#include "servtd_com.h"
#include "servtd_attest.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define TDX_ATTEST_DEV_PATH     "/dev/tdx_guest"
#define TDX_CMD_GET_REPORT0     _IOWR('T', 1, struct tdx_report_req)
#define TDX_CMD_GET_QUOTE       _IOR('T', 4, struct tdx_quote_req)

#define HEX_DUMP_SIZE 16

#define TDX_REPORT_DATA_SIZE 64
#define MAX_QUOTE_SIZE 8096

#pragma pack(push, 1)
typedef struct _tdx_report_data_t
{
    uint8_t d[TDX_REPORT_DATA_SIZE];
} tdx_report_data_t;

struct tdx_report_req {
    __u8 reportdata[TDX_REPORT_DATA_SIZE];
    __u8 tdreport[TDX_REPORT_SIZE];
};

struct tdx_quote_req {
    __u64 buf;
    __u64 len;
};
#pragma pack(pop)

static void print_hex_dump(const char* title, const char* prefix_str,
                           const uint8_t* buf, int len)
{
    const uint8_t* ptr = buf;
    int i, rowsize = HEX_DUMP_SIZE;

    if (!len || !buf)
        return;

    fprintf(stdout, "\t\t%s", title);

    for (i = 0; i < len; i++)
    {
        if (!(i % rowsize))
            fprintf(stdout, "\n%s%.8x:", prefix_str, i);
        if (ptr[i] <= 0x0f)
            fprintf(stdout, " 0%x", ptr[i]);
        else
            fprintf(stdout, " %x", ptr[i]);
    }

    fprintf(stdout, "\n");
}

static bool get_tdx_report(void* p_tdx_report)
{
    bool ret = false;
    if (NULL == p_tdx_report)
    {
        return ret;
    }

    int devfd = -1;
    struct tdx_report_req req = {0};
    tdx_report_data_t report_data = {{0}};
    uint8_t tdx_report[TDX_REPORT_SIZE] = {0};

    memcpy(req.reportdata, report_data.d, sizeof(req.reportdata));

    devfd = open(TDX_ATTEST_DEV_PATH, O_RDWR | O_SYNC);
    if (-1 == devfd)
    {
        perror(NULL);
        goto ret_point;
    }

    if (-1 == ioctl(devfd, TDX_CMD_GET_REPORT0, &req))
    {
        perror(NULL);
        goto ret_point;
    }
    
    memcpy(p_tdx_report, req.tdreport, sizeof(req.tdreport));
    ret = true;

ret_point:
    if (-1 != devfd)
    {
        close(devfd);
    }
    return true;
}

std::vector<uint8_t> readBinaryContent(const std::string& filePath)
{
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open())
    {
        printf("Error: Unable to open quote file %s\n", filePath.data());
        return {};
    }

    file.seekg(0, std::ios_base::end);
    std::streampos fileSize = file.tellg();

    file.seekg(0, std::ios_base::beg);
    std::vector<uint8_t> retVal(fileSize);
    file.read(reinterpret_cast<char*>(retVal.data()), fileSize);
    file.close();
    return retVal;
}

/**
 *  servtd_get_quote is the interface provided by ServTD Core to invoke TDVMCALL<Get_Quote> during ServTD env.
 *  Here for testing in TD Guest OS, it will call the IOCTL inteface provided by TD Guest OS
 **/
int servtd_get_quote(const void* p_get_quote_blob, const uint64_t len)
{
    int devfd = -1;
    int ret = -1;
    struct tdx_quote_req arg;

    if (NULL == p_get_quote_blob || len > SERVTD_REQ_BUF_SIZE)
    {
        goto ret_point;
    }
    
    devfd = open(TDX_ATTEST_DEV_PATH, O_RDWR | O_SYNC);
    if (-1 == devfd)
    {
        perror(NULL);
        goto ret_point;
    }

    arg.buf = (__u64)p_get_quote_blob;
    arg.len = len;

    ret = ioctl(devfd, TDX_CMD_GET_QUOTE, &arg);
    if (0 != ret)
    {
        perror(NULL);
        goto ret_point;
    }
    ret = 0;

ret_point:
    if (-1 != devfd)
    {
        close(devfd);
    }
    return ret;
}

// need to alloc enough heap for attest lib to use
#define TEST_HEAP_SIZE (HEAP_PAGE_SIZE * 0x100)
static uint8_t test_heap_base[TEST_HEAP_SIZE] __attribute__((aligned(0x1000)));

static void initialize_heap()
{
    servtd_attest_error_t status = init_heap(test_heap_base, TEST_HEAP_SIZE);
    if (SERVTD_ATTEST_SUCCESS != status)
        printf("Failed to %s with heap_size = 0x%x\n", __FUNCTION__, TEST_HEAP_SIZE);
    printf("Successful to %s with heap_size = 0x%x\n", __FUNCTION__, TEST_HEAP_SIZE);
}

__attribute__((section(".preinit_array"), used)) static void(*preinit_func)(void) = &initialize_heap;

int main(int argc, char* argv[])
{
    int ret = 0;

    FILE* fptr_report = NULL;
    void* p_tdx_report = NULL;
    bool get_td_report_status = false;

    FILE* fptr_quote = NULL;
    void* p_td_quote = NULL;
    uint32_t quote_size = 0;
    servtd_attest_error_t get_quote_status = SERVTD_ATTEST_ERROR_UNEXPECTED;

    FILE* fptr_report_body = NULL;
    void* p_tdx_servtd_suppl_data = NULL;
    // Intel Root Public Key
    uint8_t INTEL_ROOT_PUB_KEY[] = {
	    0x04, 0x4f, 0xfa, 0x0f, 0xfd, 0x56, 0x1c, 0xda, 0xd6, 0xc0, 0xf9, 0x8d, 0x30, 0x8c, 0x81,
        0x28, 0xc5, 0xb9, 0x27, 0xa2, 0x73, 0x32, 0xc8, 0xe8, 0xeb, 0x13, 0xf6, 0xbe, 0x42, 0xb5,
        0x71, 0xd6, 0x46, 0x6f, 0x53, 0xc6, 0x44, 0xff, 0xc2, 0xff, 0xc1, 0x02, 0x82, 0x20, 0xe4,
        0x9a, 0x49, 0x66, 0xcf, 0x02, 0xf3, 0x2e, 0x2f, 0xb4, 0xd3, 0x49, 0xbb, 0x2c, 0xba, 0xed,
        0x28, 0x90, 0x37, 0xa0, 0x2d};

    uint32_t tdx_servtd_suppl_data_size = 0;
    servtd_attest_error_t verify_status = SERVTD_ATTEST_ERROR_UNEXPECTED;

    std::vector<uint8_t> quote = {0};
    // 1. get td report
    p_tdx_report = malloc(TDX_REPORT_SIZE);
    if (NULL == p_tdx_report)
    {
        fprintf(stderr, "\nFailed to malloc TD report\n");
        ret = 1;
        goto ret_point;
    }
    memset(p_tdx_report, 0, TDX_REPORT_SIZE);

    get_td_report_status = get_tdx_report(p_tdx_report);
    if (!get_td_report_status)
    {
        fprintf(stderr, "\nFailed to get TD report\n");
        ret = 1;
        goto ret_point;
    }

    print_hex_dump("\n\t\tTD report Info\n", " ", (uint8_t*)p_tdx_report,
                   TDX_REPORT_SIZE);
    fprintf(stdout, "\nSuccessfully get the TD Report\n");

    // store td report in file
    fptr_report = fopen("report.dat", "wb");
    if (!fptr_report)
    {
        fprintf(stderr, "\nFailed to open report.dat\n");
        ret = 1;
        goto ret_point;
    }
    fwrite(p_tdx_report, TDX_REPORT_SIZE, 1, fptr_report);
    fclose(fptr_report);
    fptr_report= NULL;
    fprintf(stdout, "\nWrote TD Report to report.dat\n");

    // 2. get td quote
    quote_size = MAX_QUOTE_SIZE;
    p_td_quote = malloc(quote_size);
    if (NULL == p_td_quote)
    {
        fprintf(stderr, "\nFailed to malloc TD quote\n");
        ret = 1;
        goto ret_point;
    }
    memset(p_td_quote, 0, quote_size);

    get_quote_status =
        get_quote(p_tdx_report, TDX_REPORT_SIZE, p_td_quote, &quote_size);
    if (SERVTD_ATTEST_SUCCESS != get_quote_status)
    {
        fprintf(stderr, "\nFailed to get TD quote\n");
        ret = 1;
        goto ret_point;
    }

    print_hex_dump("\n\t\tTD quote data\n", " ", (uint8_t*)p_td_quote,
                   quote_size);
    fprintf(stdout, "\nSuccessfully get the TD Quote\n");

    // store td quote in file
    fptr_quote = fopen("quote.dat", "wb");
    if (!fptr_quote)
    {
        fprintf(stderr, "\nFailed to open quote.dat\n");
        ret = 1;
        goto ret_point;
    }
    fwrite(p_td_quote, quote_size, 1, fptr_quote);
    fclose(fptr_quote);
    fptr_quote = NULL;
    fprintf(stdout, "\nWrote TD Quote to quote.dat\n");

	// 3. verify td quote integrity
	quote = readBinaryContent("quote.dat");

	tdx_servtd_suppl_data_size = TDX_MIGR_SUPPL_DATA_SIZE;
	p_tdx_servtd_suppl_data = malloc(tdx_servtd_suppl_data_size);
	if (NULL == p_tdx_servtd_suppl_data) {
        fprintf(stderr, "\nFailed to malloc buff for supplemental data\n");
		ret = 1;
		goto ret_point;
	}
	memset(p_tdx_servtd_suppl_data, 0, tdx_servtd_suppl_data_size);
    
	verify_status = verify_quote_integrity(quote.data(), (int)quote.size(), 
				INTEL_ROOT_PUB_KEY, sizeof(INTEL_ROOT_PUB_KEY),
				p_tdx_servtd_suppl_data, &tdx_servtd_suppl_data_size);
    
    if(SERVTD_ATTEST_SUCCESS != verify_status) {
        fprintf(stderr, "\nFailed to verify TD quote\n");
		ret = 1;
		goto ret_point;
    }

	print_hex_dump("\n\t\tTD report by verify_quote_integrity\n", " ", (uint8_t *)p_tdx_servtd_suppl_data, tdx_servtd_suppl_data_size);
    fprintf(stdout, "\nSuccessfully get the TD Report Info\n");

	// store td report info in file
    fptr_report_body = fopen("report_verify.dat","wb");
    if(!fptr_report_body)
    {
        fprintf(stderr, "\nFailed to open report_verify.dat\n");
        ret = 1;
        goto ret_point;
    }
    fwrite(p_tdx_servtd_suppl_data, tdx_servtd_suppl_data_size, 1, fptr_report_body);
    fclose(fptr_report_body);
    fptr_report_body = NULL;
    fprintf(stdout, "\nWrote TD Report Info to report_body.dat\n");

    ret = 0;

ret_point:

    if (p_tdx_report)
    {
        free(p_tdx_report);
        p_tdx_report = NULL;
    }

    if (p_td_quote)
    {
        free(p_td_quote);
        p_td_quote = NULL;
    }

    if (p_tdx_servtd_suppl_data)
    {
        free(p_tdx_servtd_suppl_data);
        p_tdx_servtd_suppl_data = NULL;
    }

    return ret;
}
