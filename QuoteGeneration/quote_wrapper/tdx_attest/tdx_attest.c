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

#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include "tdx_attest.h"
#include "qgs_msg_lib.h"

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/types.h>
#include <linux/ioctl.h>
#include <sys/ioctl.h>
#include <fcntl.h>
// For strtoul
#include <limits.h>
#include <errno.h>
#include <syslog.h>
#include <assert.h>

#define TDX_ATTEST_DEV_PATH "/dev/tdx-guest"
#define CFG_FILE_PATH "/etc/tdx-attest.conf"
// TODO: Should include kernel header, but the header file are included by
// different package in differnt distro, and installed in different locations.
// So add these defines here. Need to remove them later when kernel header
// became stable.
#define TDX_CMD_GET_REPORT _IOWR('T', 0x01, __u64)
#define TDX_CMD_GET_QUOTE _IOR('T', 0x02, __u64)

/* TD Quote status codes */
#define GET_QUOTE_SUCCESS 0
#define GET_QUOTE_IN_FLIGHT 0xffffffffffffffff
#define GET_QUOTE_ERROR 0x8000000000000000
#define GET_QUOTE_SERVICE_UNAVAILABLE 0x8000000000000001

#ifdef DEBUG
#define TDX_TRACE                                          \
    do {                                                   \
        fprintf(stderr, "\n[%s:%d] ", __FILE__, __LINE__); \
        perror(NULL);                                      \
    }while(0)
#else
#define TDX_TRACE
#endif

struct tdx_report_req {
    __u8 subtype;
    __u64 reportdata;
    __u32 rpd_len;
    __u64 tdreport;
    __u32 tdr_len;
};

struct tdx_quote_hdr {
    /* Quote version, filled by TD */
    __u64 version;
    /* Status code of Quote request, filled by VMM */
    __u64 status;
    /* Length of TDREPORT, filled by TD */
    __u32 in_len;
    /* Length of Quote, filled by VMM */
    __u32 out_len;
    /* Actual Quote data or TDREPORT on input */
    __u64 data[0];
};

struct tdx_quote_req {
    __u64 buf;
    __u64 len;
};

static const unsigned HEADER_SIZE = 4;
static const size_t REQ_BUF_SIZE = 4 * 4 * 1024; // 4 pages
static const tdx_uuid_t g_intel_tdqe_uuid = {TDX_SGX_ECDSA_ATTESTATION_ID};

static unsigned int get_vsock_port(void)
{
    FILE *p_config_fd = NULL;
    char *p_line = NULL;
    char *p = NULL;
    size_t line_len = 0;
    long long_num = 0;
    unsigned int port = 0;

    p_config_fd = fopen(CFG_FILE_PATH, "r");
    if (NULL == p_config_fd) {
        TDX_TRACE;
        return 0;
    }
    while(-1 != getline(&p_line, &line_len, p_config_fd)) {
        char temp[11] = {0};
        int number = 0;
        int ret = sscanf(p_line, " %10[#]", temp);
        if (ret == 1) {
            continue;
        }
        /* leading or trailing white space are ignored, white space around '='
           are also ignored. The number should no longer than 10 characters.
           Trailing non-whitespace are not allowed. */
        ret = sscanf(p_line, " port = %10[0-9] %n", temp, &number);
        /* Make sure number is positive then make the cast. It's not likely to
           have a negtive value, just a defense-in-depth. The cast is used to
           suppress the -Wsign-compare warning. */
        if (ret == 1 && number > 0 && ((size_t)number < line_len)
            && !p_line[number]) {
            errno = 0;
            long_num = strtol(temp, &p, 10);
            if (p == temp) {
                TDX_TRACE;
                port = 0;
                break;
            }

            // make sure that no range error occurred
            if (errno == ERANGE || long_num > UINT_MAX) {
                TDX_TRACE;
                port = 0;
                break;
            }

            // range is ok, so we can convert to int
            port = (unsigned int)long_num & 0xFFFFFFFF;
            #ifdef DEBUG
            fprintf(stdout, "\nGet the vsock port number [%u]\n", port);
            #endif
            break;
        }
    }

    /* p_line is allocated by sscanf */
    free(p_line);
    fclose(p_config_fd);

    return port;
}

static tdx_attest_error_t get_tdx_report(
    int devfd,
    const tdx_report_data_t *p_tdx_report_data,
    tdx_report_t *p_tdx_report)
{
    if (-1 == devfd) {
        return TDX_ATTEST_ERROR_UNEXPECTED;
    }
    if (!p_tdx_report) {
        fprintf(stderr, "\nNeed to input TDX report.");
        return TDX_ATTEST_ERROR_INVALID_PARAMETER;
    }

    struct tdx_report_req req;
    uint8_t tdx_report[TDX_REPORT_SIZE] = {0};

    req.subtype = 0;
    req.reportdata = (__u64)p_tdx_report_data->d;
    req.rpd_len = TDX_REPORT_DATA_SIZE;
    req.tdreport = (__u64)tdx_report;
    req.tdr_len = TDX_REPORT_SIZE;

    if (-1 == ioctl(devfd, TDX_CMD_GET_REPORT, &req)) {
        TDX_TRACE;
        return TDX_ATTEST_ERROR_REPORT_FAILURE;
    }
    memcpy(p_tdx_report->d, tdx_report, sizeof(p_tdx_report->d));
    return TDX_ATTEST_SUCCESS;
}

tdx_attest_error_t tdx_att_get_quote(
    const tdx_report_data_t *p_tdx_report_data,
    const tdx_uuid_t *p_att_key_id_list,
    uint32_t list_size,
    tdx_uuid_t *p_att_key_id,
    uint8_t **pp_quote,
    uint32_t *p_quote_size,
    uint32_t flags)
{
    int s = -1;
    int devfd = -1;
    int use_tdvmcall = 1;
    uint32_t quote_size = 0;
    uint32_t recieved_bytes = 0;
    uint32_t in_msg_size = 0;
    unsigned int vsock_port = 0;
    tdx_attest_error_t ret = TDX_ATTEST_ERROR_UNEXPECTED;
    struct tdx_quote_hdr *p_get_quote_blob = NULL;
    uint8_t *p_blob_payload = NULL;
    tdx_report_t tdx_report;
    uint32_t msg_size = 0;

    qgs_msg_error_t qgs_msg_ret = QGS_MSG_SUCCESS;
    qgs_msg_header_t *p_header = NULL;
    uint8_t *p_req = NULL;
    const uint8_t *p_quote = NULL;
    const uint8_t *p_selected_id = NULL;
    uint32_t id_size = 0;

    if ((!p_att_key_id_list && list_size) ||
        (p_att_key_id_list && !list_size)) {
        ret = TDX_ATTEST_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }
    if (!pp_quote) {
        ret = TDX_ATTEST_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }
    if (flags) {
        //TODO: I think we need to have a runtime version to make this flag usable.
        ret = TDX_ATTEST_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    // Currently only intel TDQE are supported
    if (1 < list_size) {
        ret = TDX_ATTEST_ERROR_INVALID_PARAMETER;
    }
    if (p_att_key_id_list && memcmp(p_att_key_id_list, &g_intel_tdqe_uuid,
                    sizeof(g_intel_tdqe_uuid))) {
        ret = TDX_ATTEST_ERROR_UNSUPPORTED_ATT_KEY_ID;
    }
    *pp_quote = NULL;
    memset(&tdx_report, 0, sizeof(tdx_report));
    p_get_quote_blob = (struct tdx_quote_hdr *)malloc(REQ_BUF_SIZE);
    if (!p_get_quote_blob) {
        ret = TDX_ATTEST_ERROR_OUT_OF_MEMORY;
        goto ret_point;
    }

    devfd = open(TDX_ATTEST_DEV_PATH, O_RDWR | O_SYNC);
    if (-1 == devfd) {
        TDX_TRACE;
        ret = TDX_ATTEST_ERROR_DEVICE_FAILURE;
        goto ret_point;
    }

    ret = get_tdx_report(devfd, p_tdx_report_data, &tdx_report);
    if (TDX_ATTEST_SUCCESS != ret) {
        goto ret_point;
    }

    qgs_msg_ret = qgs_msg_gen_get_quote_req(tdx_report.d, sizeof(tdx_report.d),
        NULL, 0, &p_req, &msg_size);
    if (QGS_MSG_SUCCESS != qgs_msg_ret) {
        #ifdef DEBUG
        fprintf(stdout, "\nqgs_msg_gen_get_quote_req return 0x%x\n", qgs_msg_ret);
        #endif
        ret = TDX_ATTEST_ERROR_UNEXPECTED;
        goto ret_point;
    }

    if (msg_size > REQ_BUF_SIZE - sizeof(struct tdx_quote_hdr) - HEADER_SIZE) {
#ifdef DEBUG
        fprintf(stdout, "\nqmsg_size[%d] is too big\n", msg_size);
        #endif
        ret = TDX_ATTEST_ERROR_NOT_SUPPORTED;
        goto ret_point;
    }

    p_blob_payload = (uint8_t *)&p_get_quote_blob->data;
    p_blob_payload[0] = (uint8_t)((msg_size >> 24) & 0xFF);
    p_blob_payload[1] = (uint8_t)((msg_size >> 16) & 0xFF);
    p_blob_payload[2] = (uint8_t)((msg_size >> 8) & 0xFF);
    p_blob_payload[3] = (uint8_t)(msg_size & 0xFF);

    memcpy(p_blob_payload + HEADER_SIZE, p_req, msg_size);

    do {
        vsock_port = get_vsock_port();
        if (!vsock_port) {
            syslog(LOG_INFO, "libtdx_attest: fallback to tdvmcall mode.");
            break;
        }
        s = socket(AF_VSOCK, SOCK_STREAM, 0);
        if (-1 == s) {
            syslog(LOG_INFO, "libtdx_attest: fallback to tdvmcall mode.");
            break;
        }
        struct sockaddr_vm vm_addr;
        memset(&vm_addr, 0, sizeof(vm_addr));
        vm_addr.svm_family = AF_VSOCK;
        vm_addr.svm_reserved1 = 0;
        vm_addr.svm_port = vsock_port;
        vm_addr.svm_cid = VMADDR_CID_HOST;
        if (connect(s, (struct sockaddr *)&vm_addr, sizeof(vm_addr))) {
            syslog(LOG_INFO, "libtdx_attest: fallback to tdvmcall mode.");
            break;
        }

        // Write to socket
        if (HEADER_SIZE + msg_size != send(s, p_blob_payload,
            HEADER_SIZE + msg_size, 0)) {
            TDX_TRACE;
            ret = TDX_ATTEST_ERROR_VSOCK_FAILURE;
            goto ret_point;
        }

        // Read the response size header
        if (HEADER_SIZE != recv(s, p_blob_payload,
            HEADER_SIZE, 0)) {
            TDX_TRACE;
            ret = TDX_ATTEST_ERROR_VSOCK_FAILURE;
            goto ret_point;
        }

        // decode the size
        for (unsigned i = 0; i < HEADER_SIZE; ++i) {
            in_msg_size = in_msg_size * 256 + ((p_blob_payload[i]) & 0xFF);
        }

        // prepare the buffer and read the reply body
        #ifdef DEBUG
        fprintf(stdout, "\nReply message body is %u bytes", in_msg_size);
        #endif

        if (REQ_BUF_SIZE - sizeof(struct tdx_quote_hdr) - HEADER_SIZE < in_msg_size) {
            #ifdef DEBUG
            fprintf(stdout, "\nReply message body is too big");
            #endif
            ret = TDX_ATTEST_ERROR_UNEXPECTED;
            goto ret_point;
        }
        while( recieved_bytes < in_msg_size) {
            int recv_ret = (int)recv(s, p_blob_payload + HEADER_SIZE + recieved_bytes,
                                     in_msg_size - recieved_bytes, 0);
            if (recv_ret < 0) {
                ret = TDX_ATTEST_ERROR_VSOCK_FAILURE;
                goto ret_point;
            }
            recieved_bytes += (uint32_t)recv_ret;
        }
        #ifdef DEBUG
        fprintf(stdout, "\nGet %u bytes response from vsock", recieved_bytes);
        #endif
        use_tdvmcall = 0;
    } while (0);

    if (use_tdvmcall) {
        int ioctl_ret = 0;
        struct tdx_quote_req arg;
        p_get_quote_blob->version = 1;
        p_get_quote_blob->status = 0;
        p_get_quote_blob->in_len = HEADER_SIZE + msg_size;
        p_get_quote_blob->out_len = 0;
        arg.buf = (__u64)p_get_quote_blob;
        arg.len = REQ_BUF_SIZE;

        ioctl_ret = ioctl(devfd, TDX_CMD_GET_QUOTE, &arg);
        if (EBUSY == ioctl_ret) {
            TDX_TRACE;
            ret = TDX_ATTEST_ERROR_BUSY;
            goto ret_point;
        } else if (ioctl_ret) {
            TDX_TRACE;
            ret = TDX_ATTEST_ERROR_QUOTE_FAILURE;
            goto ret_point;
        }
        if (p_get_quote_blob->status
            || p_get_quote_blob->out_len <= HEADER_SIZE) {
            TDX_TRACE;
            if (GET_QUOTE_IN_FLIGHT == p_get_quote_blob->status) {
                ret = TDX_ATTEST_ERROR_BUSY;
            } else if (GET_QUOTE_SERVICE_UNAVAILABLE == p_get_quote_blob->status) {
                ret = TDX_ATTEST_ERROR_NOT_SUPPORTED;
            } else {
                ret = TDX_ATTEST_ERROR_UNEXPECTED;
            }
            goto ret_point;
        }

        //in_msg_size is the size of serialized response
        for (unsigned i = 0; i < HEADER_SIZE; ++i) {
            in_msg_size = in_msg_size * 256 + ((p_blob_payload[i]) & 0xFF);
        }
        if (in_msg_size != p_get_quote_blob->out_len - HEADER_SIZE) {
            TDX_TRACE;
            ret = TDX_ATTEST_ERROR_UNEXPECTED;
            goto ret_point;
        }
        #ifdef DEBUG
        fprintf(stdout, "\nGet %u bytes response from tdvmcall", in_msg_size);
        #endif
    }

    qgs_msg_ret = qgs_msg_inflate_get_quote_resp(
        p_blob_payload + HEADER_SIZE, in_msg_size,
        &p_selected_id, &id_size,
        &p_quote, &quote_size);
    if (QGS_MSG_SUCCESS != qgs_msg_ret) {
        #ifdef DEBUG
        fprintf(stdout, "\nqgs_msg_inflate_get_quote_resp return 0x%x", qgs_msg_ret);
        #endif
        ret = TDX_ATTEST_ERROR_UNEXPECTED;
        goto ret_point;
    }

    // We've called qgs_msg_inflate_get_quote_resp, the message type should be GET_QUOTE_RESP
    p_header = (qgs_msg_header_t *)(p_blob_payload + HEADER_SIZE);
    if (p_header->error_code != 0) {
        #ifdef DEBUG
        fprintf(stdout, "\nerror code in resp msg is 0x%x", p_header->error_code);
        #endif
        ret = TDX_ATTEST_ERROR_UNEXPECTED;
        goto ret_point;
    }
    *pp_quote = malloc(quote_size);
    if (!*pp_quote) {
        ret = TDX_ATTEST_ERROR_OUT_OF_MEMORY;
        goto ret_point;
    }
    memcpy(*pp_quote, p_quote, quote_size);
    if (p_quote_size) {
        *p_quote_size = quote_size;
    }
    if (p_att_key_id) {
        *p_att_key_id = g_intel_tdqe_uuid;
    }
    ret = TDX_ATTEST_SUCCESS;

ret_point:
    if (s >= 0) {
        close(s);
    }
    if (-1 != devfd) {
        close(devfd);
    }
    qgs_msg_free(p_req);
    free(p_get_quote_blob);

    return ret;
}

tdx_attest_error_t tdx_att_free_quote(
    uint8_t *p_quote)
{
    free(p_quote);
    return TDX_ATTEST_SUCCESS;
}

tdx_attest_error_t tdx_att_get_report(
    const tdx_report_data_t *p_tdx_report_data,
    tdx_report_t *p_tdx_report)
{
    int devfd;
    tdx_attest_error_t ret = TDX_ATTEST_SUCCESS;

    devfd = open(TDX_ATTEST_DEV_PATH, O_RDWR | O_SYNC);
    if (-1 == devfd) {
        TDX_TRACE;
        return TDX_ATTEST_ERROR_DEVICE_FAILURE;
    }

    ret = get_tdx_report(devfd, p_tdx_report_data, p_tdx_report);

    close(devfd);
    return ret;
}

tdx_attest_error_t tdx_att_get_supported_att_key_ids(
        tdx_uuid_t *p_att_key_id_list,
        uint32_t *p_list_size)
{
    if (!p_list_size) {
        return TDX_ATTEST_ERROR_INVALID_PARAMETER;
    }
    if (p_att_key_id_list && !*p_list_size) {
        return TDX_ATTEST_ERROR_INVALID_PARAMETER;
    }
    if (!p_att_key_id_list && *p_list_size) {
        return TDX_ATTEST_ERROR_INVALID_PARAMETER;
    }
    if (p_att_key_id_list) {
        p_att_key_id_list[0] = g_intel_tdqe_uuid;
    }
    *p_list_size = 1;
    return TDX_ATTEST_SUCCESS;
}

tdx_attest_error_t tdx_att_extend(
    const tdx_rtmr_event_t *p_rtmr_event)
{
#ifdef TDX_CMD_EXTEND_RTMR
    int devfd = -1;
    uint64_t extend_data_size = 0;
    if (!p_rtmr_event || p_rtmr_event->version != 1) {
        return TDX_ATTEST_ERROR_INVALID_PARAMETER;
    }
    if (p_rtmr_event->event_data_size) {
        return TDX_ATTEST_ERROR_NOT_SUPPORTED;
    }

    devfd = open(TDX_ATTEST_DEV_PATH, O_RDWR | O_SYNC);
    if (-1 == devfd) {
        TDX_TRACE;
        return TDX_ATTEST_ERROR_DEVICE_FAILURE;
    }

    if (-1 == ioctl(devfd, TDX_CMD_GET_EXTEND_SIZE, &extend_data_size)) {
        TDX_TRACE;
        close(devfd);
        return TDX_ATTEST_ERROR_EXTEND_FAILURE;
    }
    assert(extend_data_size == sizeof(p_rtmr_event->extend_data));
    if (-1 == ioctl(devfd, TDX_CMD_EXTEND_RTMR, &p_rtmr_event->rtmr_index)) {
        TDX_TRACE;
        close(devfd);
        if (EINVAL == errno) {
            return TDX_ATTEST_ERROR_INVALID_RTMR_INDEX;
        }
        return TDX_ATTEST_ERROR_EXTEND_FAILURE;
    }
    close(devfd);
    return TDX_ATTEST_SUCCESS;
#else
    (void)p_rtmr_event;
    return TDX_ATTEST_ERROR_NOT_SUPPORTED;
#endif
}
