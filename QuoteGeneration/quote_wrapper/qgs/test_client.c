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
#include "qgs_msg_lib.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>


static const unsigned HEADER_SIZE = 4;

#define HEX_DUMP_SIZE 16
static void print_hex_dump(const char *title, const char *prefix_str,
                           const uint8_t *buf, uint32_t len) {
    const uint8_t *ptr = buf;
    uint32_t i, rowsize = HEX_DUMP_SIZE;

    if (!len || !buf)
        return;

    fprintf(stdout, "\t\t%s", title);

    for (i = 0; i < len; i++) {
        if (!(i % rowsize))
            fprintf(stdout, "\n%s%.8x:", prefix_str, i);
        if (ptr[i] <= 0x0f)
            fprintf(stdout, " 0%x", ptr[i]);
        else
            fprintf(stdout, " %x", ptr[i]);
    }

    fprintf(stdout, "\n");
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    int s = -1;
    int ret = 0;

    uint8_t buf[4 * 1024] = {0};
    uint32_t msg_size = 0;
    uint32_t in_msg_size = 0;
    uint32_t recieved_bytes = 0;

    uint16_t tdqe_isvsvn;
    uint16_t pce_isvsvn;
    const uint8_t *p_platform_id = NULL;
    uint32_t platform_id_size = 0;
    const uint8_t *p_cpusvn = NULL;
    uint32_t cpusvn_size = 0;

    qgs_msg_error_t qgs_msg_ret = QGS_MSG_SUCCESS;
    qgs_msg_header_t *p_header = NULL;
    uint8_t *p_req = NULL;

    qgs_msg_ret = qgs_msg_gen_get_platform_info_req(&p_req, &msg_size);
    if (QGS_MSG_SUCCESS != qgs_msg_ret) {
        fprintf(stderr, "\nqgs_msg_gen_get_platform_info_req return 0x%x\n", qgs_msg_ret);
        ret = 1;
        goto ret_point;
    }

    buf[0] = (uint8_t)((msg_size >> 24) & 0xFF);
    buf[1] = (uint8_t)((msg_size >> 16) & 0xFF);
    buf[2] = (uint8_t)((msg_size >> 8) & 0xFF);
    buf[3] = (uint8_t)(msg_size & 0xFF);

    memcpy(buf + HEADER_SIZE, p_req, msg_size);
    qgs_msg_free(p_req);

    s = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (-1 == s) {
        fprintf(stderr, "\nsocket return 0x%x\n", qgs_msg_ret);
        ret = 1;
        goto ret_point;
    }
    struct sockaddr_vm vm_addr;
    memset(&vm_addr, 0, sizeof(vm_addr));
    vm_addr.svm_family = AF_VSOCK;
    vm_addr.svm_reserved1 = 0;
    vm_addr.svm_port = 4050;
    vm_addr.svm_cid = VMADDR_CID_HOST;
    if (connect(s, (struct sockaddr *)&vm_addr, sizeof(vm_addr))) {
        fprintf(stderr, "\nconnect error\n");
        ret = 1;
        goto ret_point;
    }

    // Write to socket
    if (HEADER_SIZE + msg_size != send(s, buf, HEADER_SIZE + msg_size, 0)) {
        fprintf(stderr, "\nsend error\n");
        ret = 1;
        goto ret_point;
    }

    // Read the response size header
    if (HEADER_SIZE != recv(s, buf, HEADER_SIZE, 0)) {
        fprintf(stderr, "\nrecv error\n");
        ret = 1;
        goto ret_point;
    }

    // decode the size
    for (unsigned i = 0; i < HEADER_SIZE; ++i) {
        in_msg_size = in_msg_size * 256 + ((buf[i]) & 0xFF);
    }

    if (sizeof(buf) - HEADER_SIZE < in_msg_size) {
        fprintf(stderr, "\nReply message body is too big");
        ret = 1;
        goto ret_point;
    }
    while( recieved_bytes < in_msg_size) {
        int recv_ret = (int)recv(s, buf + HEADER_SIZE + recieved_bytes,
                                    in_msg_size - recieved_bytes, 0);
        if (recv_ret < 0) {
            fprintf(stderr, "\nrecv return value < 0");
            ret = 1;
            goto ret_point;
        }
        recieved_bytes += (uint32_t)recv_ret;
    }

    qgs_msg_ret = qgs_msg_inflate_get_platform_info_resp(buf + HEADER_SIZE, in_msg_size,
        &tdqe_isvsvn, &pce_isvsvn, &p_platform_id, &platform_id_size, &p_cpusvn, &cpusvn_size);

    if (QGS_MSG_SUCCESS != qgs_msg_ret) {
        fprintf(stderr, "\nqgs_msg_inflate_get_platform_info_resp return 0x%x\n", qgs_msg_ret);
        ret = 1;
        goto ret_point;
    }

    // We've called qgs_msg_inflate_get_quote_resp, the message type should be GET_QUOTE_RESP
    p_header = (qgs_msg_header_t *)(buf + HEADER_SIZE);
    if (p_header->error_code != 0) {
        fprintf(stderr, "\nerror code in resp msg is 0x%x", p_header->error_code);
        ret = 1;
        goto ret_point;
    }
    fprintf(stdout, "\nPCE_ISVSVN: %d\tTDQE_ISVSVN: %d\n", pce_isvsvn, tdqe_isvsvn);
    print_hex_dump("\n\t\tQEID\n", " ", p_platform_id, platform_id_size);
    print_hex_dump("\n\t\tCPUSVN\n", " ", p_cpusvn, cpusvn_size);
    ret = 0;

ret_point:
    if (s >= 0) {
        close(s);
    }

    return ret;
}