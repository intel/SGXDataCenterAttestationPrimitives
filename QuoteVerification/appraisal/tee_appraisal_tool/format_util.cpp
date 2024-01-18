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

#include <string>
#include <iostream>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "se_trace.h"
#include "format_util.h"
// transfer Byte to hex string
std::string bytes_to_string(const uint8_t *data, size_t len)
{
    std::string result;
    result.reserve(len * 2); // two digits per character

    static constexpr char hex[] = "0123456789ABCDEF";

    for (; len > 0; len--)
    {
        result.push_back(hex[data[len - 1] / 16]);
        result.push_back(hex[data[len - 1] % 16]);
    }

    return result;
}

// time transfer to ISO 8601 standard (YYYY-MM-DDThh:mm:ssZ)
void time_to_string(time_t time_before, char *time_str, size_t len)
{
    if (time_str == NULL)
    {
        return;
    }
    struct tm *nowtm;
    // transfer UTC to gmtime
    nowtm = gmtime(&time_before);
    // transfer to ISO 8601 standard (YYYY-MM-DDThh:mm:ssZ)
    if (nowtm == NULL)
    {
        return;
    }
    strftime(time_str, len, "%Y-%m-%dT%H:%M:%SZ", nowtm);
    return;
}

std::string base64url_encode(const std::string &in)
{
    static const char base64_url_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                            'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                            'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'};
    std::string out = "";
    if (in.length() == 0)
        return out;
    size_t i = 0;
    if (in.length() >= 3)
    {
        for (; i < in.length() - 2; i += 3)
        {
            out += base64_url_table[(in[i] >> 2) & 0x3F];
            out += base64_url_table[((in[i] & 0x3) << 4) | ((int)(in[i + 1] & 0xF0) >> 4)];
            out += base64_url_table[((in[i + 1] & 0xF) << 2) | ((int)(in[i + 2] & 0xC0) >> 6)];
            out += base64_url_table[in[i + 2] & 0x3F];
        }
    }
    if (i < in.length())
    {
        out += base64_url_table[(in[i] >> 2) & 0x3F];
        if (i == in.length() - 1)
        {
            out += base64_url_table[((in[i] & 0x3) << 4)];
        }
        else
        {
            out += base64_url_table[((in[i] & 0x3) << 4) | ((int)(in[i + 1] & 0xF0) >> 4)];
            out += base64_url_table[((in[i + 1] & 0xF) << 2)];
        }
    }
    return out;
}