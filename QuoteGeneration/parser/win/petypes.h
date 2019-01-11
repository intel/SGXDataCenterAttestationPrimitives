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


#ifndef PETYPES_H__
#define PETYPES_H__

#include <stdint.h>
#include <binparser.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

/* Type-traits for PE types.  We are using PETypes<32> and PETypes<64>
 * to get the correct PE types to be used by the parser.
 */
template <int N>
class PETypes
{
};

template <>
class PETypes< 32 >
{
public:
    typedef IMAGE_NT_HEADERS32              image_nt_hdrs_t;
    typedef PIMAGE_NT_HEADERS32             pimage_nt_hdrs_t;
    typedef PIMAGE_OPTIONAL_HEADER32        pimage_opt_hdr_t;
    typedef IMAGE_LOAD_CONFIG_DIRECTORY32   image_load_config_directory;
    typedef PIMAGE_LOAD_CONFIG_DIRECTORY32  pimage_load_config_directory;
    typedef IMAGE_TLS_DIRECTORY32           image_tls_directory;
    typedef PIMAGE_TLS_DIRECTORY32          pimage_tls_directory;

    enum { IMAGE_REL_TYPE = IMAGE_REL_BASED_HIGHLOW, RELOC_BOUNDARY = 0xFFC };
    enum { FH_MACHINE = IMAGE_FILE_MACHINE_I386 };
    enum { OPT_MAGIC = IMAGE_NT_OPTIONAL_HDR32_MAGIC };
    enum { BIN_FORMAT = BF_PE32 };

    static bool check_dll(const pimage_nt_hdrs_t nt_hdr)
    {
        WORD Characteristics = nt_hdr->FileHeader.Characteristics & (~IMAGE_FILE_RELOCS_STRIPPED);
        if( ( Characteristics != (IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE | IMAGE_FILE_DLL) ) &&
                ( Characteristics != (IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_32BIT_MACHINE | IMAGE_FILE_DLL) ) )
        {
            return false;
        }

        return true;
    }
};

template <>
class PETypes< 64 >
{
public:
    typedef IMAGE_NT_HEADERS64              image_nt_hdrs_t;
    typedef PIMAGE_NT_HEADERS64             pimage_nt_hdrs_t;
    typedef PIMAGE_OPTIONAL_HEADER64        pimage_opt_hdr_t;
    typedef IMAGE_LOAD_CONFIG_DIRECTORY64   image_load_config_directory;
    typedef PIMAGE_LOAD_CONFIG_DIRECTORY64  pimage_load_config_directory;
    typedef IMAGE_TLS_DIRECTORY64           image_tls_directory;
    typedef PIMAGE_TLS_DIRECTORY64          pimage_tls_directory;

    enum { IMAGE_REL_TYPE = IMAGE_REL_BASED_DIR64, RELOC_BOUNDARY = 0xFF8 };
    enum { FH_MACHINE = IMAGE_FILE_MACHINE_AMD64 };
    enum { OPT_MAGIC = IMAGE_NT_OPTIONAL_HDR64_MAGIC };
    enum { BIN_FORMAT = BF_PE64 };

    static bool check_dll(const pimage_nt_hdrs_t nt_hdr)
    {
        WORD Characteristics = nt_hdr->FileHeader.Characteristics & (~IMAGE_FILE_RELOCS_STRIPPED);
        if(Characteristics != (IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_DLL))
        {
            return false;
        }

        return true;
    }
};

#endif
