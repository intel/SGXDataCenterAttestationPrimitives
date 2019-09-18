/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
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
/**
 * File: pce_parser.cpp 
 *  
 * Description: Wrapper functions for the 
 * reference implementing the PCE
 * function defined in sgx_pce.h. This
 * would be replaced or used to wrap the
 * PSW defined interfaces to the PCE.
 *
 */

#include <stdio.h>
#include <tchar.h>
#include "se_trace.h"
#include "se_map.h"
#include "sgx_urts.h"
#include "binparser.h"
#ifndef PARSER
#if defined(_MSC_VER)
#include "peparser.h"
#define PARSER PEParserT<sizeof(size_t) * 8>
#endif
#endif
#include "metadata.h"
#include "sgx_attributes.h"

static bool get_metadata(BinParser *parser, metadata_t *metadata)
{
    if (parser == NULL || metadata == NULL)
        return false;
    memset(metadata, 0, sizeof(*metadata));
    uint64_t meta_rva = parser->get_metadata_offset();
    const uint8_t *base_addr = parser->get_start_addr();

    // Copy metadata and get the metadata offset
    metadata_t *meta_addr = GET_PTR(metadata_t, base_addr, meta_rva);
    if (memcpy_s(metadata, sizeof(metadata_t), meta_addr, sizeof(metadata_t)))
        return false;
    if (metadata->size != METADATA_SIZE || metadata->magic_num != METADATA_MAGIC)
        return false;
    return true;
}



bool pce_get_metadata(const TCHAR* enclave_file, metadata_t *metadata)
{
    map_handle_t* mh = NULL;
    uint32_t file_size = 0;

    HANDLE pfile = CreateFileW(enclave_file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (pfile == INVALID_HANDLE_VALUE)
    {
        SE_TRACE(SE_TRACE_ERROR, "Couldn't open file with CreateFile()\n");
        return false;
    }

    mh = map_file(pfile, &file_size);
    if (!mh)
    {
        CloseHandle(pfile);
        return false;
    }

    PARSER parser(const_cast<uint8_t *>(mh->base_addr), (uint64_t)(file_size));
    if (SGX_SUCCESS != parser.run_parser())
    {
        unmap_file(mh);
        CloseHandle(pfile);
        return false;
    }
    //Make sure we have function "enclave_entry"
    if (!parser.get_symbol_rva("enclave_entry"))
    {
        SE_TRACE_WARNING("Function enclave_entry not found, please link with the sgx_trts.lib/libsgx_trts.a");

        unmap_file(mh);
        CloseHandle(pfile);
        return false;
    }
    if(true != get_metadata(&parser, metadata))
    {
        unmap_file(mh);
        CloseHandle(pfile);
        return false;
    }
        unmap_file(mh);
        CloseHandle(pfile);
    return true;
}
#define PCE_ENCLAVE_NAME _T("pce.signed.dll")

bool get_pce_path(
    const TCHAR *p_dirpath,
    TCHAR *p_file_path,
    size_t buf_size)
{
    if (!p_file_path)
        return false;

    HMODULE hModule;
    if (p_dirpath != NULL)
    {
        if(_tcsnlen(p_dirpath,buf_size)==buf_size)
        {
            SE_TRACE(SE_TRACE_ERROR, "Input dirpath is too long\n");
            return false;
        }
        (void)_tcsncpy(p_file_path,p_dirpath,buf_size);
    }
    else
    {
        if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, _T(__FUNCTION__), &hModule))
            return false;
        DWORD path_length = GetModuleFileName(hModule, p_file_path, static_cast<DWORD>(buf_size));
        if (path_length == 0)
            return false;
        if (path_length == buf_size)
            return false;
    }

    TCHAR *p_last_slash = _tcsrchr(p_file_path, _T('\\'));
    if (p_last_slash != NULL)
    {
        p_last_slash++;
        *p_last_slash = _T('\0');
    }
    else
        return false;
    if (_tcsnlen(PCE_ENCLAVE_NAME, MAX_PATH) + _tcsnlen(p_file_path, MAX_PATH) + sizeof(TCHAR) > buf_size)
        return false;
    if (_tcscat_s(p_file_path, buf_size, PCE_ENCLAVE_NAME))
        return false;
    return true;
}
