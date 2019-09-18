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
#include <fcntl.h>
#include <dlfcn.h>
#include "se_trace.h"
#include "se_map.h"
#include "sgx_urts.h"
#include "binparser.h"
#ifndef PARSER
#include "elfparser.h"
#define PARSER ElfParser
#endif
#include "metadata.h"
#include "sgx_attributes.h"

static bool get_metadata(BinParser *parser, metadata_t **metadata)
{
    if (parser == NULL || metadata == NULL)
        return false;
    uint64_t meta_rva = parser->get_metadata_offset();
    const uint8_t *base_addr = parser->get_start_addr();
    uint64_t urts_version = META_DATA_MAKE_VERSION(MAJOR_VERSION,MINOR_VERSION);
    metadata_t *target_metadata = NULL;

    //assume PCE only contains one metadata
    *metadata = GET_PTR(metadata_t, base_addr, meta_rva);

    if(metadata == NULL)
    {
        return false;
    }
    if((*metadata)->magic_num != METADATA_MAGIC)
    {
        return false;
    }
    if(0 == (*metadata)->size)
    {
        SE_TRACE(SE_TRACE_ERROR, "ERROR: metadata's size can't be zero.\n");
        return false;
    }
    //check metadata version
    if(MAJOR_VERSION_OF_METADATA(urts_version) >=
       MAJOR_VERSION_OF_METADATA((*metadata)->version))
    {
        if(target_metadata == NULL ||
           target_metadata->version < (*metadata)->version)
        {
            target_metadata = *metadata;
        }
    }
    if(target_metadata == NULL )
    {
        return false;
    }
    else
    {
        *metadata = target_metadata;
    }
    return true;
}



bool pce_get_metadata(const char* enclave_file, metadata_t *metadata)
{
    map_handle_t* mh = NULL;
    metadata_t *p_metadata;
    
    uint32_t file_size = 0;
    int fd = open(enclave_file, O_RDONLY);
    if(-1 == fd)
    {
        SE_TRACE(SE_TRACE_ERROR, "Couldn't open the enclave file, error = %d\n", errno);
        return false;
    }
    
    
    mh = map_file(fd, &file_size);
    if (!mh)
    {
        close(fd);
        return false;
    }

    PARSER parser(const_cast<uint8_t *>(mh->base_addr), (uint64_t)(file_size));
    if(SGX_SUCCESS != parser.run_parser())
    {
        unmap_file(mh);
        close(fd);
        return false;
    }

    if(true != get_metadata(&parser, &p_metadata))
    {
        unmap_file(mh);
        close(fd);
        return false;
    }
    memcpy(metadata, p_metadata, sizeof(metadata_t));
    unmap_file(mh);
    close(fd);
    return true;
}

#define PCE_ENCLAVE_NAME "libsgx_pce.signed.so"
bool get_pce_path(
    const char *p_dirpath,
    char *p_file_path,
    size_t buf_size)
{
    if(!p_file_path)
        return false;

    Dl_info dl_info;
    if (p_dirpath != NULL)
    {
        if(strnlen(p_dirpath,buf_size)==buf_size)
        {
            SE_TRACE(SE_TRACE_ERROR, "Input dirpath is too long\n");
            return false;
        }
        (void)strncpy(p_file_path,p_dirpath,buf_size);
    }
    else if(0 != dladdr(__builtin_return_address(0), &dl_info) &&
        NULL != dl_info.dli_fname)
    {
        if(strnlen(dl_info.dli_fname,buf_size)==buf_size)
            return false;
        (void)strncpy(p_file_path,dl_info.dli_fname,buf_size);
    }
    else //not a dynamic executable
    {
        ssize_t i = readlink( "/proc/self/exe", p_file_path, buf_size );
        if (i == -1)
            return false;
        p_file_path[i] = '\0';
    }

    char* p_last_slash = strrchr(p_file_path, '/' );
    if ( p_last_slash != NULL )
    {
        p_last_slash++;   //increment beyond the last slash
        *p_last_slash = '\0';  //null terminate the string
    }
    else p_file_path[0] = '\0';
    if(strnlen(p_file_path,buf_size)+strnlen(PCE_ENCLAVE_NAME,buf_size)+sizeof(char)>buf_size)
        return false;
    (void)strncat(p_file_path,PCE_ENCLAVE_NAME, strnlen(PCE_ENCLAVE_NAME,buf_size));
    return true;
}
