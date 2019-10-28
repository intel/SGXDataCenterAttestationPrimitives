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


#include "se_map.h"
#include "se_trace.h"
#include <stdlib.h>

#if defined(_MSC_VER)

map_handle_t* map_file(se_file_handle_t file, uint32_t *size)
{
    if(size == NULL)
        return NULL;

    map_handle_t* mh = (map_handle_t *)calloc(1, sizeof(map_handle_t));
    if (mh == NULL)
        return NULL;

    // Using GetFileSizeEx instead of GetFileSize.
    // We do NOT support mapping files larger than max uint32_t with this API.
    LARGE_INTEGER file_size; file_size.QuadPart = 0;
    if (GetFileSizeEx(file, &file_size) && file_size.HighPart == 0)
    {
        *size = file_size.LowPart;
    }
    else
    {
        free(mh);
        return NULL;
    }

    mh->maph = CreateFileMappingW(file, NULL, PAGE_WRITECOPY | SEC_COMMIT, 0, 0, NULL);
    if (NULL == mh->maph)
    {
        SE_TRACE(SE_TRACE_ERROR, "Couldn't open file mapping with CreateFileMapping()\n");
        free(mh);
        return NULL;
    }

    mh->base_addr = (uint8_t*)MapViewOfFile(mh->maph,FILE_MAP_COPY,0,0,0);
    if (NULL == mh->base_addr)
    {
        CloseHandle(mh->maph);
        free(mh);
        SE_TRACE(SE_TRACE_ERROR, "Couldn't map view of file with MapViewOfFile(), error code %x\n", GetLastError());
        return NULL;
    }

    return mh;
}

void unmap_file(map_handle_t* mh)
{
    UnmapViewOfFile(mh->base_addr);
    CloseHandle(mh->maph);
    free(mh);
}

#elif defined(__GNUC__)
map_handle_t* map_file(se_file_handle_t fd, uint32_t *size)
{
    struct stat st;
    memset(&st, 0, sizeof(st));
    if (-1 == fstat(fd, &st))
        return NULL;

    map_handle_t* mh = (map_handle_t *)calloc(1, sizeof(map_handle_t));
    if (mh == NULL)
        return NULL;

    mh->base_addr = (uint8_t *)mmap(NULL, (size_t)st.st_size,
            PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
    if(MAP_FAILED == mh->base_addr)
    {
        free(mh);
        SE_TRACE(SE_TRACE_WARNING, "Couldn't map view of file,  error code %x\n", errno);
        return NULL;
    }

    mh->length = (size_t)st.st_size;
    if (size) *size = (uint32_t)st.st_size;
    return mh;
}

void unmap_file(map_handle_t* mh)
{
    munmap(mh->base_addr, mh->length);
    free(mh);
}

#endif

