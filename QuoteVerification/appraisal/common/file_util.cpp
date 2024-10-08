/**
 * Copyright (c) 2017-2023, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of Intel Corporation nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "file_util.h"
#include "se_trace.h"

bool write_buffer_to_file(const char *filename, const char *mode, const uint8_t *buf, size_t bsize, long offset)
{
    FILE *file = NULL;
    if (!filename || !mode || !buf || !bsize || offset < 0)
    {
        return false;
    }
    if (!(file = fopen(filename, mode)))
    {
        return false;
    }
    if (fseek(file, offset, SEEK_SET) != 0)
    {
        fclose(file);
        return false;
    }
    if (fwrite(buf, sizeof(uint8_t), bsize, file) != bsize)
    {
        fclose(file);
        return false;
    }
    fclose(file);
    return true;
}

uint8_t *read_file_to_buffer(const char *filename, size_t *ret_size)
{
    unsigned char *buffer = NULL;
    FILE *file = NULL;
    size_t file_size = 0, read_size = 0;

    if (!filename || !ret_size)
    {
        return NULL;
    }

    if (!(file = fopen(filename, "rb")))
    {
        return NULL;
    }

    if (fseek(file, 0, SEEK_END) != 0)
    {
        fclose(file);
        return NULL;
    }
    file_size = ftell(file);
    if (fseek(file, 0, SEEK_SET) != 0)
    {
        fclose(file);
        return NULL;
    }
    if (!(buffer = (unsigned char *)malloc(file_size)))
    {
        se_trace(SE_TRACE_WARNING, "Read file to buffer failed: alloc memory failed.\n");
        fclose(file);
        return NULL;
    }

    read_size = fread(buffer, 1, file_size, file);
    fclose(file);

    if (read_size < file_size)
    {
        free(buffer);
        return NULL;
    }

    *ret_size = file_size;

    return buffer;
}

map_handle_t *map_file(se_file_handle_t fd, off_t *size)
{
    struct stat st;
    memset(&st, 0, sizeof(st));
    if (-1 == fstat(fd, &st))
        return NULL;

    map_handle_t *mh = (map_handle_t *)calloc(1, sizeof(map_handle_t));
    if (mh == NULL)
        return NULL;

    mh->base_addr = (uint8_t *)mmap(NULL, (size_t)st.st_size,
                                    PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (MAP_FAILED == mh->base_addr)
    {
        free(mh);
        se_trace(SE_TRACE_WARNING, "Couldn't map view of file,  error code %x\n", errno);
        return NULL;
    }

    mh->length = (size_t)st.st_size;
    if (size)
        *size = st.st_size;
    return mh;
}

void unmap_file(map_handle_t *mh)
{
    munmap(mh->base_addr, mh->length);
    free(mh);
}
