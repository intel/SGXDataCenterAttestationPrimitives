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



#pragma once

#ifndef _PEPARSER_H_
#define _PEPARSER_H_

#include "binparser.h"
#include "uncopyable.h"
#include "petypes.h"
#include "cpputil.h"
#include "thread_data.h"
#include "se_trace.h"

#include <assert.h>
#include <string>
#include <map>

using std::map;
using std::string;

#include "update_thread_data.hxx"

#define CV_PDB20_SIGNATURE   0x3031424E
#define CV_PDB70_SIGNATURE   0x53445352

struct CV_HEADER
{
    DWORD dwCvSignature;
    LONG  lOffset;
};

// CodeView debug info structure for PDB 2.0
struct CV_PDB20_INFO
{
    CV_HEADER  cvHeader;
    DWORD      dwSignature;
    DWORD      dwAge;
    BYTE       byPdbFileName[1];
};

// CodeView debug info structure for PDB 7.0
struct CV_PDB70_INFO
{
    DWORD      dwCvSignature;
    GUID       guSignature;
    DWORD      dwAge;
    BYTE       byPdbFileName[1];
};

namespace {
si_flags_t page_attr_to_si_flags(uint32_t page_attr)
{
    si_flags_t res = SI_FLAG_REG;

    if (page_attr & IMAGE_SCN_MEM_READ)
        res |= SI_FLAG_R;

    if (page_attr & IMAGE_SCN_MEM_WRITE)
        res |= SI_FLAG_W;

    if (page_attr & IMAGE_SCN_MEM_EXECUTE)
        res |= SI_FLAG_X;

    return res;
}

Section* build_section(const uint8_t* raw_data, uint64_t size, uint64_t virtual_size,
                       uint64_t rva, uint32_t page_attr)
{
    si_flags_t sf = page_attr_to_si_flags(page_attr);

    if (sf != SI_FLAG_REG)
        return new Section(raw_data, size, virtual_size, rva, sf);

    return NULL;
}

const char* TLS_SEC_NAME = ".tls";

bool is_tls_section(const PIMAGE_SECTION_HEADER sec_hdr)
{
    return strcmp((const char *)sec_hdr->Name, TLS_SEC_NAME) == 0;
}

const char *METADATA_SEC_NAME = "sgxmeta";
bool is_meta_section(const PIMAGE_SECTION_HEADER sec_hdr)
{
    return strcmp((const char *)sec_hdr->Name, METADATA_SEC_NAME) == 0;
}

/* If the RVA is not within the export section, the field is an export RVA.
 * Otherwise, it is a forwarder RVA and not allowed inside an Enclave.
*/
bool is_forwarder_rva(uint32_t exports_rva, uint32_t exports_size, uint32_t this_rva)
{
    return (this_rva >= exports_rva && (uint64_t)this_rva < ((uint64_t)exports_rva + exports_size));
}

bool need_relocation(const PIMAGE_DATA_DIRECTORY reloc_dir)
{
    return (reloc_dir->Size != 0 && reloc_dir->VirtualAddress != 0);
}
}


template <int N>
class PEHelper {
public:
    typedef typename PETypes<N>::pimage_nt_hdrs_t pimage_nt_hdrs_t;
    typedef typename PETypes<N>::image_nt_hdrs_t  image_nt_hdrs_t;
    typedef typename PETypes<N>::pimage_opt_hdr_t pimage_opt_hdr_t;
    typedef typename PETypes<N>::image_load_config_directory image_load_config_directory;
    typedef typename PETypes<N>::pimage_load_config_directory pimage_load_config_directory;
    typedef typename PETypes<N>::pimage_tls_directory pimage_tls_directory;
    typedef typename PETypes<N>::image_tls_directory  image_tls_directory;

    static const pimage_nt_hdrs_t get_nt_header(const uint8_t* start_addr, uint64_t len)
    {

        if (len < sizeof(IMAGE_DOS_HEADER))
            return NULL;

        PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)start_addr;

        /* Check invalid DOS header */
        if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE)
            return NULL;

        const pimage_nt_hdrs_t nt_hdr = GET_PTR(image_nt_hdrs_t, dos_hdr, dos_hdr->e_lfanew);
        if (len < DIFF64(nt_hdr, dos_hdr) + sizeof(image_nt_hdrs_t))
            return NULL;

        return nt_hdr;
    }

    static const PIMAGE_SECTION_HEADER get_section(const pimage_nt_hdrs_t nt_hdr, uint64_t rva, uint64_t size)
    {
        PIMAGE_SECTION_HEADER sec_hdr = IMAGE_FIRST_SECTION(nt_hdr);
        const int nr_sections = nt_hdr->FileHeader.NumberOfSections;
        const uint64_t rhs_bound = rva + size;

        //check overflow
        if(rhs_bound < rva || rhs_bound < size)
            return NULL;
        for (int idx = 0; idx < nr_sections; ++idx, ++sec_hdr)
        {
            if (rva >= sec_hdr->VirtualAddress
                    && rhs_bound <= (sec_hdr->VirtualAddress + ROUND_TO_PAGE(sec_hdr->Misc.VirtualSize))
                    && (rhs_bound - sec_hdr->VirtualAddress) <= sec_hdr->SizeOfRawData)
            {
                return sec_hdr;
            }
        }

        return NULL;
    }

    static const PIMAGE_SECTION_HEADER get_section(const pimage_nt_hdrs_t nt_hdr, const char* sec_name)
    {
        assert(sec_name != NULL);

        PIMAGE_SECTION_HEADER sec_hdr = IMAGE_FIRST_SECTION(nt_hdr);
        const int nr_sections = nt_hdr->FileHeader.NumberOfSections;

        for (int idx = 0; idx < nr_sections; ++idx, ++sec_hdr)
        {
            if (strcmp(sec_name, (char *)sec_hdr->Name) == 0)
                return sec_hdr;
        }

        return NULL;
    }

    static const void* get_raw_data(const uint8_t* start_addr, const pimage_nt_hdrs_t nt_hdr, uint64_t rva, uint64_t size)
    {
        const PIMAGE_SECTION_HEADER sec_hdr = get_section(nt_hdr, rva, size);
        if (sec_hdr == NULL)
            return NULL;

        uint64_t diff = DIFF64(rva, sec_hdr->VirtualAddress);
        uint64_t end = diff + size;
        if(end < diff || end < size)
            return NULL;
        if (end > sec_hdr->SizeOfRawData)
            return NULL;

        return GET_PTR(void, start_addr, sec_hdr->PointerToRawData + diff);
    }

#define _get_reloc_type(entry) (((entry) >> 12) & 0xF)

    static sgx_status_t validate_reloc_types (const uint8_t* start_addr,
            const pimage_nt_hdrs_t nt_hdr,
            const pimage_opt_hdr_t opt_hdr)
    {
        const PIMAGE_DATA_DIRECTORY reloc_dir = &opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        /* No relocation needed */
        if (!need_relocation(reloc_dir))
            return SGX_SUCCESS;

        PIMAGE_BASE_RELOCATION reloc_blk =
            (PIMAGE_BASE_RELOCATION)(get_raw_data(start_addr, nt_hdr,
                                     reloc_dir->VirtualAddress, reloc_dir->Size));
        if (reloc_blk == NULL)
            return SGX_ERROR_INVALID_ENCLAVE;

        uint64_t reloc_edge = (uint64_t)reloc_blk + reloc_dir->Size;

        // Relocation Table
        //                   DWORD          DWORD        WORD     WORD
        //      block[0]: VirtualAddress, SizeOfBlock, entry[0], entry[1], ....
        //      block[1]: VirtualAddress, SizeOfBlock, entry[0], entry[1], ....
        //      ....
        while (reloc_blk->SizeOfBlock != 0)
        {
            uint16_t* entry_list = GET_PTR(uint16_t, reloc_blk, sizeof(IMAGE_BASE_RELOCATION));
            int entry_num = (reloc_blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
            if(entry_num <= 0)
                return SGX_ERROR_INVALID_ENCLAVE;

            for (int idx = 0; idx < entry_num; ++idx)
            {
                uint16_t reloc_type = _get_reloc_type(entry_list[idx]);
                switch (reloc_type)
                {
                case PETypes<N>::IMAGE_REL_TYPE:
                    /* fall through. */
                case IMAGE_REL_BASED_ABSOLUTE:
                    break;

                default:
                    return SGX_ERROR_INVALID_ENCLAVE;
                }
            }

            reloc_blk = GET_PTR(IMAGE_BASE_RELOCATION, reloc_blk, reloc_blk->SizeOfBlock);
            if ((uint64_t)reloc_blk >= reloc_edge)
                break;
        }

        return SGX_SUCCESS;
    }

    // Check whether given input is a valid PE image.
    static sgx_status_t validate_pe_file(const uint8_t* start_addr, const pimage_nt_hdrs_t nt_hdr)
    {
        /* Check NT signature */
        if (nt_hdr->Signature != IMAGE_NT_SIGNATURE)
            return SGX_ERROR_INVALID_ENCLAVE;

        const pimage_opt_hdr_t opt_hdr = &nt_hdr->OptionalHeader;

        /* Section must be 1-page aligned */
        if (opt_hdr->SectionAlignment != SE_PAGE_SIZE)
            return SGX_ERROR_INVALID_ENCLAVE;

        if (opt_hdr->SectionAlignment < opt_hdr->FileAlignment)
            return SGX_ERROR_INVALID_ENCLAVE;

        const PIMAGE_DATA_DIRECTORY id_dir = opt_hdr->DataDirectory;

        /* Enclave should NOT have imports */
        if (id_dir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0)
        {
            SE_TRACE_WARNING("warning: The enclave contains an import table.\n");
            return SGX_ERROR_UNDEFINED_SYMBOL;
        }
        /* Nor delayed imports */
        if (id_dir[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress != 0)
        {
            SE_TRACE_WARNING("warning: The enclave contains an import table.\n");
            return SGX_ERROR_UNDEFINED_SYMBOL;
        }

        return validate_reloc_types(start_addr, nt_hdr, opt_hdr);
    }

    static bool get_bin_fmt(const pimage_nt_hdrs_t nt_hdr, bin_fmt_t& bf)
    {
        if (nt_hdr->FileHeader.Machine != PETypes<N>::FH_MACHINE)
            return false;
        if (nt_hdr->OptionalHeader.Magic != PETypes<N>::OPT_MAGIC)
            return false;

        bf = (bin_fmt_t)PETypes<N>::BIN_FORMAT;
        return true;
    }

    static bool build_regular_sections(const uint8_t* start_addr,
                                       uint64_t len,
                                       const pimage_nt_hdrs_t nt_hdr,
                                       vector<Section *>& sections,
                                       const Section*& tls_sec,
                                       uint64_t& metadata_offset)
    {
        const int nr_sec = nt_hdr->FileHeader.NumberOfSections;
        PIMAGE_SECTION_HEADER sec_hdr = IMAGE_FIRST_SECTION(nt_hdr);

        for (int idx = 0; idx < nr_sec; ++idx, ++sec_hdr)
        {
            /* Validate the size of the buffer */
            if (len < (uint64_t)sec_hdr->PointerToRawData + (uint64_t)sec_hdr->SizeOfRawData)
                return false;

            if (is_meta_section(sec_hdr))
            {
                metadata_offset = sec_hdr->PointerToRawData;
                continue;
            }

            Section* sec = build_section(GET_PTR(uint8_t, start_addr, sec_hdr->PointerToRawData),
                                         sec_hdr->SizeOfRawData, sec_hdr->Misc.VirtualSize,
                                         sec_hdr->VirtualAddress, sec_hdr->Characteristics);
            if (sec == NULL)
                return false;

            if (is_tls_section(sec_hdr))
            {
                tls_sec = sec;
            }

            sections.push_back(sec);
        }

        if(metadata_offset == 0)
        {
            SE_TRACE(SE_TRACE_ERROR, "ERROR: The enclave image should have one 'sgxmeta' section\n");
            return false;
        }
        return true;
    }

    static bool setup_export_table(const uint8_t* start_addr,
                                   const pimage_nt_hdrs_t nt_hdr,
                                   map<string, uint64_t>& sym_table)
    {
        const PIMAGE_DATA_DIRECTORY exp_entry = &nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        const uint32_t exports_rva = exp_entry->VirtualAddress;
        const uint32_t exports_siz = exp_entry->Size;

        const PIMAGE_SECTION_HEADER exp_dir_sec_hdr = get_section(nt_hdr, exports_rva, exports_siz);
        if (exp_dir_sec_hdr == NULL)
        {
            // failed to find the section that contains export directory
            return false;
        }

        uint64_t diff = DIFF64(exports_rva, exp_dir_sec_hdr->VirtualAddress);
        const PIMAGE_EXPORT_DIRECTORY exp_dir = GET_PTR(IMAGE_EXPORT_DIRECTORY,
                                                start_addr,
                                                exp_dir_sec_hdr->PointerToRawData + diff);

        diff = DIFF64(exp_dir->AddressOfNames, exp_dir_sec_hdr->VirtualAddress);
        uint32_t* name_ptr_table = GET_PTR(uint32_t, start_addr, exp_dir_sec_hdr->PointerToRawData + diff);

        // Record the export address table
        const PIMAGE_SECTION_HEADER exp_addr_sec_hdr = get_section(nt_hdr,
                exp_dir->AddressOfFunctions,
                exp_dir->NumberOfFunctions * sizeof(uint32_t));
        if (exp_addr_sec_hdr == NULL)
        {
            // failed to find the section that contains export address table
            return false;
        }

        diff = DIFF64(exp_dir->AddressOfFunctions, exp_addr_sec_hdr->VirtualAddress);
        const uint32_t* exp_addr_table = GET_PTR(uint32_t, start_addr, exp_addr_sec_hdr->PointerToRawData + diff);

        //Record the ordinal table
        diff = DIFF64(exp_dir->AddressOfNameOrdinals, exp_addr_sec_hdr->VirtualAddress);
        //From PE spec, address table, name table, ordinal table should all locate at .edata section.
        //Here we check diff should be within the section.
        if(diff >= exp_addr_sec_hdr->SizeOfRawData)
            return false;
        const uint16_t* ordinal_table = GET_PTR(uint16_t, start_addr, exp_addr_sec_hdr->PointerToRawData + diff);

        /* The algorithm for finding a symbol's RVA is:
         *
         * idx = search_name_ptr_table(symbol_name);
         * ord = ordinal_table[idx];
         * rva = exp_addr_table[ord];
         */

        // Iterate the name address table to record exported symbol names
        for (unsigned idx = 0; idx < exp_dir->NumberOfNames; ++idx)
        {
            diff = DIFF64(name_ptr_table[idx], exp_dir_sec_hdr->VirtualAddress);
            //Here we check diff should be within the section.
            if (diff >= exp_dir_sec_hdr->SizeOfRawData)
                return false;

            const char* sym_name = GET_PTR(char, start_addr, exp_dir_sec_hdr->PointerToRawData + diff);

            /* An exported symbol name can't be NULL */
            if (sym_name == NULL)
                return false;

            map<string, uint64_t>::const_iterator it = sym_table.find(sym_name);
            if (it == sym_table.end())
            {
                uint32_t rva = exp_addr_table[ordinal_table[idx]];
                if (is_forwarder_rva(exports_rva, exports_siz, rva))
                    return false;

                sym_table[sym_name] = rva;
            }
            else
                return false;   /* duplicated symbol name */
        }

        return true;
    }

    static bool get_enclave_diff_info(const uint8_t* start_addr, const pimage_nt_hdrs_t nt_hdr, enclave_diff_info_t *enclave_diff_info)
    {
        if(start_addr == NULL || nt_hdr == NULL || enclave_diff_info == NULL)
            return false;

        //get time date stamp for file header
        PIMAGE_FILE_HEADER file_hdr = &nt_hdr->FileHeader;
        enclave_diff_info->file_hdr_TimeDateStamp = file_hdr->TimeDateStamp;

        //get timedatestamp from export dir
        const PIMAGE_DATA_DIRECTORY exp_entry = &nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        const uint32_t exports_rva = exp_entry->VirtualAddress;
        const uint32_t exports_siz = exp_entry->Size;
        //if rva and size are not 0, it means export driectory exist
        if (exports_rva != 0 && exports_siz != 0)
        {
            const PIMAGE_SECTION_HEADER exp_dir_sec_hdr = get_section(nt_hdr, exports_rva, exports_siz);
            if (exp_dir_sec_hdr != NULL)
            {
                uint64_t diff = DIFF64(exports_rva, exp_dir_sec_hdr->VirtualAddress);
                const PIMAGE_EXPORT_DIRECTORY exp_dir = GET_PTR(IMAGE_EXPORT_DIRECTORY,
                                                        start_addr,
                                                        exp_dir_sec_hdr->PointerToRawData + diff);
                enclave_diff_info->export_dir_TimeDateStamp = exp_dir->TimeDateStamp;
            }
        }

        //get debug releated info form debug directory
        const PIMAGE_DATA_DIRECTORY debug_entry = &nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        const uint32_t debug_rva = debug_entry->VirtualAddress;
        const uint32_t debug_siz = debug_entry->Size;
        //if rva and size are not 0, it means debug driectory exist in enclave
        if (debug_rva != 0 && debug_siz != 0)
        {
            const PIMAGE_SECTION_HEADER debug_dir_sec_hdr = get_section(nt_hdr, debug_rva, debug_siz);
            if (debug_dir_sec_hdr != NULL)
            {
                uint64_t diff = DIFF64(debug_rva, debug_dir_sec_hdr->VirtualAddress);
                const uint32_t num_debug_table = debug_siz/sizeof(IMAGE_DEBUG_DIRECTORY);
                uint32_t i =0;
                for(i=0; i<num_debug_table; i++)
                {
                    const PIMAGE_DEBUG_DIRECTORY debug_dir = GET_PTR(IMAGE_DEBUG_DIRECTORY,
                            start_addr,
                            debug_dir_sec_hdr->PointerToRawData + diff + sizeof(IMAGE_DEBUG_DIRECTORY)*i);
                    enclave_diff_info->debug_dir_TimeDateStamp = debug_dir->TimeDateStamp;
                    if(debug_dir->Type == IMAGE_DEBUG_TYPE_CODEVIEW)
                    {
                        CV_PDB70_INFO* pCvInfo = GET_PTR(CV_PDB70_INFO,
                                                        start_addr,
                                                        debug_dir->PointerToRawData);
                        //RSDS, pdb 7.0
                        if(pCvInfo->dwCvSignature == CV_PDB70_SIGNATURE)
                        {
                            memcpy_s(&enclave_diff_info->PDB70Signature, sizeof(pCvInfo->guSignature), &pCvInfo->guSignature, sizeof(pCvInfo->guSignature));
                            enclave_diff_info->Age = pCvInfo->dwAge;
                            enclave_diff_info->PdbFileName = (char *)pCvInfo->byPdbFileName;
                        }
                        //NB10, pdb 2.0
                        else if(pCvInfo->dwCvSignature == CV_PDB20_SIGNATURE)
                        {
                            CV_PDB20_INFO *pCvInfo1 = reinterpret_cast<CV_PDB20_INFO*>(pCvInfo);
                            enclave_diff_info->PDB20Signature = pCvInfo1->dwSignature;
                            enclave_diff_info->Age = pCvInfo1->dwAge;
                            enclave_diff_info->PdbFileName = (char *)pCvInfo->byPdbFileName;
                        }
                    }
                }
            }
        }

        //get timedatestamp from load dir
        const PIMAGE_DATA_DIRECTORY load_entry = &nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
        const uint32_t load_rva = load_entry->VirtualAddress;
        const uint32_t load_siz = load_entry->Size;
        //if rva and size are not 0, it means load config driectory exist in enclave
        if(load_rva != 0 && load_siz != 0)
        {
            const PIMAGE_SECTION_HEADER load_dir_sec_hdr = get_section(nt_hdr, load_rva, load_siz);
            if (load_dir_sec_hdr != NULL)
            {
                uint64_t diff = DIFF64(load_rva, load_dir_sec_hdr->VirtualAddress);
                const pimage_load_config_directory load_dir = GET_PTR(image_load_config_directory,
                        start_addr,
                        load_dir_sec_hdr->PointerToRawData + diff);
                enclave_diff_info->load_dir_TimeDateStamp = load_dir->TimeDateStamp;
            }
        }

        //get timedatestamp from resourec dir
        const PIMAGE_DATA_DIRECTORY resc_entry = &nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
        const uint32_t resc_rva = resc_entry->VirtualAddress;
        const uint32_t resc_siz = resc_entry->Size;
        //if rva and size are not 0, it means resource driectory exist in enclave
        if(resc_rva != 0 && resc_siz != 0)
        {
            const PIMAGE_SECTION_HEADER resc_dir_sec_hdr = get_section(nt_hdr, resc_rva, resc_siz);
            if (resc_dir_sec_hdr != NULL)
            {
                uint64_t diff = DIFF64(resc_rva, resc_dir_sec_hdr->VirtualAddress);
                const PIMAGE_RESOURCE_DIRECTORY resc_dir = GET_PTR(IMAGE_RESOURCE_DIRECTORY,
                        start_addr,
                        resc_dir_sec_hdr->PointerToRawData + diff);
                enclave_diff_info->resource_dir_TimeDateStamp = resc_dir->TimeDateStamp;
            }
        }
        return true;
    }

    static bool update_enclave_with_enclave_diff_info(const uint8_t* start_addr, const pimage_nt_hdrs_t nt_hdr, enclave_diff_info_t *enclave_diff_info)
    {
        if(start_addr == NULL || nt_hdr == NULL || enclave_diff_info == NULL)
            return false;

        //update time date stamp for file header
        PIMAGE_FILE_HEADER file_hdr = &nt_hdr->FileHeader;
        file_hdr->TimeDateStamp = enclave_diff_info->file_hdr_TimeDateStamp;

        //enclave have no import directory
        //update time date stamp for export directory
        const PIMAGE_DATA_DIRECTORY exp_entry = &nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        const uint32_t exports_rva = exp_entry->VirtualAddress;
        const uint32_t exports_siz = exp_entry->Size;
        //if rva and size are not 0, it means export driectory exist
        if (exports_rva != 0 && exports_siz != 0)
        {
            const PIMAGE_SECTION_HEADER exp_dir_sec_hdr = get_section(nt_hdr, exports_rva, exports_siz);
            if (exp_dir_sec_hdr != NULL)
            {
                uint64_t diff = DIFF64(exports_rva, exp_dir_sec_hdr->VirtualAddress);
                const PIMAGE_EXPORT_DIRECTORY exp_dir = GET_PTR(IMAGE_EXPORT_DIRECTORY,
                                                        start_addr,
                                                        exp_dir_sec_hdr->PointerToRawData + diff);
                exp_dir->TimeDateStamp = enclave_diff_info->export_dir_TimeDateStamp;
            }
        }

        //update time date stamp and signature and age for debug directory
        const PIMAGE_DATA_DIRECTORY debug_entry = &nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        const uint32_t debug_rva = debug_entry->VirtualAddress;
        const uint32_t debug_siz = debug_entry->Size;
        //if rva and size are not 0, it means debug driectory exist in enclave
        if (debug_rva != 0 && debug_siz != 0)
        {
            const PIMAGE_SECTION_HEADER debug_dir_sec_hdr = get_section(nt_hdr, debug_rva, debug_siz);
            if (debug_dir_sec_hdr != NULL)
            {
                uint64_t diff = DIFF64(debug_rva, debug_dir_sec_hdr->VirtualAddress);
                const uint32_t num_debug_table = debug_siz/sizeof(IMAGE_DEBUG_DIRECTORY);
                uint32_t i =0;
                for(i=0; i<num_debug_table; i++)
                {
                    const PIMAGE_DEBUG_DIRECTORY debug_dir = GET_PTR(IMAGE_DEBUG_DIRECTORY,
                            start_addr,
                            debug_dir_sec_hdr->PointerToRawData + diff + sizeof(IMAGE_DEBUG_DIRECTORY)*i);
                    debug_dir->TimeDateStamp = enclave_diff_info->debug_dir_TimeDateStamp;
                    if(debug_dir->Type == IMAGE_DEBUG_TYPE_CODEVIEW)
                    {
                        CV_PDB70_INFO* pCvInfo = GET_PTR(CV_PDB70_INFO,
                                                        start_addr,
                                                        debug_dir->PointerToRawData);
                        //RSDS
                        if (pCvInfo->dwCvSignature == CV_PDB70_SIGNATURE)
                        {
                            memcpy_s(&pCvInfo->guSignature , sizeof(pCvInfo->guSignature), &enclave_diff_info->PDB70Signature, sizeof(pCvInfo->guSignature));
                            //when build the code, age will be increased, so need to clear it here
                            pCvInfo->dwAge = enclave_diff_info->Age;
                        }
                        else if (pCvInfo->dwCvSignature == CV_PDB20_SIGNATURE)
                        {
                            CV_PDB20_INFO *pCvInfo1 = reinterpret_cast<CV_PDB20_INFO*>(pCvInfo);
                            pCvInfo1->dwSignature = enclave_diff_info->PDB20Signature;
                            //when build the code, age will be increased, so need to clear it here
                            pCvInfo1->dwAge = enclave_diff_info->Age;
                        }
                    }
                }
            }
        }

        //in load config and resource directory, will find time stamp is always 0
        //but no document say is not used, so also clear it here
        //update time date stamp for load config directory
        const PIMAGE_DATA_DIRECTORY load_entry = &nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
        const uint32_t load_rva = load_entry->VirtualAddress;
        const uint32_t load_siz = load_entry->Size;
        //if rva and size are not 0, it means load config driectory exist in enclave
        if(load_rva != 0 && load_siz != 0)
        {
            const PIMAGE_SECTION_HEADER load_dir_sec_hdr = get_section(nt_hdr, load_rva, load_siz);
            if (load_dir_sec_hdr != NULL)
            {
                uint64_t diff = DIFF64(load_rva, load_dir_sec_hdr->VirtualAddress);
                const pimage_load_config_directory load_dir = GET_PTR(image_load_config_directory,
                        start_addr,
                        load_dir_sec_hdr->PointerToRawData + diff);
                load_dir->TimeDateStamp = enclave_diff_info->load_dir_TimeDateStamp;
            }
        }

        //update time date stamp for resourec directory
        const PIMAGE_DATA_DIRECTORY rescource_entry = &nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
        const uint32_t resc_rva = rescource_entry->VirtualAddress;
        const uint32_t resc_siz = rescource_entry->Size;
        //if rva and size are not 0, it means resource driectory exist in enclave
        if(resc_rva != 0 && resc_siz != 0)
        {
            const PIMAGE_SECTION_HEADER resc_dir_sec_hdr = get_section(nt_hdr, resc_rva, resc_siz);
            if (resc_dir_sec_hdr != NULL)
            {
                uint64_t diff = DIFF64(resc_rva, resc_dir_sec_hdr->VirtualAddress);
                const PIMAGE_RESOURCE_DIRECTORY resc_dir = GET_PTR(IMAGE_RESOURCE_DIRECTORY,
                        start_addr,
                        resc_dir_sec_hdr->PointerToRawData + diff);
                resc_dir->TimeDateStamp = enclave_diff_info->resource_dir_TimeDateStamp;

                PIMAGE_RESOURCE_DIRECTORY_ENTRY resc_entry = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY_ENTRY>(resc_dir + 1);
                uint32_t count =  resc_dir->NumberOfIdEntries + resc_dir->NumberOfNamedEntries;
                for (uint32_t i =0; i < count; i++)
                {
                    PIMAGE_RESOURCE_DIRECTORY resc_dir1 = GET_PTR(IMAGE_RESOURCE_DIRECTORY,
                                                          start_addr,
                                                          resc_entry->OffsetToDirectory + resc_dir_sec_hdr->PointerToRawData);
                    resc_dir1->TimeDateStamp = enclave_diff_info->resource_dir_TimeDateStamp;

                    uint32_t count1 = resc_dir1->NumberOfIdEntries + resc_dir1->NumberOfNamedEntries;
                    PIMAGE_RESOURCE_DIRECTORY_ENTRY resc_entry1 = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY_ENTRY>(resc_dir1 + 1);
                    for (uint32_t j =0; j < count1; j++)
                    {
                        PIMAGE_RESOURCE_DIRECTORY resc_dir2 = GET_PTR(IMAGE_RESOURCE_DIRECTORY,
                                                              start_addr,
                                                              resc_entry1->OffsetToDirectory + resc_dir_sec_hdr->PointerToRawData);
                        resc_dir2->TimeDateStamp = enclave_diff_info->resource_dir_TimeDateStamp;

                        resc_entry1++;
                    }
                    resc_entry++;
                }
            }
        }

        return true;
    }

    static bool get_tls_section(const uint8_t* start_addr, uint64_t len, const Section*&tls_sec)
    {
        uint64_t rva_size = 0;
        uint64_t rva = NULL;
        const pimage_nt_hdrs_t nt_header = get_nt_header(start_addr, len);
        IMAGE_DATA_DIRECTORY id_tls_dir = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (id_tls_dir.VirtualAddress == 0 || id_tls_dir.Size == 0)
        {
            return false;
        }
        pimage_tls_directory tls_dir = (pimage_tls_directory)(PEHelper<N>::get_raw_data(start_addr, nt_header, id_tls_dir.VirtualAddress, id_tls_dir.Size));
        rva_size = DIFF64(tls_dir->EndAddressOfRawData, tls_dir->StartAddressOfRawData);
        rva = DIFF64(tls_dir->StartAddressOfRawData, nt_header->OptionalHeader.ImageBase);

        PIMAGE_SECTION_HEADER sec_hdr = PEHelper<N>::get_section(nt_header, ".rdata");
        if (sec_hdr == NULL)
        {
            return false;
        }

        uint64_t tls_offset = DIFF64(rva, sec_hdr->VirtualAddress);
        uint8_t * raw_data = (uint8_t*)(sec_hdr->PointerToRawData + tls_offset);
        uint32_t page_attr = sec_hdr->Characteristics;

        // No need to use the raw_data size for the tls section, so just set 0 for it.
        Section* sec = build_section(GET_PTR(uint8_t, start_addr, (size_t)raw_data), 0, rva_size, rva, page_attr | IMAGE_SCN_MEM_WRITE);
        tls_sec = sec;
        return true;
    }
};

template <int N>
class PEParserT : public BinParser, private Uncopyable {
    typedef typename PETypes<N>::pimage_nt_hdrs_t pimage_nt_hdrs_t;
    typedef typename PETypes<N>::pimage_load_config_directory pimage_load_config_directory;

public:
    // The `start_addr' cannot be NULL
    PEParserT(const uint8_t* start_addr, uint64_t len)
        : m_start_addr(start_addr)
        , m_len(len)
        , m_bin_fmt(BF_UNKNOWN)
        , m_tls_section(NULL)
        , m_metadata_offset(0)
        , m_preferred_base_addr(0)
    {
    }

    ~PEParserT()
    {
        delete_ptrs_from_container(m_sections);
    }

    // Do the parsing job - use it before calling other methods
    sgx_status_t run_parser()
    {
        sgx_status_t status = SGX_SUCCESS;

        /* We only need to run the parser once. */
        if (m_sections.size() != 0) return SGX_SUCCESS;

        const pimage_nt_hdrs_t nt_hdr = PEHelper<N>::get_nt_header(m_start_addr, m_len);
        if (nt_hdr == NULL)
            return SGX_ERROR_INVALID_ENCLAVE;
        if (!PETypes<N>::check_dll(nt_hdr))
            return SGX_ERROR_INVALID_ENCLAVE;
        /* Get and check PE machine mode */
        if (!PEHelper<N>::get_bin_fmt(nt_hdr, m_bin_fmt))
            return SGX_ERROR_MODE_INCOMPATIBLE;

        status = PEHelper<N>::validate_pe_file(m_start_addr, nt_hdr);
        if (status != SGX_SUCCESS)
            return status;

        if (!PEHelper<N>::setup_export_table(m_start_addr, nt_hdr, m_sym_table))
            return SGX_ERROR_INVALID_ENCLAVE;

        /* the NT header is treated as a section */
        const uint32_t nt_hdr_raw_size = nt_hdr->OptionalHeader.SizeOfHeaders;
        const uint32_t nt_hdr_vir_size = ROUND_TO_PAGE(nt_hdr_raw_size);
        if (m_len < nt_hdr_raw_size)
            return SGX_ERROR_INVALID_ENCLAVE;

        if ((nt_hdr->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0)
        {
            this->m_preferred_base_addr = (uint64_t)nt_hdr->OptionalHeader.ImageBase;
            //if the preferred base address is zero, change it to 0xFFFFFFFFFFFFFFFF, because 0 means any value is acceptable 
            if (m_preferred_base_addr == 0)
            {
                m_preferred_base_addr = 0xFFFFFFFFFFFFFFFF;
            }
        }

        Section* sec = build_section(m_start_addr, nt_hdr_raw_size, nt_hdr_vir_size,
                                     0, IMAGE_SCN_MEM_READ);
        if (sec == NULL)
            return SGX_ERROR_INVALID_ENCLAVE;

        m_sections.push_back(sec);

        /* build regular sections */
        if(!PEHelper<N>::build_regular_sections(m_start_addr, m_len, nt_hdr, m_sections, m_tls_section, m_metadata_offset))
            return SGX_ERROR_INVALID_ENCLAVE;

        if (m_tls_section == NULL)
        {
            // The image has no .tls section and the tls is merged to .rdata section  
            if (!PEHelper<N>::get_tls_section(m_start_addr, m_len, m_tls_section))
                return SGX_ERROR_INVALID_ENCLAVE;
        }
        return SGX_SUCCESS;
    }

    bool has_tls_section() const
    {
        const pimage_nt_hdrs_t nt_hdr = PEHelper<N>::get_nt_header(m_start_addr, m_len);
        if (PEHelper<N>::get_section(nt_hdr, TLS_SEC_NAME))
            return true;
        else
            return false;
    }

    bin_fmt_t get_bin_format() const
    {
        return m_bin_fmt;
    }

    uint64_t get_metadata_offset() const
    {
        return m_metadata_offset;
    }

    const uint8_t *get_start_addr() const
    {
        return m_start_addr;
    }

    const vector<Section *>& get_sections() const
    {
        return m_sections;
    }

    const Section* get_tls_section() const
    {
        return m_tls_section;
    }

    uint64_t get_symbol_rva(const char* name) const
    {
        map<string, uint64_t>::const_iterator it = m_sym_table.find(name);
        return (it != m_sym_table.end()) ? it->second : 0;
    }

    bool is_cfg_enabled() const
    {
        const pimage_nt_hdrs_t nt_hdr = PEHelper<N>::get_nt_header(m_start_addr, m_len);
        assert(nt_hdr != NULL);
        return(!!(nt_hdr->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF));
    }

    bool get_reloc_bitmap(vector<uint8_t> &bitmap)
    {
        const pimage_nt_hdrs_t nt_hdr = PEHelper<N>::get_nt_header(m_start_addr, m_len);
        assert(nt_hdr != NULL);

        // Clear the `bitmap' so that it is in a known state
        bitmap.clear();

        // Get the relocation directory
        const PIMAGE_DATA_DIRECTORY reloc_dir = &nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (!need_relocation(reloc_dir))
        {
            // There is no relocation entry
            return true;
        }

        bitmap.resize((((nt_hdr->OptionalHeader.SizeOfImage + (SE_PAGE_SIZE - 1)) >> SE_PAGE_SHIFT) + 7) / 8);

        PIMAGE_BASE_RELOCATION reloc_blk =
            (PIMAGE_BASE_RELOCATION)(PEHelper<N>::get_raw_data(m_start_addr, nt_hdr,
                                     reloc_dir->VirtualAddress, reloc_dir->Size));
        if (reloc_blk == NULL)
            return false;

        uint64_t reloc_edge = (uint64_t)reloc_blk + reloc_dir->Size;

        // Relocation Table
        //                   DWORD          DWORD        WORD     WORD
        //      block[0]: VirtualAddress, SizeOfBlock, entry[0], entry[1], ....
        //      block[1]: VirtualAddress, SizeOfBlock, entry[0], entry[1], ....
        //      ....
        while(reloc_blk->SizeOfBlock != 0)
        {
            // Since relocation block is of page unit, we needn't tranverse each relocation entry.
            // But we need take care of the entry of which the offset is within [0xffd, 0xfff].
            // In such case the relocation will across two pages,
            // and we need change the protection attribute for both pages.
            bool across_boundary = false;
            uint16_t *entry_list = GET_PTR(uint16_t, reloc_blk, sizeof(IMAGE_BASE_RELOCATION));
            int entry_num = (reloc_blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
            if (entry_num <= 0)
                return false;
            for(unsigned idx = 0; idx < (unsigned int)entry_num; idx++)
            {
                uint16_t reloc_type = _get_reloc_type(entry_list[idx]);

                if (reloc_type == PETypes<N>::IMAGE_REL_TYPE)
                {
                    if((entry_list[idx] & 0xFFF) > PETypes<N>::RELOC_BOUNDARY)
                        across_boundary = true;
                }
            }

            //NOTE:
            //  Current enclave size is not beyond 64G, so the type-casting from (uint64>>15) to (size_t) is OK.
            //  In the future, if the max enclave size is extended to beyond 1<<49, this type-casting will not work.
            //  It only impacts the enclave signing process. (32bit signing tool to sign 64 bit enclaves)
            uint64_t page_frame = reloc_blk->VirtualAddress >> SE_PAGE_SHIFT;
            bitmap[(size_t)(page_frame / 8)] |= (1 << (page_frame % 8));

            if(across_boundary)
            {
                page_frame++;
                bitmap[(size_t)(page_frame / 8)] |= (1 << (page_frame % 8));
            }
            reloc_blk = GET_PTR(IMAGE_BASE_RELOCATION, reloc_blk, reloc_blk->SizeOfBlock);
            if ((uint64_t)reloc_blk >= reloc_edge)
                break;
        }

        return true;
    }

    void update_thread_data(const create_param_t* const create_param,
                            uint64_t enclave_size)
    {
        const Section* tls_sec = this->get_tls_section();

        // The file is mapped as COW, so we can write the mapped region.
        thread_data_t *thread_data = reinterpret_cast<thread_data_t*>(
                                         const_cast<uint8_t*>(tls_sec->raw_data()));

        do_update_thread_data(create_param, enclave_size, tls_sec, thread_data);
    }

    // Get the offsets (relative to the base address) of the relocation
    // address, which falls into the range of section identified by `sec_name'.
    void get_reloc_entry_offset(const char* sec_name,
                                vector<uint64_t>& offsets)
    {
        offsets.clear();

        if (sec_name == NULL)
            return;

        const pimage_nt_hdrs_t nt_hdr = PEHelper<N>::get_nt_header(m_start_addr, m_len);
        assert (nt_hdr != NULL);

        const PIMAGE_SECTION_HEADER sec_hdr = PEHelper<N>::get_section(nt_hdr, sec_name);
        if (sec_hdr == NULL)
            return;

        // Get the relocation directory
        const PIMAGE_DATA_DIRECTORY reloc_dir = &nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (!need_relocation(reloc_dir))
        {
            // There is no relocation entry
            return;
        }

        PIMAGE_BASE_RELOCATION reloc_blk =
            (PIMAGE_BASE_RELOCATION)(PEHelper<N>::get_raw_data(m_start_addr, nt_hdr,
                                     reloc_dir->VirtualAddress, reloc_dir->Size));
        if (reloc_blk == NULL)
            return;

        uint64_t reloc_edge = (uint64_t)reloc_blk + reloc_dir->Size;

        // Relocation Table
        //                   DWORD          DWORD        WORD     WORD
        //      block[0]: VirtualAddress, SizeOfBlock, entry[0], entry[1], ....
        //      block[1]: VirtualAddress, SizeOfBlock, entry[0], entry[1], ....
        //      ....
        while (reloc_blk->SizeOfBlock != 0)
        {
            uint16_t *entry_list = GET_PTR(uint16_t, reloc_blk, sizeof(IMAGE_BASE_RELOCATION));
            int entry_num = (reloc_blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);

            for(int idx = 0; idx < entry_num; ++idx)
            {
                uint16_t reloc_type = _get_reloc_type(entry_list[idx]);
                if (reloc_type == PETypes<N>::IMAGE_REL_TYPE)
                {
                    unsigned offset = (entry_list[idx] & 0xfff) + reloc_blk->VirtualAddress;
                    unsigned start_rva = sec_hdr->VirtualAddress;
                    unsigned end_rva = start_rva + sec_hdr->Misc.VirtualSize;

                    if( offset >= start_rva && offset < end_rva )
                    {
                        offsets.push_back(offset);
                    }
                }
            }

            reloc_blk = GET_PTR(IMAGE_BASE_RELOCATION, reloc_blk, reloc_blk->SizeOfBlock);
            if ((uint64_t)reloc_blk >= reloc_edge)
                break;
        }
    }

    sgx_status_t modify_info(enclave_diff_info_t *enclave_diff_info)
    {
        assert(enclave_diff_info != NULL);

        const pimage_nt_hdrs_t nt_hdr = PEHelper<N>::get_nt_header(m_start_addr, m_len);
        if (nt_hdr == NULL)
            return SGX_ERROR_INVALID_ENCLAVE;

        //clear time stamp for PE file
        if (!PEHelper<N>::update_enclave_with_enclave_diff_info(m_start_addr, nt_hdr, enclave_diff_info))
            return SGX_ERROR_INVALID_ENCLAVE;

        return SGX_SUCCESS;
    }

    sgx_status_t get_info(enclave_diff_info_t *enclave_diff_info)
    {
        assert(enclave_diff_info != NULL);

        const pimage_nt_hdrs_t nt_hdr = PEHelper<N>::get_nt_header(m_start_addr, m_len);
        if (nt_hdr == NULL)
            return SGX_ERROR_INVALID_ENCLAVE;

        //clear time stamp for PE file
        if (!PEHelper<N>::get_enclave_diff_info(m_start_addr, nt_hdr, enclave_diff_info))
            return SGX_ERROR_INVALID_ENCLAVE;

        return SGX_SUCCESS;
    }

    uint64_t get_preferred_base_addr() const
    {
        return m_preferred_base_addr;
    }

    void get_executable_sections(vector<const char *>& xsec_names) const
    {
        xsec_names.clear();
        const pimage_nt_hdrs_t nt_hdr = PEHelper<N>::get_nt_header(m_start_addr, m_len);
        assert(nt_hdr != NULL);

        PIMAGE_SECTION_HEADER sec_hdr = IMAGE_FIRST_SECTION(nt_hdr);
        const int nr_sec = nt_hdr->FileHeader.NumberOfSections;

        for (int idx = 0; idx < nr_sec; ++idx, ++sec_hdr)
        {
            if ((sec_hdr->Characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ))
                     == (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ))
            {
                xsec_names.push_back(reinterpret_cast<const char *> (sec_hdr->Name));
            }
        }
        return;
    }

    bool is_enclave_encrypted()const
    {
        //if enclave is encrypted, enclave should contain trts2 section
        const char* sec_name = "trts2";

        const pimage_nt_hdrs_t nt_hdr = PEHelper<N>::get_nt_header(m_start_addr, m_len);
        if (nt_hdr == NULL)
            return false;

        if (PEHelper<N>::get_section(nt_hdr, sec_name) != NULL)
        {
            return true;
        }
        return false;
    }

private:
    const uint8_t*      m_start_addr;
    uint64_t            m_len;
    bin_fmt_t           m_bin_fmt;
    vector<Section *>   m_sections;
    const Section*      m_tls_section;
    uint64_t            m_metadata_offset;
    uint64_t            m_preferred_base_addr;

    // A map from symbol name to its RVA
    map<string, uint64_t> m_sym_table;
};

#endif
