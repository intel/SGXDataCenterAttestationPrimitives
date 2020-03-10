/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
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


namespace {
    void do_update_thread_data(const create_param_t* const create_param,
                               uint64_t enclave_size,
                               const Section* tls_sec,
                               thread_data_t* thread_data)
    {
#if (RTS_SYSTEM_WORDSIZE == 32)
        thread_data->seh_header = 0xFFFFFFFF;
#endif
        // offset of last_sp relative to TCS -- TCS + TD(TLS) +  guard page + SSA + guard page + stack size
        thread_data->last_sp = TCS_SIZE
            + (sys_word_t)ROUND_TO_PAGE(tls_sec->virtual_size())
            + SE_GUARD_PAGE_SIZE
            + create_param->ssa_frame_size * create_param->ssa_num * SE_PAGE_SIZE
            + SE_GUARD_PAGE_SIZE
            + (sys_word_t)create_param->stack_size;
        thread_data->stack_base_addr = (sys_word_t)thread_data->last_sp;
        thread_data->stack_limit_addr = thread_data->stack_base_addr - (sys_word_t)create_param->stack_size;

        // offset of heap relative to enclave base
        thread_data->info.heap_offset = (sys_word_t)create_param->heap_offset;

        thread_data->heap_size = (uint32_t)create_param->heap_size;

        // enclave virtual size
        thread_data->info.enclave_size = (sys_word_t)enclave_size;

        // offset of ssa relative to TCS ---  TCS + TD(TLS) + guard page
        thread_data->first_ssa_base = TCS_SIZE
            + (sys_word_t)ROUND_TO_PAGE(tls_sec->virtual_size())
            + SE_GUARD_PAGE_SIZE;

        // ssa frame size
        thread_data->ssa_frame_size = create_param->ssa_frame_size;

        // TD address relative to TCS
        thread_data->self_addr = SE_PAGE_SIZE;
        thread_data->tls_array = reinterpret_cast<uintptr_t>(&(((thread_data_t *)SE_PAGE_SIZE)->self_addr));

        // first ssa gpr start address relative to TCS
        thread_data->first_ssa_gpr = thread_data->first_ssa_base + create_param->ssa_frame_size * SE_PAGE_SIZE - (uint32_t)sizeof(ssa_gpr_t);

        //curretly there is only 2 options of thread policy, bind mode and unbind mode.
        //In unbind mode trts will initialize thread data on root ECALL.
        //If there is more thread policy, trts may needn't know the thread policy.
        //BE CAREFUL TO set thread_data->thread_policy when new thread policy is added.
        thread_data->thread_policy = (uint8_t)create_param->tcs_policy;
    }
}
