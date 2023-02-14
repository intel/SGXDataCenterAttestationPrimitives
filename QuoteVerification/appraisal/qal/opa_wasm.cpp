/*
 * Copyright (C) 2011-2023 Intel Corporation. All rights reserved.
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

#include "wasm_export.h"
#include "sgx_dcap_qal.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <map>
#include "jwt-cpp/jwt.h"
#include "opa_builtins.h"
#include "opa_helper.h"
#include "opa_wasm.h"
#include "se_memcpy.h"
#include "se_trace.h"

std::map<int, std::string> g_builtins;

std::map<std::string, void *> g_builtin_func_map;

#ifdef USE_LOCAL_WASM
#define WASM_FILE "./policy.wasm"
#else
#define WASM_FILE "/usr/share/sgx/sgx_appraisal_policy.wasm"
#endif

#define CHECK_OPA_RET(val) if(val == 0) {return SGX_QL_ERROR_UNEXPECTED;}

static NativeSymbol native_symbols[] = {
    {"opa_builtin0", (void *)opa_builtin0, "(i*)i", NULL},
    {"opa_builtin1", (void *)opa_builtin1, "(i**)i", NULL},
    {"opa_builtin2", (void *)opa_builtin2, "(i***)i", NULL},
    {"opa_builtin3", (void *)opa_builtin3, "(i****)i", NULL},
    {"opa_builtin4", (void *)opa_builtin4, "(i*****)i", NULL},
    {"opa_abort", (void *)opa_abort, "($)", NULL}};

OPAEvaluateEngine::OPAEvaluateEngine()
{
    m_stack_size = DEFAULT_STACK_SIZE;
    m_heap_size = DEFAULT_HEAP_SIZE;
    m_exec_env = NULL;
    m_wasm_module = NULL;
    m_wasm_module_inst = NULL;
    m_wasm_file_buf = NULL;
    m_wasm_file_size = 0;
    m_heap_addr_for_eval = 0;
}

OPAEvaluateEngine::~OPAEvaluateEngine()
{
    if (m_exec_env)
        wasm_runtime_destroy_exec_env(m_exec_env);
    if (m_wasm_module_inst)
    {
        wasm_runtime_deinstantiate(m_wasm_module_inst);
    }
    if (m_wasm_module)
        wasm_runtime_unload(m_wasm_module);
    if (m_wasm_file_buf)
        free(m_wasm_file_buf);
    wasm_runtime_destroy();
}

int OPAEvaluateEngine::read_wasm_file()
{
    unsigned char *buffer;
    FILE *file;
    long file_size, read_size;

    if (!(file = fopen(WASM_FILE, "rb")))
    {
        SE_TRACE(SE_TRACE_DEBUG, "Read file to buffer failed: open file %s failed.\n", WASM_FILE);
        return -1;
    }

    if (fseek(file, 0, SEEK_END))
    {
        fclose(file);
        return -1;
    }
    if ((file_size = ftell(file)) == -1)
    {
        fclose(file);
        return -1;
    }
    if (fseek(file, 0, SEEK_SET))
    {
        fclose(file);
        return -1;
    }

    if (!(buffer = (unsigned char *)malloc(file_size)))
    {
        SE_TRACE(SE_TRACE_ERROR, "Alloc memory failed.\n");
        fclose(file);
        return 1;
    }

    read_size = fread(buffer, 1, file_size, file);
    fclose(file);

    if (read_size < file_size)
    {
        SE_TRACE(SE_TRACE_ERROR, "Read file to buffer failed: read file content failed.\n");
        free(buffer);
        return -1;
    }

    m_wasm_file_size = file_size;
    m_wasm_file_buf = buffer;
    return 0;
}

quote3_error_t OPAEvaluateEngine::prepare_wasm(uint32_t stack_size, uint32_t heap_size)
{
    RuntimeInitArgs init_args;
    char error_buf[128] = {0};

    memset(&init_args, 0, sizeof(RuntimeInitArgs));

    init_args.mem_alloc_type = Alloc_With_Allocator;
    init_args.mem_alloc_option.allocator.malloc_func = (void *)malloc;
    init_args.mem_alloc_option.allocator.realloc_func = (void *)realloc;
    init_args.mem_alloc_option.allocator.free_func = (void *)free;

    // Native symbols need below registration phase
    init_args.n_native_symbols = sizeof(native_symbols) / sizeof(NativeSymbol);
    init_args.native_module_name = "env";
    init_args.native_symbols = native_symbols;

    g_builtin_func_map.insert(std::pair<std::string, void *>("time.parse_rfc3339_ns", (void *)get_ns_since_epoch));
    g_builtin_func_map.insert(std::pair<std::string, void *>("time.now_ns", (void *)get_now_ns));

    // Set the heap/stack size
    m_stack_size = stack_size;
    m_heap_size = heap_size;

    if (!wasm_runtime_full_init(&init_args))
    {
        SE_TRACE(SE_TRACE_DEBUG, "Init runtime environment failed.\n");
        return SGX_QL_ERROR_UNEXPECTED;
    }
    /* load WASM byte buffer from WASM bin file */
    int ret = read_wasm_file();
    if (ret != 0)
    {
        if(ret == 1)
            return SGX_QL_ERROR_OUT_OF_MEMORY;
        return SGX_QL_ERROR_UNEXPECTED;
    }
    /* load WASM module */
    if (!(m_wasm_module = wasm_runtime_load(m_wasm_file_buf, (uint32_t)m_wasm_file_size,
                                            error_buf, sizeof(error_buf))))
    {
        SE_TRACE(SE_TRACE_DEBUG, "%s\n", error_buf);
        return SGX_QL_ERROR_UNEXPECTED;
    }

    /* instantiate the module */
    if (!(m_wasm_module_inst =
              wasm_runtime_instantiate(m_wasm_module, m_stack_size, m_heap_size,
                                       error_buf, sizeof(error_buf))))
    {
        SE_TRACE(SE_TRACE_DEBUG, "%s\n", error_buf);
        return SGX_QL_ERROR_UNEXPECTED;
    }
    if (!(m_exec_env = wasm_runtime_create_exec_env(m_wasm_module_inst, m_stack_size)))
    {
        SE_TRACE(SE_TRACE_DEBUG, "Create wasm execution environment failed.\n");
        return SGX_QL_ERROR_UNEXPECTED;
    }

    // Retrieve the builtin maps
    int builtins = opa_builtins(m_wasm_module_inst, m_exec_env);
    CHECK_OPA_RET(builtins);

    int json_builtins = opa_json_dump(m_wasm_module_inst, m_exec_env, builtins);
    CHECK_OPA_RET(json_builtins);

    char *json_buffer_builtins = (char *)wasm_runtime_addr_app_to_native(m_wasm_module_inst, json_builtins);
    picojson::value v;
    std::string err;
    picojson::parse(v, json_buffer_builtins, json_buffer_builtins + strlen(json_buffer_builtins), &err);
    if (!err.empty())
    {
        SE_TRACE(SE_TRACE_DEBUG, "%s\n", err.c_str());
        return SGX_QL_ERROR_UNEXPECTED;
    }
    // check if the type of the value is "object"
    if (!v.is<picojson::object>())
    {
        SE_TRACE(SE_TRACE_DEBUG, "JSON is not an object\n");
        return SGX_QL_ERROR_UNEXPECTED;
    }

    // Set the g_builtins
    const picojson::value::object &obj = v.get<picojson::object>();
    for (picojson::value::object::const_iterator i = obj.begin(); i != obj.end(); ++i)
    {
        g_builtins.insert(std::pair<int, std::string>(stoi(i->second.to_str()), i->first));
    }

    m_heap_addr_for_eval = opa_heap_ptr_get(m_wasm_module_inst, m_exec_env);
    CHECK_OPA_RET(m_heap_addr_for_eval);
    return SGX_QL_SUCCESS;
}

quote3_error_t OPAEvaluateEngine::start_eval(const uint8_t *input_json_buf, uint32_t json_size, const time_t appraisal_check_date, uint32_t *p_appraisal_result_token_buffer_size, uint8_t *p_appraisal_result_token)
{
    // Record the heap addr before evaluation 
    int heap_addr = opa_heap_ptr_get(m_wasm_module_inst, m_exec_env);
    if (heap_addr != m_heap_addr_for_eval)
    {
        opa_heap_ptr_set(m_wasm_module_inst, m_exec_env, m_heap_addr_for_eval);
    }

    // Set the check data as `current time` for OPA builtin
    g_current_time = appraisal_check_date;
    int ctx = opa_eval_ctx_new(m_wasm_module_inst, m_exec_env);
    CHECK_OPA_RET(ctx);

    int input_buffer = opa_malloc(m_wasm_module_inst, m_exec_env, json_size);
    CHECK_OPA_RET(input_buffer);

    void *json_buffer = wasm_runtime_addr_app_to_native(m_wasm_module_inst, input_buffer);
    memset(json_buffer, 0, json_size);

    memcpy_s((void *)json_buffer, json_size, input_json_buf, json_size);

    int input = opa_json_parse(m_wasm_module_inst, m_exec_env, input_buffer, json_size);
    CHECK_OPA_RET(input);

    opa_eval_ctx_set_input(m_wasm_module_inst, m_exec_env, ctx, input);

    int ret = eval(m_wasm_module_inst, m_exec_env, ctx);
    if (ret != 0)
    {
        SE_TRACE(SE_TRACE_ERROR, "OPA eval() returns failure\n");
        return SGX_QL_ERROR_UNEXPECTED;
    }

    int result = opa_eval_ctx_get_result(m_wasm_module_inst, m_exec_env, ctx);
    CHECK_OPA_RET(result);
    int json_result = opa_json_dump(m_wasm_module_inst, m_exec_env, result);
    CHECK_OPA_RET(json_result);

    char *json_buffer_result = (char *)wasm_runtime_addr_app_to_native(m_wasm_module_inst, json_result);
    SE_TRACE(SE_TRACE_NOTICE, "eval result is: %s\n", (char *)json_buffer_result);

    opa_free(m_wasm_module_inst, m_exec_env, input_buffer);
    std::string str(json_buffer_result);

    auto token = jwt::create()
                     .set_type("JWT")
                     .set_payload_claim("appraisal_result", jwt::claim(str))
                     .sign(jwt::algorithm::none{});
    SE_TRACE_ERROR("Unsigned token: %s\n", token.c_str());

    if (*p_appraisal_result_token_buffer_size <  token.length() + 1)
    {
        SE_TRACE_ERROR("ERROR! Please enlarge the appraisal result token buffer.\n");
        *p_appraisal_result_token_buffer_size = (uint32_t)token.length() + 1;
        return SGX_QL_ERROR_OUT_OF_MEMORY;
    }
    else
    {
        memcpy_s(p_appraisal_result_token, *p_appraisal_result_token_buffer_size, token.c_str(), token.length());
        p_appraisal_result_token[token.length()] = 0;
        *p_appraisal_result_token_buffer_size = (uint32_t)token.length() + 1;
    }

    return SGX_QL_SUCCESS;
}
