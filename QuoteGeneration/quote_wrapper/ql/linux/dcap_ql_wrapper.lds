{
global:
    sgx_qe_set_enclave_load_policy;
    sgx_qe_get_target_info;
    sgx_qe_get_quote_size;
    sgx_qe_get_quote;
    sgx_qe_cleanup_by_policy;
    sgx_ql_set_path;
    sgx_trace_logger_callback;
    sgx_trace_loglevel;
    sgx_ql_set_trace_callback;
local:
    *;
};

