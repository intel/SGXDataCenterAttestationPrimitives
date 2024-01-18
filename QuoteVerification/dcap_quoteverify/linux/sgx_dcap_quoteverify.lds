{
global:
    sgx_qv_verify_quote;
    sgx_qv_get_quote_supplemental_data_size;
    sgx_qv_set_enclave_load_policy;
    sgx_qv_get_qve_identity;
    sgx_qv_free_qve_identity;
    sgx_qv_set_path;
    tdx_qv_get_quote_supplemental_data_size;
    tdx_qv_verify_quote;
    tee_qv_get_collateral;
    tee_qv_free_collateral;
    tee_get_supplemental_data_version_and_size;
    tee_verify_quote;
    tee_get_fmspc_from_quote;
    tee_verify_quote_qvt;
    tee_free_verify_quote_qvt;
    sgx_trace_logger_callback;
    sgx_trace_loglevel;

    tee_appraise_verification_token;
    tee_free_appraisal_token;
    tee_authenticate_appraisal_result;
local:
    *;
};


