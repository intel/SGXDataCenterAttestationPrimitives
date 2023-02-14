## Introduction
The SGX Attestation Appraisal functionality is part of DCAP Attestation. A tool and three APIs are provided for the appraisal functionality:

* **APIs**:
```bash
/**
 * Get quote verification result token.
 *
 * @param p_quote[IN] - Pointer to SGX Quote.
 * @param quote_size[IN] - Size of the buffer pointed to by p_quote (in bytes).
 * @param p_quote_collateral[IN] - The parameter is optional. This is a pointer to the Quote Certification Collateral provided by the caller.
 * @param p_qve_report_info[IN/OUT] - This parameter can be used in 2 ways.
 *        If p_qve_report_info is NOT NULL, the API will use Intel QvE to perform quote verification, and QvE will generate a report using the target_info in sgx_ql_qe_report_info_t structure.
 *        If p_qve_report_info is NULL, the API will use QVL library to perform quote verification, note that the results can not be cryptographically authenticated in this mode.
 * @param p_user_data[IN] - User data.
 * @param p_verification_result_token_buffer_size[OUT] - Size of the buffer pointed to by verification_result_token (in bytes).
 * @param p_verification_result_token[OUT] - Pointer to the verification_result_token.
 *
 * @return Status code of the operation, one of:
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_ERROR_OUT_OF_MEMORY
 *      - SGX_QL_ERROR_UNEXPECTED
 **/
quote3_error_t  tee_verify_quote_qvt(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const sgx_ql_qve_collateral_t *p_quote_collateral,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    const uint8_t *p_user_data,
    uint32_t *p_verification_result_token_buffer_size,
    uint8_t **p_verification_result_token)

 /**
 * Free quote verification result token buffer, which returned by `tee_verify_quote_qvt`
 *
 * @param p_verification_result_token[IN] - Pointer to verification result token
 * @param p_verification_result_token_buffer_size[IN] - Pointer to verification result token size
 *
 * @return Status code of the operation, one of:
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_ERROR_INVALID_PARAMETER
 **/
quote3_error_t tee_free_verify_quote_qvt(
    uint8_t *p_verification_result_token,
    uint32_t *p_verification_result_token_buffer_size) 

/**
 * Appraise a Verification Result JWT against one or more Quote Appraisal Policies
 *
 * @param p_verification_result_token[IN] - Points to a null-terminated string containing the input Verification Result JWT.
 * @param p_qaps[IN] - Points to an array of pointers, with each pointer pointing to a buffer holding a quote appraisal policy JWT token. Each token is a null-terminated string holding a JWT.
 * @param qaps_count[IN] - The number of pointers in the p_qaps array.
 * @param appraisal_check_date[IN] - -	User input, used by the appraisal engine as its “current time” for expiration dates check.
 * @param p_qae_report_info[IN, OUT] - The parameter is optional.
 * @param p_appraisal_result_token_buffer_size[IN, OUT] - Points to hold the size of the p_appraisal_result_token buffer.
 * @param p_appraisal_result_token[OUT] - Points to the output Appraisal result JWT.
 *
 * @return Status code of the operation. SGX_QL_SUCCESS or failure as defined in sgx_ql_lib_common.h
 **/
    quote3_error_t tee_appraise_verification_token(
    const uint8_t *p_verification_result_token,
    uint8_t **p_qaps,
    uint8_t qaps_count,
    const time_t appraisal_check_date,
    sgx_ql_qe_report_info_t *p_qae_report_info,
    uint32_t *p_appraisal_result_token_buffer_size,
    uint8_t *p_appraisal_result_token)
    
```

* **Tool**: [tee_appraisal_tool](qal/tee_appraisal_tool)  
       It is used to generate a signed JWT based on the input appraisal policy. It also could help to translate the qvl_result to an unsigned JWT.
    ```bash
      $ tee_appraisal_tool {your_policy_manifest.json}
    ```


#### Tool Usage
- Prepare the enclave policy and platform policy. The folder [tee_appraisal_tool/data](qal/tee_appraisal_tool/data) provides some policy manifest templates. The [QuoteAppraisalSample](../../SampleCode/QuoteAppraisalSample) also provides some policy examples. You can refer to them to generate your own appraisal policies. The policy templates provides a default ECDSA signing key pair with below format:     
   * 384 bits   
   * private key - PEM format   
    * public key - JWK format             

If you want to generate your own ECDSA signing key pair, run below command to utilize the OpenSSL with the tool https://github.com/danedmunds/pem-to-jwk:    
```bash
    $ openssl ecparam -name secp384r1 -genkey --noout > ec_priv.pem
    $ cat ec_priv.pem | docker run -i danedmunds/pem-to-jwk:latest --public  --pretty
 ```

 
 - Sign the policies with the tool `tee_appraisal_tool`:
    * Go to qal/tee_appraisal_tool folder and  run `tee_appraisal_tool` to sign the policies:
    ```bash
      $ tee_appraisal_tool {your_policy_manifest.json}
    ```
    
Please refer to [QuoteAppraisalSample](../../SampleCode/QuoteAppraisalSample) for the whole workflow for SGX appraisal.
