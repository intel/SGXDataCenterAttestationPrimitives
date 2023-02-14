#include <string>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <stdlib.h>
#include <string.h>
#include "sgx_dcap_qal.h"
#include "jwt-cpp/jwt.h"

// JWT token for policies - HS256
std::string platform_policy_str = "eyJhbGciOiJFUzM4NCIsImp3ayI6IntcImt0eVwiOlwiRUNcIixcInVzZVwiOlwic2lnXCIsXCJjcnZcIjpcIlAtMzg0XCIsXCJraWRcIjpcInpsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxcIixcInhcIjpcIlljYXhzeXkzS3dGYmJMQjViWDlTcXNlaU1uaUhMNFBYQmlsYXI4RGFESUdZUF9pcGVyQl9sbG1yaDFEckUzU0hcIixcInlcIjpcIlB4SzFOdWNxM2NEc0E1VEo2TlFSbXRINHRJY01kV1VuNTUtb0JWbmszRF9UTEFmdkUwOVJMWkp2NmFZYWhaaC1cIixcImFsZ1wiOlwiRVMzODRcIn0iLCJ0eXAiOiJKV1QifQ.eyJwb2xpY2llcyI6IntcInNneF9wbGF0Zm9ybVwiOntcImhlYWRlclwiOntcInZlcnNpb25cIjpcIjEuMFwiLFwiaWRcIjpcIklELXBlci1wb2xpY3ktaW5zdGFuY2VcIixcInR5cGVcIjpcIjxVVUlELXNneC1wbGF0Zm9ybT5cIixcImRlc2NyaXB0aW9uXCI6XCJTR1ggUGxhdGZvcm0gUG9saWN5IGZvciBBY21lIENTUFwiLFwic3ZuXCI6MTIzfSxcInRjYlwiOntcImFjY2VwdGVkX3RjYl9zdGF0dXNcIjpbXCJVcFRvRGF0ZVwiLFwiU1dIYXJkZW5pbmdOZWVkZWRcIixcIkNvbmZpZ3VyYXRpb25OZWVkZWRcIl0sXCJjb2xsYXRlcmFsX2dyYWNlX3BlcmlvZFwiOjI1OTIwMDAwMCxcInBsYXRmb3JtX2dyYWNlX3BlcmlvZFwiOjI1OTIwMDAwMCxcIm1pbl9ldmFsX251bVwiOjUsXCJhY2NlcHRlZF9wbGF0Zm9ybV9wcm92aWRlcl9pZHNcIjpbXCJwcGlkMVwiLFwicHBpZDJcIixcInBwaWQzXCJdLFwicmVxdWlyZWRfc2d4X3R5cGVzXCI6W1wiQ29uZmlkZW50aWFsaXR5UHJvdGVjdGVkXCJdLFwiYWxsb3dfZHluYW1pY19wbGFmb3JtXCI6dHJ1ZSxcImFsbG93X2NhY2hlZF9rZXlzX3BvbGljeVwiOnRydWUsXCJhbGxvd19zbXRfZW5hYmxlZFwiOmZhbHNlLFwicmVqZWN0ZWRfYWR2aXNvcnlfaWRzXCI6W1wiSU5URUwtU0EtMDAwNzhcIl19fX0ifQ.AUGyVGRFMNxN4Dp7-ZrBnn6FQZfNNbbr19NBMUHmFspn8dHxQlEg4FLVpT3FcqwCu0lYhSdd_DPaeDdv-NARERxRxAkVgxUUnGgwmjIbFVAsRY7_OUu4ruQKK8ZXyOvC";
// JWT token for policies - HS256
std::string enclave_policy_str = "eyJhbGciOiJFUzM4NCIsImp3ayI6IntcImt0eVwiOlwiRUNcIixcInVzZVwiOlwic2lnXCIsXCJjcnZcIjpcIlAtMzg0XCIsXCJraWRcIjpcInpsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxcIixcInhcIjpcIlljYXhzeXkzS3dGYmJMQjViWDlTcXNlaU1uaUhMNFBYQmlsYXI4RGFESUdZUF9pcGVyQl9sbG1yaDFEckUzU0hcIixcInlcIjpcIlB4SzFOdWNxM2NEc0E1VEo2TlFSbXRINHRJY01kV1VuNTUtb0JWbmszRF9UTEFmdkUwOVJMWkp2NmFZYWhaaC1cIixcImFsZ1wiOlwiRVMzODRcIn0iLCJ0eXAiOiJKV1QifQ.eyJwb2xpY2llcyI6IntcInNneF9lbmNsYXZlXCI6e1wiaGVhZGVyXCI6e1widmVyc2lvblwiOlwiMS4wXCIsXCJ0eXBlXCI6XCIgYmVmN2NiOGMtMzFhYS00MmMxLTg1NGMtMTBkYjAwNWQ1YzQxXCIsXCJkZXNjcmlwdGlvblwiOlwiQXBwbGljYXRpb24gU0dYIEVuY2xhdmUgUG9saWN5XCIsXCJzdm5cIjoxMjMsXCJpZFwiOlwiSUQtcGVyLXBvbGljeS1pbnN0YW5jZVwifSxcInRjYlwiOntcIm1pc2NzZWxlY3RcIjpcIjAxMjM0NTY3XCIsXCJtaXNjc2VsZWN0X21hc2tcIjpcIjAxMjM0NTY3XCIsXCJhdHRyaWJ1dGVzXCI6XCIwMTIzNDU2Nzg5QUJDREVGMDEyMzQ1Njc4OUFCQ0RFRlwiLFwiYXR0cmlidXRlc19tYXNrXCI6XCIwMTIzNDU2Nzg5QUJDREVGMDEyMzQ1Njc4OUFCQ0RFRlwiLFwiY2VfYXR0cmlidXRlc1wiOlwiMDFcIixcImNlX2F0dHJpYnV0ZXNfbWFza1wiOlwiMDFcIixcIm1yZW5jbGF2ZVwiOlwiPFN0cmluZz5cIixcIm1yc2lnbmVyXCI6XCI8U3RyaW5nPlwiLFwiaXN2cHJvZGlkXCI6MTIzLFwibWluX2lzdnN2blwiOjUsXCJjb25maWdpZFwiOlwiPFN0cmluZz5cIixcIm1pbl9jb25maWdzdm5cIjo2LFwiaXN2ZXh0cHJvZGlkXCI6XCI8U3RyaW5nPlwiLFwiaXN2ZmFtaWx5aWRcIjpcIjxVVUlELXN0cmluZz5cIn19fSJ9.3fPoYB-hUc-W0DjUDF8-Ckds6HDixFdst2LVfOQXFEaNXLWaR1i9DiL6sO2xFSYdm-iYP-DRlbp445e-XVBpbK17gkQmwirMNBa5MJ2Gg8CDxBmk7nt8SPGydYEyjbQZ";
std::string qvl_result = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJxdmxfcmVzdWx0Ijoie1wiZW5jbGF2ZV90Y2JcIjp7XCJoZWFkZXJcIjp7XCJ0eXBlXCI6XCI8VVVJRC1zZ3gtZW5jbGF2ZT5cIixcInZlcnNpb25cIjpcIjEuMFwifSxcInRjYlwiOntcIm1pc2NzZWxlY3RcIjpcIjAxMjM0NTY3XCIsXCJhdHRyaWJ1dGVzXCI6XCIwMTIzNDU2Nzg5QUJDREVGMDEyMzQ1Njc4OUFCQ0RFRlwiLFwiY2VfYXR0cmlidXRlc1wiOlwiMDFcIixcIm1yZW5jbGF2ZVwiOlwiPFN0cmluZz5cIixcIm1yc2lnbmVyXCI6XCI8U3RyaW5nPlwiLFwiaXN2cHJvZGlkXCI6MTIzLFwiaXN2c3ZuXCI6NSxcImNvbmZpZ2lkXCI6XCI8U3RyaW5nPlwiLFwiY29uZmlnc3ZuXCI6NixcImlzdmV4dHByb2RpZFwiOlwiPFN0cmluZz5cIixcImlzdmZhbWlseWlkXCI6XCI8VVVJRC1zdHJpbmc-XCIsXCJyZXBvcnRkYXRhXCI6XCI8NjQtYnl0ZXM-XCJ9fSxcInBsYXRmb3JtX3RjYlwiOntcImhlYWRlclwiOntcInR5cGVcIjpcIjxVVUlELXNneC1wbGF0Zm9ybT5cIixcInZlcnNpb25cIjpcIjEuMFwiLFwicmVxdWVzdF9pZFwiOjEyMzQ1Njc4OSxcInZlcmlmaWNhdGlvbl90aW1lXCI6XCIyMDIyLTAyLTEzVDAwOjAwOjAwWlwifSxcInRjYlwiOntcInRjYl9zdGF0dXNcIjpbXCJVcFRvRGF0ZVwiLFwiU1dIYXJkZW5pbmdOZWVkZWRcIl0sXCJlYXJsaWVzdF9pc3N1ZV9kYXRlXCI6XCIyMDIyLTAyLTEyVDAwOjAwOjAwWlwiLFwibGF0ZXN0X2lzc3VlX2RhdGVcIjpcIjIwMjItMDItMTVUMDA6MDA6MDBaXCIsXCJlYXJsaWVzdF9leHBpcmF0aW9uX2RhdGVcIjpcIjIwMjItMDMtMTBUMDA6MDA6MDBaXCIsXCJ0Y2JfbGV2ZWxfZGF0ZV90YWdcIjpcIjIwMjAtMDctMjhUMDA6MDA6MDBaXCIsXCJ0Y2JfZXZhbF9udW1cIjo1LFwicGxhdGZvcm1fcHJvdmlkZXJfaWRcIjpcInBwaWQxXCIsXCJzZ3hfdHlwZXNcIjpbXCJDb25maWRlbnRpYWxpdHlQcm90ZWN0ZWRcIl0sXCJpc19keW5hbWljX3BsYWZvcm1cIjpmYWxzZSxcImlzX2NhY2hlZF9rZXlzX3BvbGljeVwiOnRydWUsXCJpc19zbXRfZW5hYmxlZFwiOmZhbHNlLFwiYWR2aXNvcnlfaWRzXCI6W1wiSU5URUwtU0EtMDAwNzlcIixcIklOVEVMLVNBLTAwMDc3XCJdfSxcImVuZG9yc2VtZW50XCI6e1wicGNrX2NybF9pc3N1ZXJfY2hhaW5cIjpcIjxiYXNlNjQtZW5jb2RlZC1zdHJpbmc-XCIsXCJyb290X2NhX2NybFwiOlwiPGJhc2U2NC1lbmNvZGVkLXN0cmluZz5cIixcInBja19jcmxcIjpcIjxiYXNlNjQtZW5jb2RlZC1zdHJpbmc-XCIsXCJ0Y2JfaW5mb19pc3N1ZXJfY2hhaW5cIjpcIjxiYXNlNjQtZW5jb2RlZC1zdHJpbmc-XCIsXCJ0Y2JfaW5mb1wiOlwiPGJhc2U2NC1lbmNvZGVkLXN0cmluZz5cIixcInFlX2lkZW50aXR5X2lzc3Vlcl9jaGFpblwiOlwiPGJhc2U2NC1lbmNvZGVkLXN0cmluZz5cIixcInFlX2lkZW50aXR5XCI6XCI8YmFzZTY0LWVuY29kZWQtc3RyaW5nPlwifX19In0.";


unsigned char *
read_file_to_buffer(const char *filename, uint32_t *ret_size)
{
    unsigned char *buffer;
    FILE *file;
    size_t file_size, read_size;

    if (!filename || !ret_size) {
        printf("Read file to buffer failed: invalid filename or ret size.\n");
        return NULL;
    }

    if (!(file = fopen(filename, "r"))) {
        printf("Read file to buffer failed: open file %s failed.\n", filename);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (!(buffer = (unsigned char *)malloc(file_size + 1))) {
        printf("Read file to buffer failed: alloc memory failed.\n");
        fclose(file);
        return NULL;
    }
	memset(buffer, 0, file_size+1);
    read_size = fread(buffer, 1, file_size, file);
    fclose(file);

    if (read_size < file_size) {
        printf("Read file to buffer failed: read file content failed.\n");
        free(buffer);
        return NULL;
    }

    *ret_size = (uint32_t)file_size;

    return buffer;
}

int main()
{
    uint8_t appraisal_result[0x6000] = {0};
    uint32_t appraisal_result_buf_size = 0x6000;

	const char *p_qaps[2] = {enclave_policy_str.c_str(), platform_policy_str.c_str()};
	time_t current_time;
	time(&current_time);
	uint32_t fsize = 0;

#ifndef READ_FROM_FILE
    quote3_error_t ret = tee_appraise_verification_token((const uint8_t *)qvl_result.c_str(), (uint8_t **)p_qaps, 2, current_time, 
	                                 NULL, &appraisal_result_buf_size, appraisal_result);
#else
	unsigned char * qvl = read_file_to_buffer("./token.txt", &fsize);
    quote3_error_t ret = tee_appraise_verification_token((const uint8_t *)qvl, (uint8_t **)p_qaps, 2, current_time,
	                                 NULL, &appraisal_result_buf_size, appraisal_result);
    free(qvl);
#endif
	if(ret == SGX_QL_SUCCESS)
    {
        printf("Succeed\n");
        return 0;
    }
    else if(appraisal_result_buf_size > 0x6000)
    {
        printf("size = %#x\n", appraisal_result_buf_size);
        return -1;
    }
    else{
        printf("Failed, ret = %#x\n", ret);
        return -1;
    }
}