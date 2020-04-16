// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include "sgx_dcap_pcs_com.h"
#include "se_trace.h"
#include "se_thread.h"

#define SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME "dcap_quoteprov.dll"

HINSTANCE g_qpl_handle = NULL;
se_mutex_t g_qpl_mutex;

extern sgx_get_quote_verification_collateral_func_t p_sgx_ql_get_quote_verification_collateral;
extern sgx_free_quote_verification_collateral_func_t p_sgx_ql_free_quote_verification_collateral;

extern sgx_ql_get_qve_identity_func_t p_sgx_ql_get_qve_identity;
extern sgx_ql_free_qve_identity_func_t p_sgx_ql_free_qve_identity;

extern sgx_ql_get_root_ca_crl_func_t p_sgx_ql_get_root_ca_crl;
extern sgx_ql_free_root_ca_crl_func_t p_sgx_ql_free_root_ca_crl;



bool sgx_dcap_load_qpl()
{
    bool ret = false;

    int rc = se_mutex_lock(&g_qpl_mutex);
    if (rc != 1) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to lock qpl mutex");
        return false;
    }

    if (g_qpl_handle &&
            p_sgx_ql_get_quote_verification_collateral && p_sgx_ql_free_quote_verification_collateral &&
            p_sgx_ql_get_qve_identity && p_sgx_ql_free_qve_identity &&
            p_sgx_ql_get_root_ca_crl && p_sgx_ql_free_root_ca_crl) {

        ret = true;
        goto end;
    }

    do {

        //try to dynamically load dcap_quoteprov.dll
        //
		g_qpl_handle = LoadLibrary(TEXT(SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME));
        if (g_qpl_handle == NULL) {
            SE_TRACE(SE_TRACE_DEBUG, "Couldn't find the Quote's dependent library. %s.\n", SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            break;
        }

        //search for sgx_ql_get_quote_verification_collateral symbol in dcap_quoteprov library
        //
        p_sgx_ql_get_quote_verification_collateral = (sgx_get_quote_verification_collateral_func_t)GetProcAddress(g_qpl_handle, QL_API_GET_QUOTE_VERIFICATION_COLLATERAL);
        if (p_sgx_ql_get_quote_verification_collateral == NULL) {
            SE_TRACE(SE_TRACE_DEBUG, "Couldn't locate %s in Quote's dependent library. %s.\n", QL_API_GET_QUOTE_VERIFICATION_COLLATERAL, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            break;
        }

        //search for sgx_ql_free_quote_verification_collateral symbol in dcap_quoteprov library
        //
        p_sgx_ql_free_quote_verification_collateral = (sgx_free_quote_verification_collateral_func_t)GetProcAddress(g_qpl_handle, QL_API_FREE_QUOTE_VERIFICATION_COLLATERAL);
        if (p_sgx_ql_free_quote_verification_collateral == NULL) {
            SE_TRACE(SE_TRACE_DEBUG, "Couldn't locate %s in Quote's dependent library. %s.\n", QL_API_FREE_QUOTE_VERIFICATION_COLLATERAL, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            break;
        }

        //search for sgx_ql_get_qve_identity symbol in dcap_quoteprov library
        //
        p_sgx_ql_get_qve_identity = (sgx_ql_get_qve_identity_func_t)GetProcAddress(g_qpl_handle, QL_API_GET_QVE_IDENTITY);
        if (p_sgx_ql_get_qve_identity == NULL) {
            SE_TRACE(SE_TRACE_DEBUG, "Couldn't locate %s in Quote's dependent library. %s.\n", QL_API_GET_QVE_IDENTITY, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            break;
        }

        //search for sgx_ql_free_qve_identity symbol in dcap_quoteprov library
        //
        p_sgx_ql_free_qve_identity = (sgx_ql_free_qve_identity_func_t)GetProcAddress(g_qpl_handle, QL_API_FREE_QVE_IDENTITY);
        if (p_sgx_ql_free_qve_identity == NULL) {
            SE_TRACE(SE_TRACE_DEBUG, "Couldn't locate %s in Quote's dependent library. %s.\n", QL_API_FREE_QVE_IDENTITY, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            break;
        }

        //search for sgx_ql_get_root_ca_crl symbol in dcap_quoteprov library
        //
        p_sgx_ql_get_root_ca_crl = (sgx_ql_get_root_ca_crl_func_t)GetProcAddress(g_qpl_handle, QL_API_GET_ROOT_CA_CRL);
        if (p_sgx_ql_get_root_ca_crl == NULL) {
            SE_TRACE(SE_TRACE_DEBUG, "Couldn't locate %s in Quote's dependent library. %s.\n", QL_API_GET_ROOT_CA_CRL, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            break;
        }

        //search for sgx_ql_free_root_ca_crl symbol in dcap_quoteprov library
        //
        p_sgx_ql_free_root_ca_crl = (sgx_ql_free_root_ca_crl_func_t)GetProcAddress(g_qpl_handle, QL_API_FREE_ROOT_CA_CRL);
        if (p_sgx_ql_free_root_ca_crl == NULL) {
            SE_TRACE(SE_TRACE_DEBUG, "Couldn't locate %s in Quote's dependent library. %s.\n", QL_API_FREE_ROOT_CA_CRL, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            break;
        }


        ret = true;

    } while (0);


end:
    rc = se_mutex_unlock(&g_qpl_mutex);
    if (rc != 1) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to unlock qpl mutex");
        return false;
    }

    return ret;
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    (void)(hModule);
    (void)(lpReserved);
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        {
            se_mutex_init(&g_qpl_mutex);
            break;
        }
    case DLL_PROCESS_DETACH:
        // try to unload QPL if exist
        {
            int rc = se_mutex_lock(&g_qpl_mutex);
            if (rc != 1) {
                SE_TRACE(SE_TRACE_ERROR, "Failed to lock qpl mutex");
                //destroy the mutex before lib is unloaded, even there are some errs here
                se_mutex_destroy(&g_qpl_mutex);
                break;
            }

            if (p_sgx_ql_get_quote_verification_collateral)
                p_sgx_ql_get_quote_verification_collateral = NULL;
            if (p_sgx_ql_free_quote_verification_collateral)
                p_sgx_ql_free_quote_verification_collateral = NULL;

            if (p_sgx_ql_get_qve_identity)
                p_sgx_ql_get_qve_identity = NULL;
			if (p_sgx_ql_free_qve_identity)
				p_sgx_ql_free_qve_identity = NULL;

            if (p_sgx_ql_get_root_ca_crl)
                p_sgx_ql_get_root_ca_crl = NULL;
            if (p_sgx_ql_free_root_ca_crl)
                p_sgx_ql_free_root_ca_crl = NULL;

            if (g_qpl_handle) {
                FreeLibrary(g_qpl_handle);
                g_qpl_handle = NULL;
            }

            rc = se_mutex_unlock(&g_qpl_mutex);
            if (rc != 1) {
                SE_TRACE(SE_TRACE_ERROR, "Failed to unlock qpl mutex");
            }

           se_mutex_destroy(&g_qpl_mutex);

           break;
        }
    case DLL_THREAD_ATTACH:
	    break;
    case DLL_THREAD_DETACH:
	    break;
    }
    return TRUE;
}

