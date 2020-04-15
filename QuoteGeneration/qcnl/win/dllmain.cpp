// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include <tchar.h>
#include <stdlib.h>

#define MAX_URL_LENGTH  2083
#define REG_KEY_SGX_QCNL                _T("SOFTWARE\\Intel\\SGX\\QCNL")
#define REG_VALUE_QCNL_PCCS_URL         _T("PCCS_URL")
#define REG_VALUE_QCNL_USE_SECURE_CERT  _T("USE_SECURE_CERT")

// Default URL for PCCS server if registry key doesn't exist
char server_url[MAX_URL_LENGTH] = "https://localhost:8081/sgx/certification/v2/";
// Use secure HTTPS certificate or not
bool g_use_secure_cert = true;
bool g_isWin81OrLater = true;

bool isWin81OrLater();

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    (void)hModule;
    (void)lpReserved;
    switch (ul_reason_for_call)
    {
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        return TRUE;
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
		break;
    }

    // Get Windows Version
    g_isWin81OrLater = isWin81OrLater();

    // Read configuration data from registry
    // Open the Registry Key
    HKEY key = NULL;
    LSTATUS status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, REG_KEY_SGX_QCNL, 0, KEY_READ, &key);
    if (ERROR_SUCCESS != status) {
        // Use default value
        return TRUE;
    }

    DWORD type, count;
    TCHAR url[MAX_URL_LENGTH] = { 0 };

    count = MAX_URL_LENGTH * sizeof(TCHAR);
    status = RegQueryValueEx(key, REG_VALUE_QCNL_PCCS_URL, NULL, &type, (LPBYTE)url, &count);
    if (ERROR_SUCCESS == status && type == REG_SZ) {
        size_t input_len = _tcsnlen(url, MAX_URL_LENGTH);
        size_t output_len = 0;

        if (wcstombs_s(&output_len, server_url, MAX_URL_LENGTH, url, input_len) != 0) {
            RegCloseKey(key);
            return FALSE;
        }
    }

    count = sizeof(DWORD);
    DWORD dwSecureCert = 0;
    status = RegQueryValueEx(key, REG_VALUE_QCNL_USE_SECURE_CERT, NULL, &type, (LPBYTE)&dwSecureCert, &count);
    if (ERROR_SUCCESS == status && type == REG_DWORD) {
        g_use_secure_cert = (dwSecureCert != 0);
    }

    RegCloseKey(key);

    return TRUE;
}

