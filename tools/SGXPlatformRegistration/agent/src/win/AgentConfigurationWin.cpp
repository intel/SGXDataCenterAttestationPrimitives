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
/**
 * File: AgentConfigurationWin.cpp
 *  
 * Description: Windows implementation for retrieving the MP Agent
 *              configurations.  
 *
 */
#include <Windows.h>
#include <tchar.h>
#include "AgentConfiguration.h"
#include "agent_logger.h"
#include "common.h"

static const TCHAR *get_registry_entry_path(mp_config_type entry)
{
    switch (entry) {
    case MP_PROXY_CONF:
        return _T("SOFTWARE\\Intel\\SGX_RA\\RAProxy");
    case MP_LOG_LEVEL_CONF:
        return _T("SOFTWARE\\Intel\\SGX_RA\\RALog");
    case MP_SUBSCRIPTION_KEY_CONF:
        return _T("SOFTWARE\\Intel\\SGX_RA\\RASubscriptionKey");
    default:
        return NULL;
    }
}

MpResult aesm_read_registry_dword(mp_config_type entry, const TCHAR *name, uint32_t *result)
{
    const TCHAR *entry_path = get_registry_entry_path(entry);
    if (entry_path == NULL) {
        agent_log_message(MP_REG_LOG_LEVEL_ERROR, "Cannot find registry entry path\n");
        return MP_INVALID_PARAMETER;
    }
    HKEY key = NULL;
    LSTATUS status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, entry_path, 0, KEY_READ, &key);
    if (ERROR_SUCCESS != status) {
        agent_log_message(MP_REG_LOG_LEVEL_ERROR, "Fail to open registry key (%s), return value %ld\n", entry_path, status);
        return MP_UNEXPECTED_ERROR;
    }
    DWORD type, count;
    count = sizeof(uint32_t);
    status = RegQueryValueEx(key, name, NULL, &type, (LPBYTE)result, &count);
    RegCloseKey(key);
    if (ERROR_SUCCESS != status ||
        type != REG_DWORD) {
        agent_log_message(MP_REG_LOG_LEVEL_ERROR, "Fail to query value %s:status=%d, type=%d\n", name, (int)status, (int)type);
        return MP_UNEXPECTED_ERROR;
    }
    return MP_SUCCESS;
}

MpResult aesm_write_registry_dword(mp_config_type entry, const TCHAR *name, uint32_t result)
{
    const TCHAR *entry_path = get_registry_entry_path(entry);
    if (entry_path == NULL) {
        agent_log_message(MP_REG_LOG_LEVEL_ERROR, "Cannot find registry entry path\n");
        return MP_INVALID_PARAMETER;
    }
    HKEY key = NULL;
    LSTATUS status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, entry_path, 0, KEY_WRITE, &key);
    if (ERROR_SUCCESS != status) {
        agent_log_message(MP_REG_LOG_LEVEL_ERROR, "Fail to open registry key (%s), return value %ld\n", entry_path, status);
        return MP_UNEXPECTED_ERROR;
    }
    DWORD type, count;
    type = REG_DWORD;
    count = sizeof(uint32_t);
    status = RegSetValueEx(key, name, NULL, type, (LPBYTE)&result, count);
    RegCloseKey(key);
    if (ERROR_SUCCESS != status) {
        agent_log_message(MP_REG_LOG_LEVEL_ERROR, "Fail to set value %s:status=%d\n", name, (int)status);
        return MP_UNEXPECTED_ERROR;
    }
    return MP_SUCCESS;
}

MpResult aesm_read_registry_value(const TCHAR * registry_path, const TCHAR *name, TCHAR value[], uint32_t tchar_num)
{
    HKEY key = NULL;
    if (!registry_path || !name || !value || !tchar_num)
        return MP_INVALID_PARAMETER;
    LSTATUS status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, registry_path, 0, KEY_READ, &key);
    if (ERROR_SUCCESS != status) {
        agent_log_message(MP_REG_LOG_LEVEL_ERROR, "Fail to open registry key (%s), return value %ld\n", registry_path, status);
        return MP_UNEXPECTED_ERROR;
    }
    DWORD type, count;
    count = tchar_num * sizeof(TCHAR);
    status = RegQueryValueEx(key, name, NULL, &type, (LPBYTE)value, &count);
    RegCloseKey(key);
    if (ERROR_SUCCESS != status ||
        type != REG_SZ) {
        agent_log_message(MP_REG_LOG_LEVEL_ERROR, "Fail to query value s: name (%s) status=%d, type=%d\n", name, (int)status, (int)type);
        return MP_UNEXPECTED_ERROR;
    }
    if (strnlen(value, tchar_num) >= tchar_num) {
        return MP_UNEXPECTED_ERROR;
    }
    return MP_SUCCESS;
}

MpResult aesm_read_registry_string(mp_config_type entry, const TCHAR *name, TCHAR value[], uint32_t tchar_num)
{
    const TCHAR *entry_path = get_registry_entry_path(entry);
    if (entry_path == NULL) {
        agent_log_message(MP_REG_LOG_LEVEL_ERROR, "Cannot find registry entry path\n");
        return MP_UNEXPECTED_ERROR;
    }
    return aesm_read_registry_value(entry_path, name, value, tchar_num);
}

/*
#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

MpResult aesm_query_install_path(const TCHAR *base_path, const TCHAR *target_component, const TCHAR *sub_path,
    const TCHAR *name, TCHAR value[], uint32_t tchar_num, const TCHAR *file_name)
{
    MpResult ret = MP_UNEXPECTED_ERROR;
    HKEY key;
    DWORD subkey_count = 0;

    if (!base_path || !target_component || !sub_path || !name || !value || !tchar_num || !file_name)
        return MP_INVALID_PARAMETER;

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, base_path, 0, KEY_READ, &key) != ERROR_SUCCESS)
        return MP_INVALID_PARAMETER;

    // Get the class name and the value count. 
    if (RegQueryInfoKey(key, NULL, NULL, NULL, &subkey_count, NULL, NULL, NULL, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
        ret = MP_UNEXPECTED_ERROR;
        goto error_catch;
    }

    // Enumerate the subkeys, until RegEnumKeyEx fails.
    if (subkey_count) {
        TCHAR registry_path[MAX_VALUE_NAME];
        for (DWORD i = 0; i < subkey_count; i++)
        {
            TCHAR buf[MAX_KEY_LENGTH];
            DWORD buf_size = ARRAY_LENGTH(buf);
            if (RegEnumKeyEx(key, i, buf, &buf_size, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                if (_tcsncpy_s(registry_path, ARRAY_LENGTH(registry_path), base_path, _tcslen(base_path))) {
                    ret = MP_UNEXPECTED_ERROR;
                    goto error_catch;
                }

                if (_tcsncat_s(registry_path, _T("\\\n", 1)) {
                    ret = MP_UNEXPECTED_ERROR;
                    goto error_catch;
                }
                if (_tcsncat_s(registry_path, buf, _tcsnlen(buf, ARRAY_LENGTH(buf)))) {
                    ret = MP_UNEXPECTED_ERROR;
                    goto error_catch;
                }
                ret = aesm_read_registry_value(registry_path, _T("MatchingDeviceId\n", buf, ARRAY_LENGTH(buf));
                if (MP_SUCCESS != ret)
                    continue;
                else {
                    if (_tcsnccmp(buf, target_component, ARRAY_LENGTH(buf)))
                        continue;
                    else {
                        if (_tcsncat_s(registry_path, sub_path, _tcslen(sub_path))) {
                            ret = MP_UNEXPECTED_ERROR;
                            goto error_catch;
                        }
                    }
                }

                ret = aesm_read_registry_value(registry_path, name, buf, ARRAY_LENGTH(buf));
                if (MP_SUCCESS != ret) {
                    goto error_catch;
                }
                else {
                    if (buf[_tcslen(buf) - 1] != _T('\\')) {
                        if (_tcsncat_s(buf, _T("\\\n", 1)) {
                            ret = MP_UNEXPECTED_ERROR;
                            goto error_catch;
                        }
                    }
                    if (_tcsncat_s(buf, file_name, _tcslen(file_name))) {
                        ret = MP_UNEXPECTED_ERROR;
                        goto error_catch;
                    }
                    if (_tcsncpy_s(value, tchar_num, buf, _tcsnlen(buf, ARRAY_LENGTH(buf)))) {
                        ret = MP_UNEXPECTED_ERROR;
                        goto error_catch;
                    }
                    ret = MP_SUCCESS;
                    goto error_catch;
                }
            }
        }
    }

error_catch:
    RegCloseKey(key);
    return ret;
}*/

bool AgentConfiguration::read(MPConfigurations& conf)
{
    MpResult res = MP_UNEXPECTED_ERROR;
    uint32_t value = 0;
    TCHAR valueStr[MAX_PATH_SIZE] = { 0 };
    memset(&conf, 0, sizeof(MPConfigurations));
    conf.log_level = MP_REG_LOG_LEVEL_ERROR;//default log level

    res = aesm_read_registry_dword(MP_PROXY_CONF, "type", &value);
    if (MP_SUCCESS == res) {
        conf.proxy.proxy_type = (ProxyType)value;
        agent_log_message(MP_REG_LOG_LEVEL_INFO, "Found proxy type reg key: %d\n", value);
    } else {
        agent_log_message(MP_REG_LOG_LEVEL_INFO, "Using deafult proxy type settings.\n", value);
    }

    res = aesm_read_registry_string(MP_PROXY_CONF, "url", valueStr, (uint32_t)sizeof(valueStr));
    if (MP_SUCCESS == res) {
        agent_log_message(MP_REG_LOG_LEVEL_INFO, "Found proxy url reg key: %s\n", valueStr);
        memcpy(conf.proxy.proxy_url, valueStr, strnlen_s(valueStr, sizeof(valueStr)));
    } else {
        if (MP_REG_PROXY_TYPE_MANUAL_PROXY == conf.proxy.proxy_type) {
            agent_log_message(MP_REG_LOG_LEVEL_ERROR, "Found manual proxy type reg key without url. Using deafult proxy configuration.\n");
            conf.proxy.proxy_type = MP_REG_PROXY_TYPE_DEFAULT_PROXY;
        }
    }

    res = aesm_read_registry_dword(MP_LOG_LEVEL_CONF, "level", &value);
    if (MP_SUCCESS == res) {
        conf.log_level = (LogLevel)value;
        agent_log_message(MP_REG_LOG_LEVEL_INFO, "Found log level reg key: %d\n", value);
    }

    res = aesm_read_registry_string(MP_SUBSCRIPTION_KEY_CONF, "token", valueStr, (uint32_t)sizeof(valueStr));
    if (MP_SUCCESS == res) {
        memcpy(conf.server_add_package_subscription_key, valueStr, strnlen_s(valueStr, sizeof(valueStr)));
        agent_log_message(MP_REG_LOG_LEVEL_INFO, "Found subscription token reg key: %s\n", valueStr);
    }
    return true;
}
