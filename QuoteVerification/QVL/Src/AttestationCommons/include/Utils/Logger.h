/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
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

#ifndef SGXECDSAATTESTATIONCOMMONS_LOGGER_H
#define SGXECDSAATTESTATIONCOMMONS_LOGGER_H

#include <string>
#include <time.h>

#ifdef SGX_LOGS
#define SPDLOG_LEVEL_NAMES                                            \
  {                                                                   \
    "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "OFF"         \
  }
#include <spdlog/spdlog.h>
#include "spdlog/pattern_formatter.h"
#include <fmt/ranges.h>

#define LOG(level, ...) spdlog::log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, level, __VA_ARGS__)
#define LOG_TRACE(...) LOG(spdlog::level::trace, __VA_ARGS__)
#define LOG_DEBUG(...) LOG(spdlog::level::debug, __VA_ARGS__)
#define LOG_INFO(...) LOG(spdlog::level::info, __VA_ARGS__)
#define LOG_WARN(...) LOG(spdlog::level::warn, __VA_ARGS__)
#define LOG_ERROR(...) LOG(spdlog::level::err, __VA_ARGS__)
#define LOG_FATAL(...) LOG(spdlog::level::critical, __VA_ARGS__)

#else
#define LOG_TRACE(...)
#define LOG_DEBUG(...)
#define LOG_INFO(...)
#define LOG_WARN(...)
#define LOG_ERROR(...)
#define LOG_FATAL(...)
#endif
#define LOG_AND_THROW(exp, msg) \
    LOG_ERROR(msg); \
    throw exp(msg);

namespace intel { namespace sgx { namespace dcap { namespace logger {
#ifdef SGX_LOGS
static thread_local std::string scopedCustomFieldKey;
static thread_local std::string scopedCustomFieldValue;
#endif

void init(const std::string &consoleLogLevel, const std::string &fileLogLevel, const std::string &fileName,
          const std::string& name, const std::string &pattern);
void setCustomField(const std::string &key, const std::string &value);
std::string timeToString(const time_t time);

#ifdef SGX_LOGS
class CustomFieldFormatter : public spdlog::custom_flag_formatter
{
public:
    void format(const spdlog::details::log_msg& /*msg*/, const std::tm &, spdlog::memory_buf_t &dest) override;
    std::unique_ptr<spdlog::custom_flag_formatter> clone() const override;
};
#endif
}}}}
#endif //SGXECDSAATTESTATIONCOMMONS_LOGGER_H
