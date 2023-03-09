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

#include <Utils/Logger.h>
#ifdef SGX_LOGS
#include <spdlog/sinks/stdout_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#endif

namespace intel { namespace sgx { namespace dcap { namespace logger {
const std::string DEFAULT_PATTERN = "[%Y-%m-%dT%H:%M:%S.%eZ] [%l] [%n %@] [pid:%P]%r %v";

void init(const std::string& name, const std::string &consoleLogLevel, const std::string &fileLogLevel,
          const std::string &fileName, const std::string &pattern)
{
#ifndef SGX_LOGS
    // suppress unused variable warning when building enclave
    (void)name;
    (void)consoleLogLevel;
    (void)fileLogLevel;
    (void)fileName;
    (void)pattern;
#endif
#ifdef SGX_LOGS

    auto loggerInstance = spdlog::get(name);

    if (!loggerInstance) {
        std::vector<spdlog::sink_ptr> sinks;

        auto consoleLogLevelParsed = spdlog::level::off;
        if (!consoleLogLevel.empty()) {
            consoleLogLevelParsed = spdlog::level::from_str(consoleLogLevel);
        }

        if (consoleLogLevelParsed != spdlog::level::off) {
            auto consoleSink = std::make_shared<spdlog::sinks::stdout_sink_mt>();
            consoleSink->set_level(consoleLogLevelParsed);
            sinks.push_back(consoleSink);
        }

        auto fileLogLevelParsed = spdlog::level::off;
        if (!fileLogLevel.empty()) {
            fileLogLevelParsed = spdlog::level::from_str(fileLogLevel);
        }

        if (fileLogLevelParsed != spdlog::level::off && !fileName.empty()) {
            auto fileSink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(fileName);
            fileSink->set_level(fileLogLevelParsed);
            sinks.push_back(fileSink);
        }

        loggerInstance = std::make_shared<spdlog::logger>(name, begin(sinks), end(sinks));

        auto formatter = std::make_unique<spdlog::pattern_formatter>();
        formatter->add_flag<CustomFieldFormatter>('r');
        if (!pattern.empty()) {
            formatter->set_pattern(pattern);
        } else {
            formatter->set_pattern(DEFAULT_PATTERN);
        }
        loggerInstance->set_formatter(std::move(formatter));

        // Log level for whole logger is set to the lowest possible level, so we can set all possible levels on sinks
        // If we leave it to default info level it won't be possible to set lower than info level on sinks.
        loggerInstance->set_level(spdlog::level::trace);
        
        loggerInstance->flush_on(spdlog::level::info);
        spdlog::flush_every(std::chrono::seconds(1));

        spdlog::register_logger(loggerInstance);
        spdlog::set_default_logger(loggerInstance);
        LOG_INFO("QVL Logging enabled and configured");
    }
#endif
}

void setCustomField(const std::string &key, const std::string &value)
{
#ifndef SGX_LOGS
    // suppress unused variable warning when building enclave
    (void)key;
    (void)value;
#endif
#ifdef SGX_LOGS
    scopedCustomFieldKey = key;
    scopedCustomFieldValue = value;
#endif
}

#ifdef SGX_LOGS
void CustomFieldFormatter::format(const spdlog::details::log_msg &/*msg*/, const std::tm &, spdlog::memory_buf_t &dest)
{
    if (!scopedCustomFieldValue.empty())
    {
        auto requestId = " [" + scopedCustomFieldKey + "=" + scopedCustomFieldValue + "]";
        dest.append(requestId.data(), requestId.data() + requestId.size());
    }
}

std::unique_ptr<spdlog::custom_flag_formatter> CustomFieldFormatter::clone() const
{
    return spdlog::details::make_unique<CustomFieldFormatter>();
}
#endif

std::string timeToString(const time_t time)
{
#ifdef SGX_LOGS
    char dateStr[20];
    std::strftime(dateStr, sizeof(dateStr), "%Y-%m-%d %H:%M:%S", std::gmtime(&time));
    return dateStr;
#else
    return std::to_string(time);
#endif
}

}}}}