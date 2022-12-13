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
/** File: local_cache.h
 *
 * Description: Implementation of local cache for PCK certificate chain & collaterals
 *
 */
#ifndef LOCALCACHE_H_
#define LOCALCACHE_H_
#pragma once

#include "qcnl_config.h"
#include "qcnl_util.h"
#include "se_memcpy.h"
#include <fstream>
#include <list>
#include <mutex>
#include <time.h>
#include <unordered_map>
#include <vector>

#ifdef _MSC_VER
#else
#include <sys/stat.h>
#endif

using namespace std;

static std::mutex mutex_cache_lock;

template <typename Key, typename Value>
class MemoryCache {
private:
    list<Key> keys_;
    unordered_map<Key, pair<Value, typename list<Key>::iterator>> map_;
    size_t size_;

public:
    // Set default cache size to 20
    MemoryCache() : size_(20) {}

    void set(const Key key, const Value value) {
        auto pos = map_.find(key);
        if (pos == map_.end()) {
            keys_.push_front(key);
            map_[key] = {value, keys_.begin()};
            if (map_.size() > size_) {
                map_.erase(keys_.back());
                keys_.pop_back();
            }
        } else {
            keys_.erase(pos->second.second);
            keys_.push_front(key);
            map_[key] = {value, keys_.begin()};
        }
    }

    bool get(const Key key, Value &value) {
        auto pos = map_.find(key);
        if (pos == map_.end())
            return false;
        keys_.erase(pos->second.second);
        keys_.push_front(key);
        map_[key] = {pos->second.first, keys_.begin()};
        value = pos->second.first;
        return true;
    }

    void remove(const Key key) {
        auto pos = map_.find(key);
        if (pos != map_.end()) {
            keys_.erase(pos->second.second);
            map_.erase(key);
        }
    }
};

struct CacheItemHeader {
    time_t expiry;
};

// (key, value) pair, where
//    Cache Key = sha256(URL)
//    Cache value = CacheItemHeader || HTTP RESPONSE(HEADER SIZE || HEADER || BODY SIZE || BODY)
class LocalCache {
private:
    //
    MemoryCache<string, vector<uint8_t>> mem_cache_;
#ifdef _MSC_VER
    wstring cache_dir_;
#else
    string cache_dir_;
#endif

public:
    static LocalCache &Instance() {
        static LocalCache myInstance;
        return myInstance;
    }

    LocalCache(LocalCache const &) = delete;
    LocalCache(LocalCache &&) = delete;
    LocalCache &operator=(LocalCache const &) = delete;
    LocalCache &operator=(LocalCache &&) = delete;

    bool get_data(const string &key, vector<uint8_t> &value) {
        // Lock the cache mutex
        std::lock_guard<std::mutex> lock(mutex_cache_lock);

        bool cache_hit = false;
        if (!mem_cache_.get(key, value)) {
            // If memory cache missed, turn to file cache
            if (!cache_dir_.empty()) {
#ifdef _MSC_VER
                wstring wskey(key.begin(), key.end());
                const auto file_name = cache_dir_ + L"\\" + wskey;
#else
                const auto file_name = cache_dir_ + "/" + key;
#endif
                ifstream ifs(file_name, std::ios::in | std::ios::binary);
                if (ifs.is_open()) {
                    qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Cache hit in folder '%s'. \n", cache_dir_.c_str());
                    value.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
                    // Need to update memory cache if file cache is hit
                    mem_cache_.set(key, value);
                    cache_hit = true;
                }
                ifs.close();
            }
        } else {
            qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Cache hit in memory. \n");
            cache_hit = true;
        }

        return cache_hit;
    }

    void set_data(const string &key, vector<uint8_t> &value) {
        // Lock the cache mutex
        std::lock_guard<std::mutex> lock(mutex_cache_lock);

        // Update memory cache
        mem_cache_.set(key, value);

        if (!cache_dir_.empty()) {
            // Update file cache
#ifdef _MSC_VER
            wstring wskey(key.begin(), key.end());
            const auto file_name = cache_dir_ + L"\\" + wskey;
#else
            const auto file_name = cache_dir_ + "/" + key;
#endif
            ofstream ofs(file_name, ios::out | ios::binary);
            if (!ofs.is_open()) {
                qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Failed to write cache file '%s'. \n", file_name.c_str());
            }
            ofs.write(reinterpret_cast<const char *>(&value[0]), value.size());
            ofs.close();

            qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Updated file cache successfully. \n");
        }
    }

    void remove_data(const string &key) {
        // Lock the cache mutex
        std::lock_guard<std::mutex> lock(mutex_cache_lock);

        // Remove memory cache entry
        mem_cache_.remove(key);

        if (!cache_dir_.empty()) {
            // Remove file cache
#ifdef _MSC_VER
            wstring wskey(key.begin(), key.end());
            const auto file_name = cache_dir_ + L"\\" + wskey;
            ::DeleteFile(file_name.c_str());
#else
            const auto file_name = cache_dir_ + "/" + key;
            std::remove(file_name.c_str());
#endif
        }
    }

protected:
    LocalCache() {
        init_cache_directory();
    }
    ~LocalCache() {}

#ifdef _MSC_VER
    void init_cache_directory() {
        const DWORD buffSize = MAX_PATH;

        auto env_home = std::make_unique<wchar_t[]>(buffSize);
        memset(env_home.get(), 0, buffSize);
        GetEnvironmentVariable(L"LOCALAPPDATA", env_home.get(), buffSize);
        std::wstring wenv_home(env_home.get());

        auto env_azdcap_cache = std::make_unique<wchar_t[]>(buffSize);
        memset(env_azdcap_cache.get(), 0, buffSize);
        GetEnvironmentVariable(L"AZDCAP_CACHE", env_azdcap_cache.get(), buffSize);
        std::wstring wenv_azdcap_cache(env_azdcap_cache.get());

        const std::wstring application_name(L"\\.dcap-qcnl");
        std::wstring dirname;

        if (wenv_azdcap_cache != L"" && wenv_azdcap_cache[0] != 0) {
            dirname = wenv_azdcap_cache;
        } else if (wenv_home != L"" && wenv_home[0] != 0) {
            dirname = wenv_home.append(L"..\\..\\LocalLow");
        }

        dirname += application_name;
        make_dir(dirname);
        cache_dir_ = dirname;
    }

    bool make_dir(const std::wstring &dirname) {
        CreateDirectory(dirname.c_str(), NULL);
        if (GetLastError() == ERROR_PATH_NOT_FOUND && GetLastError() != ERROR_ALREADY_EXISTS)
            return false;
        return true;
    }
#else
    void init_cache_directory() {
        const char *cache_locations[5];
        cache_locations[0] = ::getenv("AZDCAP_CACHE");
        cache_locations[1] = ::getenv("XDG_CACHE_HOME");
        cache_locations[2] = ::getenv("HOME");
        cache_locations[3] = ::getenv("TMPDIR");
        cache_locations[4] = "/tmp/";

        string application_name("/.dcap-qcnl/");
        for (auto &cache_location : cache_locations) {
            if (cache_location != 0 && strcmp(cache_location, "") != 0) {
                string dirname = cache_location + application_name;
                if (make_dir(dirname))
                    cache_dir_ = dirname;
                return;
            }
        }
    }

    bool make_dir(const std::string &dirname) {
        struct stat buf {};
        int rc = stat(dirname.c_str(), &buf);
        if (rc == 0) {
            if (S_ISDIR(buf.st_mode)) {
                return true;
            } else {
                qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] '%s' already exists, and is not a directory. \n", dirname.c_str());
                return false;
            }
        }

        rc = mkdir(dirname.c_str(), 0777);
        if (rc != 0) {
            qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Error creating directory '%s'. \n", dirname.c_str());
            return false;
        }

        return true;
    }
#endif
};

#endif // LOCALCACHE_H_