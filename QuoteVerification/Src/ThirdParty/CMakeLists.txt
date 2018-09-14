# Copyright (c) 2017, Intel Corporation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright notice,
#      this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in the
#      documentation and/or other materials provided with the distribution.
#    * Neither the name of Intel Corporation nor the names of its contributors
#      may be used to endorse or promote products derived from this software
#      without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

cmake_minimum_required(VERSION 3.2)
project(ThirdParty)

include(ExternalProject)

if(NOT DEFINED OPENSSL_ROOT_DIR)
    file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/openssl/dist)
    ExternalProject_add(
        openssl_download_build
        PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/openssl
        DOWNLOAD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/openssl/download
        URL "https://www.openssl.org/source/openssl-1.1.0i.tar.gz"
        BUILD_IN_SOURCE 1
        CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/openssl/src/openssl_download_build/config --prefix=${CMAKE_CURRENT_SOURCE_DIR}/openssl/dist --openssldir=${CMAKE_CURRENT_SOURCE_DIR}/openssl/dist
        BUILD_COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR}/openssl/src/openssl_download_build/ && make -j9
        INSTALL_COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR}/openssl/src/openssl_download_build/ && make install_sw install_ssldirs
        LOG_DOWNLOAD ON
    )

    set(OPENSSL_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/openssl/dist
        CACHE INTERNAL "${PROJECT_NAME} OpenSSL Root Directory" FORCE)
endif()
add_library(openssl INTERFACE)
target_include_directories(openssl SYSTEM INTERFACE "${OPENSSL_ROOT_DIR}/include/")
file(GLOB OPENSSL_SOURCE_FILES ${OPENSSL_ROOT_DIR}/include/openssl/*.h)
target_sources(openssl INTERFACE ${OPENSSL_SOURCE_FILES})
target_link_libraries(openssl INTERFACE
        ${OPENSSL_ROOT_DIR}/lib/libssl.a
        ${OPENSSL_ROOT_DIR}/lib/libcrypto.a
        )


if (NOT DEFINED GTEST_ROOT_DIR)
    find_package(Threads REQUIRED)
    file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/gtest/dist)
    ExternalProject_Add(
        gtest_download_build
        PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/gtest
        URL "https://github.com/google/googletest/archive/release-1.8.0.tar.gz"
        DOWNLOAD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/gtest/download
        BINARY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/gtest/bin
        CONFIGURE_COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR}/gtest/bin && cmake ${CMAKE_CURRENT_SOURCE_DIR}/gtest/src/gtest_download_build -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_SOURCE_DIR}/gtest/dist
        BUILD_COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR}/gtest/bin && make -j9
        LOG_DOWNLOAD ON
    )
    set(GTEST_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/gtest/dist
            CACHE INTERNAL "${PROJECT_NAME} GTest Include Directories" FORCE)
endif()
add_library(gtest INTERFACE)
target_include_directories(gtest SYSTEM INTERFACE "${GTEST_ROOT_DIR}/include/")
file(GLOB GTEST_SOURCE_FILES
        ${GTEST_ROOT_DIR}/include/gmock/*.h
        ${GTEST_ROOT_DIR}/include/gtest/*.h
        )
target_sources(gtest INTERFACE ${GTEST_SOURCE_FILES})
target_link_libraries(gtest INTERFACE
        ${GTEST_ROOT_DIR}/lib/libgtest.a
        ${GTEST_ROOT_DIR}/lib/libgtest_main.a
        ${GTEST_ROOT_DIR}/lib/libgmock.a
        )


add_library(rapidjson INTERFACE)
file(GLOB RAPIDJSON_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/rapidjson/include/rapidjson/*.h)
target_sources(rapidjson INTERFACE ${RAPIDJSON_SOURCE_FILES})
target_include_directories(rapidjson INTERFACE SYSTEM "${CMAKE_CURRENT_SOURCE_DIR}/rapidjson/include/")

add_library(cmdline INTERFACE)
file(GLOB CMDLINE_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/cmdline/*.h)
target_sources(cmdline INTERFACE ${CMDLINE_SOURCE_FILES})
target_include_directories(cmdline INTERFACE SYSTEM "${CMAKE_CURRENT_SOURCE_DIR}/cmdline/")
