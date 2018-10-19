# Copyright (c) 2017, Intel Corporation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
cmake_minimum_required(VERSION 3.2)

option(BUILD_ATTESTATION_LIBRARY "Build AttestationLibrary with tests" ON)
option(BUILD_ATTESTATION_APP "Build AttestationApp with tests" ON)
option(BUILD_TESTS "Build tests for all components" ON)
option(BUILD_DOCS "Build doxygen based documentation" OFF)

# Use AttestationLibrary from provided path if build is disabled
if(NOT BUILD_ATTESTATION_LIBRARY)
    if(NOT ATTESTATION_LIBRARY_ROOT_DIR)
        message(FATAL_ERROR "ATTESTATION_LIBRARY_ROOT_DIR is not set. Please set the property or enable library build")
    endif()
    message(STATUS "Using external attestation library at: ${ATTESTATION_LIBRARY_ROOT_DIR}")

    add_library(AttestationLibrary INTERFACE)
    target_include_directories(AttestationLibrary SYSTEM INTERFACE "${ATTESTATION_LIBRARY_ROOT_DIR}/include/")
    target_link_libraries(AttestationLibrary INTERFACE ${ATTESTATION_LIBRARY_ROOT_DIR}/lib/libQuoteVerification.so)

    add_library(AttestationLibraryStatic INTERFACE)
    target_include_directories(AttestationLibraryStatic SYSTEM INTERFACE "${ATTESTATION_LIBRARY_ROOT_DIR}/include/")
    target_link_libraries(AttestationLibraryStatic INTERFACE ${ATTESTATION_LIBRARY_ROOT_DIR}/lib/libQuoteVerificationStatic.a)
endif()

set(QVL_BUILD_DIR "${CMAKE_SOURCE_DIR}/Build/${CMAKE_BUILD_TYPE}")
set(QVL_DIST_DIR "${QVL_BUILD_DIR}/dist")

set(CMAKE_INSTALL_PREFIX ${QVL_DIST_DIR} CACHE PATH "default install path" FORCE )

if (CMAKE_BUILD_TYPE STREQUAL "Coverage")
    if (NOT DEFINED BULLSEYE_PATH)
        set(BULLSEYE_PATH "/opt/bullseye" CACHE PATH "" FORCE) #default Bullseye install path
    endif ()
    set(BULLSEYE_BIN "${BULLSEYE_PATH}/bin" CACHE PATH "bullseye binaries path" FORCE)

    get_filename_component(COMPILER_NAME ${CMAKE_CXX_COMPILER} NAME)

    find_program(BULLSEYE_CC
               NAMES ${COMPILER_NAME}
               PATHS ${BULLSEYE_BIN}
               NO_DEFAULT_PATH)

    find_program(BULLSEYE_COV_ENABLE
               NAMES "cov01"
               PATHS ${BULLSEYE_BIN}
               NO_DEFAULT_PATH)

    find_program(BULLSEYE_COV_SELECT
               NAMES "covselect"
               PATHS ${BULLSEYE_BIN}
               NO_DEFAULT_PATH)

    find_program(BULLSEYE_COV_HTML
               NAMES "covhtml"
               PATHS ${BULLSEYE_BIN}
               NO_DEFAULT_PATH)

    find_program(BULLSEYE_COV_XML
              NAMES "covxml"
              PATHS ${BULLSEYE_BIN}
              NO_DEFAULT_PATH)

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(BULLSEYE DEFAULT_MSG BULLSEYE_CC BULLSEYE_COV_ENABLE BULLSEYE_COV_SELECT BULLSEYE_COV_HTML BULLSEYE_COV_XML)

    set(CMAKE_CXX_COMPILER "${BULLSEYE_CC}" CACHE STRING "" FORCE) #must be done before 'project()'
endif ()

project(SgxEcdsaAttestation)

set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

set(IGNORED_WARNINGS
        "-Wno-gnu-statement-expression" #warns about __FILE__, __LINE__, etc. compiler macros
        "-Wno-c++98-compat"             #family of warnings indicating this code may cause errors if compiled with C++98 compiler
        "-Wno-c++98-compat-pedantic"    #same as above
        "-Wno-used-but-marked-unused"   #detects when a variable is marked as unsued (preprocessor macro or other) and warns if it is used despite that [note: triggers warnings in UT]
        "-Wno-weak-vtables"
        "-Wno-global-constructors"
        "-Wno-exit-time-destructors"
        "-Wno-padded"
        "-Wno-zero-as-null-pointer-constant" #zero as null pointer constant, mainly for openssl which widely uses 0 for null
        "-Wno-undefined-var-template"     #visible after upgrading to C++17, does not seem to be a big problem but, TODO investigate on how a proper fix should look like
        "-Wno-undefined-func-template"    #visible after upgrading to C++17, does not seem to be a big problem but, TODO investigate on how a proper fix should look like
        )

set(CMAKE_CXX_FLAGS
        "-std=c++14"                    #currently used C++ standard
        "-fPIC"                         #Position Independent Execution (PIE)
        "-fcolor-diagnostics"           #clang coloured output
        "-fstack-protector-strong"      #stack-based buffer overrun detection
        "-Werror"                       #make all warnings into errors
        "-Wall"                         #enable all warnings
        "-pthread"
        "${IGNORED_WARNINGS}"           #but ignore some unimportant ones
        "${CUSTOM_FLAGS}"
        )

set(CMAKE_CXX_FLAGS_RELEASE "-O2 -D_FORTIFY_SOURCE=2 -fvisibility=hidden")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g")

set(COMMON_LINKER_FLAGS
        "-ldl" "-lrt" "-lpthread"
        "-Wl,-z,relro" "-Wl,-z,now"     #data relocation and protection (RELRO)
        "-Wl,-z,noexecstack"            #stack execution protection
        "-Wl,--no-undefined"
        )


string(REPLACE ";" " " CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}") #Convert colon-separated CMake lists back to space-separated values that clang likes
string(REPLACE ";" " " COMMON_LINKER_FLAGS "${COMMON_LINKER_FLAGS}") #Convert colon-separated CMake lists back to space-separated values that clang likes

set(CMAKE_EXE_LINKER_FLAGS ${COMMON_LINKER_FLAGS})
set(CMAKE_SHARED_LINKER_FLAGS "-Wl,--exclude-libs,ALL")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${QVL_BUILD_DIR}/out/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${QVL_BUILD_DIR}/out/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${QVL_BUILD_DIR}/out/bin)

# Order matters!
add_subdirectory(ThirdParty)
if(BUILD_ATTESTATION_LIBRARY)
    add_subdirectory(AttestationLibrary)
endif()
if(BUILD_ATTESTATION_APP)
    add_subdirectory(AttestationApp)
endif()

add_custom_target(install_${PROJECT_NAME}
        $(MAKE) install
        DEPENDS AttestationApp
        COMMENT "Installing ${PROJECT_NAME}")

if (BUILD_TESTS)
    add_custom_target(runTests
        COMMAND cd ${QVL_DIST_DIR}/bin && LD_LIBRARY_PATH=../lib ./AttestationLibrary_UT && LD_LIBRARY_PATH=../lib ./AttestationLibrary_IT && LD_LIBRARY_PATH=../lib ./AttestationApp_UT && cd ${CMAKE_SOURCE_DIR}
        DEPENDS install_${PROJECT_NAME})

    if (CMAKE_BUILD_TYPE STREQUAL "Coverage")

        set(COVFILE "${CMAKE_SOURCE_DIR}/sgx.cov")

        add_custom_target(cov_on
            COMMAND ${BULLSEYE_COV_SELECT} -d --quiet
            COMMAND ${BULLSEYE_COV_SELECT} -i ${PROJECT_SOURCE_DIR}/BullseyeCoverageExclusions --no-banner
            COMMAND ${BULLSEYE_COV_ENABLE} -1  --no-banner
        )

        add_custom_target(cov_off
            COMMAND ${BULLSEYE_COV_ENABLE} -0 --no-banner)

        add_custom_target(cov_html
            COMMAND ${BULLSEYE_COV_HTML} -d${PROJECT_SOURCE_DIR} -f${COVFILE} ${PROJECT_SOURCE_DIR}/code-coverage-report  --no-banner)

        add_custom_target(cov_xml
            COMMAND ${BULLSEYE_COV_XML} -f${COVFILE} -o${PROJECT_SOURCE_DIR}/code-coverage-report/coverage.xml  --no-banner)

        add_custom_target(code-coverage
            COMMAND COVFILE=${COVFILE} ${CMAKE_MAKE_PROGRAM} -C ${QVL_BUILD_DIR} -j1 cov_on runTests cov_off cov_html cov_xml)
    endif ()
endif ()

