#
# Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

######## SGX SDK Settings ########
DCAP_DIR  ?= ../../../
DCAP_QG_DIR  ?= $(DCAP_DIR)QuoteGeneration
include $(DCAP_QG_DIR)/buildenv.mk
SGXSSL_PACKAGE_PATH ?= ../../sgxssl/Linux/package
######## SGX QvL Library Settings ########
INSTALL_PATH ?= /usr/lib/x86_64-linux-gnu
vpath se_%.c $(DCAP_QG_DIR)/common/src
QVL_SRC_PATH ?= ../../QVL/Src
QVE_SRC_PATH ?= ../../QvE
QVE_SRC ?= $(QVE_SRC_PATH)/Enclave/qve.cpp
QVE_OBJ ?= $(QVE_SRC_PATH)/Enclave/untrusted_qve.o
PREBUILT_OPENSSL_DIR ?= $(DCAP_DIR)prebuilt/openssl

ifeq ($(DEBUG), 1)
        SGX_COMMON_FLAGS += -O0 -g3  -ggdb -DDEBUG_MODE=1
else
        SGX_COMMON_FLAGS += -O2 -fno-delete-null-pointer-checks
endif

SGX_COMMON_FLAGS += -m64 -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls \
					-fvisibility=hidden -fpie -fpic -D_FORTIFY_SOURCE=2
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++14



# QVL related vars
ATTESTATIONPARSER_NAME := sgx_dcap_qvl_parser
QUOTEVERIFY_NAME := sgx_dcap_qvl_attestation
QVL_Lib_Static_Name := lib$(QUOTEVERIFY_NAME).a
QVL_Parser_Static_Name := lib$(ATTESTATIONPARSER_NAME).a

Attestation_Lib_DIR := $(QVL_SRC_PATH)/AttestationLibrary
Attestation_Parsers_DIR := $(QVL_SRC_PATH)/AttestationParsers

COMMON_INCLUDE := -I../../QvE/Enclave -I../../QvE/Include -I$(QVL_SRC_PATH)/ThirdParty/rapidjson/include -I$(PREBUILT_OPENSSL_DIR)/inc
Attestation_Lib_Include_Paths := $(COMMON_INCLUDE) -I$(Attestation_Lib_DIR)/include -I$(Attestation_Lib_DIR)/src -I$(Attestation_Parsers_DIR)/include
Attestation_Parsers_Include_Paths := $(COMMON_INCLUDE) -I$(Attestation_Parsers_DIR)/include -I$(Attestation_Parsers_DIR)/src -I$(Attestation_Lib_DIR)/include

Attestation_Lib_Cpp_Files := $(wildcard $(Attestation_Lib_DIR)/src/*.cpp) $(wildcard $(Attestation_Lib_DIR)/src/*/*.cpp)
Attestation_Parsers_Cpp_Files0 := $(wildcard $(Attestation_Parsers_DIR)/src/*.cpp) $(wildcard $(Attestation_Parsers_DIR)/src/*/*.cpp)
GMTIM = ../QVL/Src/AttestationParsers/src/Utils/GMTime.cpp
Attestation_Parsers_Cpp_Files := $(filter-out $(GMTIM),$(Attestation_Parsers_Cpp_Files0))

Attestation_Lib_Obj_Files := $(Attestation_Lib_Cpp_Files:.cpp=_untrusted.o)
Attestation_Parsers_Obj_Files := $(Attestation_Parsers_Cpp_Files:.cpp=_untrusted.o)

# end of QVL vars


DCAP_QUOTE_VERIFY_Lib_Cpp_Files := $(wildcard ../*.cpp) $(wildcard *.cpp)
DCAP_QUOTE_VERIFY_Lib_C_Files := se_trace.c se_thread.c qve_u.c


DCAP_QUOTE_VERIFY_Lib_Include_Paths := -I../../QvE/Include/ -I../inc -I$(DCAP_QG_DIR)/quote_wrapper/common/inc \
                     -I$(SGX_SDK)/include -I$(DCAP_QG_DIR)/common/inc/internal -I$(DCAP_QG_DIR)/pce_wrapper/inc \
                     -I$(Attestation_Lib_DIR)/include -I$(Attestation_Lib_DIR)/src -I$(Attestation_Parsers_DIR)/include \
                     -I$(QVL_SRC_PATH) -I$(Attestation_Parsers_DIR)/src -I$(QVL_SRC_PATH)/ThirdParty/rapidjson/include \
					 -I$(PREBUILT_OPENSSL_DIR)/inc


DCAP_QUOTE_VERIFY_Lib_C_Flags := -fPIC -Wno-attributes $(DCAP_QUOTE_VERIFY_Lib_Include_Paths) $(COMMON_FLAGS) -g -USGX_TRUSTED

LDUFLAGS:= -pthread -ldl $(COMMON_LDFLAGS) -L./ -l$(QUOTEVERIFY_NAME) -l$(ATTESTATIONPARSER_NAME) -L$(PREBUILT_OPENSSL_DIR)/lib/linux64 -lcrypto
LDUFLAGS += -Wl,--version-script=sgx_dcap_quoteverify.lds -Wl,--gc-sections


DCAP_QUOTE_VERIFY_Lib_Cpp_Flags := $(DCAP_QUOTE_VERIFY_Lib_C_Flags)

DCAP_QUOTE_VERIFY_Lib_Link_Flags := $(SGX_COMMON_FLAGS)

ifndef TRACE
DCAP_QUOTE_VERIFY_Lib_Cpp_Flags += -DDISABLE_TRACE
DCAP_QUOTE_VERIFY_Lib_Link_Flags += -DDISABLE_TRACE
endif

DCAP_QUOTE_VERIFY_Lib_Cpp_Objects := $(DCAP_QUOTE_VERIFY_Lib_Cpp_Files:.cpp=.o)
DCAP_QUOTE_VERIFY_Lib_C_Objects := $(DCAP_QUOTE_VERIFY_Lib_C_Files:.c=.o)
DCAP_QUOTE_VERIFY_Lib_Cpp_Deps := $(DCAP_QUOTE_VERIFY_Lib_Cpp_Objects:%.o=%.d)
DCAP_QUOTE_VERIFY_Lib_C_Deps := $(DCAP_QUOTE_VERIFY_Lib_C_Objects:%.o=%.d)

DCAP_QUOTE_VERIFY_Lib_Name_Dynamic  := libsgx_dcap_quoteverify.so

ifndef DEBUG
DCAP_QUOTE_VERIFY_Lib_Name_Dynamic_Debug := libsgx_dcap_quoteverify.so.debug
endif

.PHONY: all run


all: $(DCAP_QUOTE_VERIFY_Lib_Name) install_lib

$(BUILD_DIR):
	@$(MKDIR) $@

install_lib: $(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic) $(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic_Debug) | $(BUILD_DIR)
	@$(CP) $(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic) $|
	ln -sf $|/$(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic) $|/$(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic).1
ifndef DEBUG
	@$(CP) $(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic_Debug) $|
endif

run: all

######## QvL Library Objects ########

-include $(DCAP_QUOTE_VERIFY_Lib_Cpp_Deps)
-include $(DCAP_QUOTE_VERIFY_Lib_C_Deps)

qve_u.h: $(SGX_EDGER8R) $(QVE_SRC_PATH)/Enclave/qve.edl
	$(SGX_EDGER8R) --untrusted $(QVE_SRC_PATH)/Enclave/qve.edl --search-path $(QVE_SRC_PATH)/Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

qve_u.c: qve_u.h

$(DCAP_QUOTE_VERIFY_Lib_Cpp_Objects): %.o: %.cpp qve_u.h
	@$(CXX) $(DCAP_QUOTE_VERIFY_Lib_Cpp_Flags) -MMD -c $< -o $@
	@echo "CXX  <=  $<"

%.o: %.c
	@$(CC) $(DCAP_QUOTE_VERIFY_Lib_C_Flags) -MMD -c $< -o $@
	@echo "CC  <=  $<"

$(QVE_OBJ): $(QVE_SRC)
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(DCAP_QUOTE_VERIFY_Lib_Cpp_Flags) -MMD -c $< -o $(QVE_OBJ)
	@echo "CXX  <=  $<"

$(Attestation_Lib_Obj_Files): %_untrusted.o: %.cpp
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Attestation_Lib_Include_Paths) -c $< -o $@
	@echo "CXX  <=  $<"

$(Attestation_Parsers_Obj_Files): %_untrusted.o: %.cpp
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Attestation_Parsers_Include_Paths) -c $< -o $@
	@echo "CXX  <=  $<"

$(QVL_Lib_Static_Name): $(Attestation_Lib_Obj_Files)
	@$(AR) rsD $(QVL_Lib_Static_Name) $(Attestation_Lib_Obj_Files)

$(QVL_Parser_Static_Name): $(Attestation_Parsers_Obj_Files)
	@$(AR) rsD $(QVL_Parser_Static_Name) $(Attestation_Parsers_Obj_Files)



$(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic): $(DCAP_QUOTE_VERIFY_Lib_Cpp_Objects) $(DCAP_QUOTE_VERIFY_Lib_C_Objects) $(QVE_OBJ) $(QVL_Lib_Static_Name) $(QVL_Parser_Static_Name)
	$(CXX) $(CXXFLAGS) $(DCAP_QUOTE_VERIFY_Lib_Cpp_Objects) $(DCAP_QUOTE_VERIFY_Lib_C_Objects) $(QVE_OBJ) -shared -Wl,-soname=$@.$(SGX_MAJOR_VER) $(LDUFLAGS) $(DCAP_QUOTE_VERIFY_Lib_Link_Flags) -o $@
	ln -sf $(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic) $(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic).1

$(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic_Debug): $(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic)
	((test -f $(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic_Debug)) || $(MAKE) separate_debug_info)


.PHONY: separate_debug_info
separate_debug_info:
ifndef DEBUG
	$(CP) $(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic) $(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic).orig
	$(OBJCOPY) --only-keep-debug $(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic) $(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic_Debug)
	$(STRIP) -g $(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic)
	$(OBJCOPY) --add-gnu-debuglink=$(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic_Debug) $(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic)
endif

force_look:
	true

install: $(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic)
	$(CP) $(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic) $(INSTALL_PATH)
	ln -sf $(INSTALL_PATH)/$(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic) $(INSTALL_PATH)/$(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic).1

uninstall:
	rm -f $(INSTALL_PATH)/$(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic) $(INSTALL_PATH)/$(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic).1

.PHONY: clean

clean:
	@rm -f .config_* *_u.* $(DCAP_QUOTE_VERIFY_Lib_Name) $(DCAP_QUOTE_VERIFY_Lib_Cpp_Objects) $(DCAP_QUOTE_VERIFY_Lib_Cpp_Deps) $(DCAP_QUOTE_VERIFY_Lib_C_Objects) $(DCAP_QUOTE_VERIFY_Lib_C_Deps) $(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic)
	@rm -f $(QVE_OBJ) $(QVE_SRC_PATH)/Enclave/*.d
	@rm -f *.orig *.debug *.1
	@rm -f $(Attestation_Lib_Obj_Files) $(Attestation_Parsers_Obj_Files)
	@rm -f $(QVL_Lib_Static_Name) $(QVL_Parser_Static_Name)
