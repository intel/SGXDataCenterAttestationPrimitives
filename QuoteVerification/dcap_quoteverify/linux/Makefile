#
# Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
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


include ../../buildenv.mk

INSTALL_PATH 		?= /usr/lib/x86_64-linux-gnu
QVE_SRC_PATH		:= $(DCAP_QV_DIR)/QvE
DCAP_QPL_DIR := $(DCAP_QG_DIR)/qpl

QVL_LIB_INC		+= -I$(PREBUILD_OPENSSL_PATH)/inc -I$(QVE_SRC_PATH)/Include
QVL_PARSER_INC  += -I$(PREBUILD_OPENSSL_PATH)/inc
QVL_VERIFY_INC	:= -I$(QVE_SRC_PATH)/Include \
				   -I../inc \
				   -I$(DCAP_QG_DIR)/quote_wrapper/common/inc \
                   -I$(SGX_SDK)/include \
				   -I$(DCAP_QG_DIR)/common/inc/internal \
				   -I$(DCAP_QG_DIR)/pce_wrapper/inc \
				   -I$(PREBUILD_OPENSSL_PATH)/inc \
				   	$(QVL_LIB_INC) \
				   -I$(DCAP_QPL_DIR)/inc

QPL_BASE64_CPP_DEP	:= $(DCAP_QPL_DIR)/sgx_base64.d

SGX_COMMON_CFLAGS	+= -g -fPIC -Wno-attributes -USGX_TRUSTED
SGX_COMMON_CXXFLAGS	+= -g -fPIC -USGX_TRUSTED

QVL_LIB_OBJS := $(QVL_LIB_FILES:.cpp=_untrusted.o)
QVL_PARSER_OBJS := $(QVL_PARSER_FILES:.cpp=_untrusted.o)

QVL_LIB := sgx_dcap_qvl_parser
QVL_PARSER := sgx_dcap_qvl_attestation
QVL_LIB_NAME := lib$(QVL_LIB).a
QVL_PARSER_NAME := lib$(QVL_PARSER).a

LDUFLAGS	:= -pthread -ldl -L. -l$(QVL_LIB) -l$(QVL_PARSER) $(COMMON_LDFLAGS) -L$(PREBUILD_OPENSSL_PATH)/lib/linux64 -lcrypto
LDUFLAGS	+= -Wl,--version-script=sgx_dcap_quoteverify.lds -Wl,--gc-sections

QVL_VERIFY_CPP_SRCS := $(wildcard ../*.cpp) $(wildcard *.cpp) $(DCAP_QPL_DIR)/sgx_base64.cpp
QVL_VERIFY_C_SRCS := $(COMMON_DIR)/src/se_trace.c $(COMMON_DIR)/src/se_thread.c
QVL_VERIFY_C_SRCS += qve_u.c

QVL_VERIFY_CPP_OBJS := $(QVL_VERIFY_CPP_SRCS:.cpp=.o)
QVL_VERIFY_CPP_OBJS_STATIC := $(QVL_VERIFY_CPP_SRCS:.cpp=_s.o)
QVL_VERIFY_C_OBJS := $(QVL_VERIFY_C_SRCS:.c=.o)

QVE_CPP_SRC ?= $(QVE_SRC_PATH)/Enclave/qve.cpp
QVE_CPP_OBJ ?= $(QVE_SRC_PATH)/Enclave/untrusted_qve.o

QVL_VERIFY_LIB_NAME := libsgx_dcap_quoteverify
QVL_VERIFY_LIB_NAME_Dynamic := $(QVL_VERIFY_LIB_NAME).so
QVL_VERIFY_LIB_NAME_Static := $(QVL_VERIFY_LIB_NAME).a

QAL_APPRAISAL_DIR := $(DCAP_QV_DIR)/appraisal/qal
QAL_APPRAISAL_CPP_SRCS :=$(wildcard $(QAL_APPRAISAL_DIR)/*.cpp)
QAL_APPRAISAL_CPP_SRCS += $(QAL_APPRAISAL_DIR)/../common/file_util.cpp
QAL_CPP_OBJS := $(QAL_APPRAISAL_CPP_SRCS:.cpp=.o)
QAL_Static_Lib_Name := libdcap_qal.a
WARM_Lib_Path := $(DCAP_EXTERNAL_DIR)/wasm-micro-runtime/product-mini/platforms/linux/build/
LDUFLAGS += -L$(WARM_Lib_Path) -lvmlib
ifeq ($(DEBUG), 1)
LDUFLAGS += -fsanitize=undefined
endif

.PHONY: all run


all: install_lib

$(BUILD_DIR):
	@$(MKDIR) $@

install_lib: $(QVL_VERIFY_LIB_NAME_Dynamic) | $(BUILD_DIR)
	@$(CP) $(QVL_VERIFY_LIB_NAME_Dynamic) $|
	ln -sf $|/$(QVL_VERIFY_LIB_NAME_Dynamic) $|/$(QVL_VERIFY_LIB_NAME_Dynamic).1
	$(CP) $(QAL_APPRAISAL_DIR)/opa_bin/policy.wasm $|/tee_appraisal_policy.wasm

ifeq ($(GEN_STATIC),1)
	@$(MAKE) $(QVL_VERIFY_LIB_NAME_Static)
	@$(CP) $(QVL_VERIFY_LIB_NAME_Static) $|
endif


run: all

######## QVL Library Objects ########

qve_u.h: $(SGX_EDGER8R) $(QVE_SRC_PATH)/Enclave/qve.edl
	@$(SGX_EDGER8R) --untrusted $(QVE_SRC_PATH)/Enclave/qve.edl --search-path $(QVE_SRC_PATH)/Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

qve_u.c : qve_u.h

$(QVL_VERIFY_C_OBJS): %.o: %.c qve_u.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(QVL_VERIFY_INC) -c $< -o $@
	@echo "CC  <=  $<"

-include $(QPL_BASE64_CPP_DEP)

$(QVL_VERIFY_CPP_OBJS): %.o: %.cpp qve_u.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(QVL_VERIFY_INC) -c $< -o $@
	@echo "CXX  <=  $<"

$(QVL_VERIFY_CPP_OBJS_STATIC): %_s.o: %.cpp qve_u.h
	@$(CXX) -DGEN_STATIC $(SGX_COMMON_CXXFLAGS) $(QVL_VERIFY_INC) -c $< -o $@
	@echo "CXX  <=  $<"

$(QVE_CPP_OBJ): $(QVE_CPP_SRC)
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(QVL_VERIFY_INC) -c $< -o $(QVE_CPP_OBJ)
	@echo "CXX  <=  $<"

$(QVL_LIB_OBJS): %_untrusted.o: %.cpp
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(QVL_LIB_INC) -c $< -o $@
	@echo "CXX  <=  $<"

$(QVL_PARSER_OBJS): %_untrusted.o: %.cpp
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(QVL_PARSER_INC) -c $< -o $@
	@echo "CXX  <=  $<"

$(QVL_LIB_NAME): $(QVL_LIB_OBJS)
	@$(AR) rsD $(QVL_LIB_NAME) $(QVL_LIB_OBJS)

$(QVL_PARSER_NAME): $(QVL_PARSER_OBJS)
	@$(AR) rsD $(QVL_PARSER_NAME) $(QVL_PARSER_OBJS)


$(QVL_VERIFY_LIB_NAME_Dynamic): $(QVL_VERIFY_CPP_OBJS) $(QVL_VERIFY_C_OBJS) $(QVE_CPP_OBJ) $(QVL_LIB_NAME) $(QVL_PARSER_NAME) qal
	$(CXX) $(SGX_COMMON_CXXFLAGS) $(QVL_VERIFY_CPP_OBJS) $(QVL_VERIFY_C_OBJS) $(QVE_CPP_OBJ) $(QAL_CPP_OBJS) -shared -Wl,-soname=$@.$(SGX_MAJOR_VER) $(LDUFLAGS) -o $@
	@ln -sf $(QVL_VERIFY_LIB_NAME_Dynamic) $(QVL_VERIFY_LIB_NAME_Dynamic).1

$(QVL_VERIFY_LIB_NAME_Static): $(QVL_VERIFY_CPP_OBJS_STATIC) $(QVL_VERIFY_C_OBJS) $(QVE_CPP_OBJ) $(QVL_LIB_NAME) $(QVL_PARSER_NAME)
	@$(AR) rsD $(QVL_VERIFY_LIB_NAME_Static) $(QVL_VERIFY_CPP_OBJS_STATIC) $(QVL_VERIFY_C_OBJS) $(QVE_CPP_OBJ)

.PHONY: qal
qal: 
	$(MAKE) -C $(QAL_APPRAISAL_DIR) $(QAL_Static_Lib_Name)

force_look:
	true

install: $(QVL_VERIFY_LIB_NAME_Dynamic)
	$(CP) $(QVL_VERIFY_LIB_NAME_Dynamic) $(INSTALL_PATH)
	ln -sf $(INSTALL_PATH)/$(QVL_VERIFY_LIB_NAME_Dynamic) $(INSTALL_PATH)/$(QVL_VERIFY_LIB_NAME_Dynamic).1

uninstall:
	rm -f $(INSTALL_PATH)/$(QVL_VERIFY_LIB_NAME_Dynamic) $(INSTALL_PATH)/$(QVL_VERIFY_LIB_NAME_Dynamic).1

.PHONY: clean

clean:
	@rm -f *_u.* $(QVL_VERIFY_CPP_OBJS) $(QVL_VERIFY_CPP_OBJS_STATIC) $(QVL_VERIFY_C_OBJS) $(QVL_VERIFY_LIB_NAME_Dynamic) $(QVL_VERIFY_LIB_NAME_Static)
	@rm -f $(QVL_LIB_OBJS) $(QVL_PARSER_OBJS)
	@rm -f $(QVL_LIB_NAME) $(QVL_PARSER_NAME)
	@rm -f *.orig *.debug *.1
	@rm -f $(QVE_CPP_OBJ)
	@$(MAKE) -C $(QAL_APPRAISAL_DIR) clean