#
# Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
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
DCAP_QG_DIR  ?= $(DCAP_DIR)/QuoteGeneration/
include $(DCAP_QG_DIR)/buildenv.mk

######## SGX QvL Library Settings ########
INSTALL_PATH ?= /usr/lib/x86_64-linux-gnu/
vpath se_%.c $(DCAP_QG_DIR)/common/src/

DCAP_QUOTE_VERIFY_Lib_Cpp_Files := $(wildcard ../*.cpp) $(wildcard *.cpp)
DCAP_QUOTE_VERIFY_Lib_C_Files := se_trace.c se_thread.c qve_u.c

DCAP_QUOTE_VERIFY_Lib_Include_Paths := -I../../QvE/Include/ -I../inc -I$(DCAP_QG_DIR)/quote_wrapper/common/inc -I$(SGX_SDK)/include -I$(DCAP_QG_DIR)/common/inc/internal -I$(DCAP_QG_DIR)/pce_wrapper/inc 

DCAP_QUOTE_VERIFY_Lib_C_Flags := -fPIC -Wno-attributes $(DCAP_QUOTE_VERIFY_Lib_Include_Paths) $(COMMON_FLAGS) -g

LDUFLAGS:= -pthread $(COMMON_LDFLAGS)
LDUFLAGS += -Wl,--version-script=sgx_dcap_quoteverify.lds -Wl,--gc-sections

DCAP_QUOTE_VERIFY_Lib_Cpp_Flags := $(DCAP_QUOTE_VERIFY_Lib_C_Flags) -std=c++11

DCAP_QUOTE_VERIFY_Lib_Link_Flags := $(SGX_COMMON_FLAGS) -g -L$(SGX_SDK)/lib64 -lpthread -ldl
 
ifndef TRACE 
DCAP_QUOTE_VERIFY_Lib_Cpp_Flags += -DDISABLE_TRACE
DCAP_QUOTE_VERIFY_Lib_Link_Flags += -DDISABLE_TRACE
endif

DCAP_QUOTE_VERIFY_Lib_Cpp_Objects := $(DCAP_QUOTE_VERIFY_Lib_Cpp_Files:.cpp=.o)
DCAP_QUOTE_VERIFY_Lib_C_Objects := $(DCAP_QUOTE_VERIFY_Lib_C_Files:.c=.o)
DCAP_QUOTE_VERIFY_Lib_Cpp_Deps := $(DCAP_QUOTE_VERIFY_Lib_Cpp_Objects:%.o=%.d)

DCAP_QUOTE_VERIFY_Lib_Name_Dynamic  := libdcap_quoteverify.so
ifndef DEBUG
DCAP_QUOTE_VERIFY_Lib_Name_Dynamic_Debug := libdcap_quoteverify.so.debug
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

QvE_DIR ?= ../../QvE/
qve_u.h: $(SGX_EDGER8R) $(QvE_DIR)/Enclave/qve.edl
	$(SGX_EDGER8R) --untrusted $(QvE_DIR)/Enclave/qve.edl --search-path $(QvE_DIR)/Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

qve_u.c: qve_u.h

$(DCAP_QUOTE_VERIFY_Lib_Cpp_Objects): %.o: %.cpp qve_u.h
	@$(CXX) $(DCAP_QUOTE_VERIFY_Lib_Cpp_Flags) -MMD -c $< -o $@
	@echo "CXX  <=  $<"

%.o: %.c
	@$(CC) $(DCAP_QUOTE_VERIFY_Lib_C_Flags) -MMD -c $< -o $@
	@echo "CC  <=  $<"

$(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic): $(DCAP_QUOTE_VERIFY_Lib_Cpp_Objects) $(DCAP_QUOTE_VERIFY_Lib_C_Objects)
	$(CXX) $(CXXFLAGS) $(DCAP_QUOTE_VERIFY_Lib_Cpp_Objects) $(DCAP_QUOTE_VERIFY_Lib_C_Objects) -shared -Wl,-soname=$@.$(SGX_MAJOR_VER) $(LDUFLAGS) $(DCAP_QUOTE_VERIFY_Lib_Link_Flags) -o $@
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
	@rm -f .config_* *_u.* $(DCAP_QUOTE_VERIFY_Lib_Name) $(DCAP_QUOTE_VERIFY_Lib_Cpp_Objects) $(DCAP_QUOTE_VERIFY_Lib_Cpp_Deps) $(DCAP_QUOTE_VERIFY_Lib_C_Objects) $(DCAP_QUOTE_VERIFY_Lib_Cpp_Deps) $(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic) $(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic).orig $(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic_Debug) $(DCAP_QUOTE_VERIFY_Lib_Name_Dynamic).1


