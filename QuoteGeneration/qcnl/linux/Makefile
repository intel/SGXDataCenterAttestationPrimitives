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

######## SGX SDK Settings ########
TOP_DIR = ../..
include $(TOP_DIR)/buildenv.mk
PREBUILD_OPENSSL_PATH = ../../../prebuilt/openssl

######## SGX CNL Library Settings ########

CNL_Lib_Cpp_Files := $(wildcard *.cpp ../*.cpp)
CNL_Lib_C_Files := $(wildcard *.c ../*.c) ../../common/src/se_thread.c

######## Include path -- Don't forget to update AESM CMakefile ########
CNL_Lib_Include_Paths := -I../../quote_wrapper/common/inc       \
                         -I../inc -I$(SGX_TRUSTED_INCLUDE_PATH) \
                         -I../../common/inc/internal            \
                         -I../../pce_wrapper/inc                \
                         -I../../../QuoteVerification/QVL/Src/ThirdParty/rapidjson/include/rapidjson	\
                         -I../../../tools/PCKCertSelection/include \
                         -I$(PREBUILD_OPENSSL_PATH)/inc

CNL_Lib_C_Flags := $(COMMON_FLAGS) -g -fPIC -Wno-attributes $(CNL_Lib_Include_Paths)

LDUFLAGS:= -pthread $(COMMON_LDFLAGS)
LDUFLAGS += -Wl,--version-script=sgx_default_qcnl.lds -Wl,--gc-sections

CNL_Lib_Cpp_Flags := $(CNL_Lib_C_Flags) -std=c++11

ifdef SELF_SIGNED_CERT
CNL_Lib_Cpp_Flags+= -DSELF_SIGNED_CERT
endif

CNL_Lib_Link_Flags := $(SGX_COMMON_FLAGS) -g -L$(TOP_DIR)/build/linux -L$(SGX_LIBRARY_PATH) \
		-lpthread -ldl ../../../tools/PCKCertSelection/static_out/libPCKCertSelection.a

ifndef DEBUG
CNL_Lib_Cpp_Flags += -DDISABLE_TRACE
CNL_Lib_Link_Flags += -DDISABLE_TRACE
endif

CNL_Lib_Cpp_Objects := $(CNL_Lib_Cpp_Files:.cpp=.o)
CNL_Lib_C_Objects := $(CNL_Lib_C_Files:.c=.o)
CNL_Lib_Cpp_Deps := $(CNL_Lib_Cpp_Objects:%.o=%.d)
PCK_Selection_Cpp_Objects := $(wildcard ../../../tools/PCKCertSelection/static_out/*.o)

CNL_Lib_Name := libsgx_default_qcnl_wrapper
CNL_Lib_Name_Dynamic := $(CNL_Lib_Name).so
CNL_Lib_Name_Dynamic_Full := $(CNL_Lib_Name_Dynamic).$(SGX_VER)
CNL_Lib_Name_Dynamic_Major := $(CNL_Lib_Name_Dynamic).$(SGX_MAJOR_VER)
CNL_Lib_Name_Static := $(CNL_Lib_Name).a
PCK_Selection_Lib_Static := PCKCertSelection


.PHONY: all run

all: install_lib

install_lib: $(CNL_Lib_Name_Dynamic) | $(BUILD_DIR)
	@$(CP) $(CNL_Lib_Name_Dynamic) $|/$(CNL_Lib_Name_Dynamic_Full)
	@$(LN) $(CNL_Lib_Name_Dynamic_Full) $|/$(CNL_Lib_Name_Dynamic_Major)
	@$(LN) $(CNL_Lib_Name_Dynamic_Major) $|/$(CNL_Lib_Name_Dynamic)

ifeq ($(GEN_STATIC),1)
	@$(MAKE) $(CNL_Lib_Name_Static)
	@$(CP) $(CNL_Lib_Name_Static) $|
endif

run: all

######## CNL Library Objects ########

-include $(CNL_Lib_Cpp_Deps)

$(CNL_Lib_Cpp_Objects): %.o: %.cpp
	@$(CXX) $(CNL_Lib_Cpp_Flags) -MMD -c $< -o $@
	@echo "CXX  <=  $<"

$(CNL_Lib_C_Objects): %.o: %.c
	@$(CC) $(CNL_Lib_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

$(CNL_Lib_Name_Dynamic): $(CNL_Lib_Cpp_Objects) $(CNL_Lib_C_Objects) $(PCK_Selection_Lib_Static)
	$(CXX) $(CXXFLAGS) $(CNL_Lib_Cpp_Objects) $(CNL_Lib_C_Objects) -shared -Wl,-soname=$@.$(SGX_MAJOR_VER) $(LDUFLAGS) $(CNL_Lib_Link_Flags) -o $@

$(CNL_Lib_Name_Static): $(CNL_Lib_Cpp_Objects) $(CNL_Lib_C_Objects) $(PCK_Selection_Lib_Static)
	$(AR) rsD $(CNL_Lib_Name_Static) $(CNL_Lib_Cpp_Objects) $(CNL_Lib_C_Objects) $(PCK_Selection_Cpp_Objects)

$(PCK_Selection_Lib_Static):
	make -C ../../../tools/PCKCertSelection/PCKCertSelectionLib -f Makefile.static_lib
force_look:
	true

$(BUILD_DIR):
	@$(MKDIR) $@

.PHONY: clean

clean:
	@$(RM) .config_* $(CNL_Lib_Name) $(CNL_Lib_Cpp_Objects) $(CNL_Lib_Cpp_Deps) $(CNL_Lib_Name_Dynamic) $(CNL_Lib_Name_Static)
	@$(RM) $(addprefix $(BUILD_DIR)/,$(CNL_Lib_Name_Dynamic) $(CNL_Lib_Name_Dynamic_Full) $(CNL_Lib_Name_Dynamic_Major))
	make -C ../../../tools/PCKCertSelection/PCKCertSelectionLib -f Makefile.static_lib clean


