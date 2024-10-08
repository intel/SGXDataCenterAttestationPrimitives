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
TOP_DIR  = ../..
include $(TOP_DIR)/buildenv.mk
PREBUILD_OPENSSL_PATH  = ../../../prebuilt/openssl

######## SGX QPL Library Settings ########

QPL_Lib_Cpp_Files := $(wildcard *.cpp ../*.cpp)

######## Include path -- Don't forget to update AESM CMakefile ########
QPL_Lib_Include_Paths := -I../../quote_wrapper/common/inc       \
                         -I../inc -I$(SGX_SDK)/include          \
                         -I../../common/inc/internal            \
                         -I../../qcnl/inc                       \
                         -I$(PREBUILD_OPENSSL_PATH)/inc

QPL_Lib_C_Flags := $(COMMON_FLAGS) -g -fPIC -Wno-attributes $(QPL_Lib_Include_Paths)

LDUFLAGS:= -pthread $(COMMON_LDFLAGS)
LDUFLAGS += -Wl,--version-script=sgx_default_quote_provider.lds -Wl,--gc-sections

QPL_Lib_Cpp_Flags := $(QPL_Lib_C_Flags) -std=c++11

QPL_Lib_Link_Flags := $(SGX_COMMON_FLAGS) -g -L$(TOP_DIR)/build/linux -L$(SGX_SDK)/lib64 -L$(PREBUILD_OPENSSL_PATH)/lib/linux64 \
        -lcrypto -lsgx_default_qcnl_wrapper -lpthread -ldl
 
ifndef DEBUG
QPL_Lib_Cpp_Flags += -DDISABLE_TRACE
QPL_Lib_Link_Flags += -DDISABLE_TRACE
endif

QPL_Lib_Cpp_Objects := $(QPL_Lib_Cpp_Files:.cpp=.o)
QPL_Lib_Cpp_Deps := $(QPL_Lib_Cpp_Objects:%.o=%.d)

QPL_Lib_Name := libdcap_quoteprov
QPL_Lib_Name_Dynamic := $(QPL_Lib_Name).so
QPL_Lib_Name_Dynamic_Full := $(QPL_Lib_Name_Dynamic).$(call get_full_version,DEFAULT_QPL_VERSION)
QPL_Lib_Name_Dynamic_Major := $(QPL_Lib_Name_Dynamic).$(call get_major_version,DEFAULT_QPL_VERSION)
QPL_Lib_Name_Static := $(QPL_Lib_Name).a

.PHONY: all run

all: install_lib

install_lib: $(QPL_Lib_Name_Dynamic) | $(BUILD_DIR)
	@$(CP) $(QPL_Lib_Name_Dynamic) $|/$(QPL_Lib_Name_Dynamic_Full)
	@$(LN) $(QPL_Lib_Name_Dynamic_Full) $|/$(QPL_Lib_Name_Dynamic_Major)
	@$(LN) $(QPL_Lib_Name_Dynamic_Major) $|/$(QPL_Lib_Name_Dynamic)

ifeq ($(GEN_STATIC),1)
	@$(MAKE) $(QPL_Lib_Name_Static)
	@$(CP) $(QPL_Lib_Name_Static) $|
endif

$(BUILD_DIR):
	@$(MKDIR) $@

run: all

######## QPL Library Objects ########

-include $(QPL_Lib_Cpp_Deps)

$(QPL_Lib_Cpp_Objects): %.o: %.cpp
	@$(CXX) $(QPL_Lib_Cpp_Flags) -MMD -c $< -o $@
	@echo "CXX  <=  $<"

$(QPL_Lib_Name_Dynamic): $(QPL_Lib_Cpp_Objects)
	$(CXX) $(CXXFLAGS) $(QPL_Lib_Cpp_Objects) -shared -Wl,-soname=$(QPL_Lib_Name_Dynamic_Major) $(LDUFLAGS) $(QPL_Lib_Link_Flags) -o $@

$(QPL_Lib_Name_Static): $(QPL_Lib_Cpp_Objects)
	$(AR) rsD $(QPL_Lib_Name_Static) $(QPL_Lib_Cpp_Objects)

force_look:
	true

.PHONY: clean

clean:
	@$(RM) .config_* $(QPL_Lib_Name) $(QPL_Lib_Cpp_Objects) $(QPL_Lib_Cpp_Deps) $(QPL_Lib_Name_Dynamic) $(QPL_Lib_Name_Static) \
		$(addprefix $(BUILD_DIR)/,$(QPL_Lib_Name_Dynamic) $(QPL_Lib_Name_Dynamic_Full) $(QPL_Lib_Name_Dynamic_Major))
