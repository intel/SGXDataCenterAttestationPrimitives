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
TOP_DIR  = ../..
include $(TOP_DIR)/buildenv.mk

######## SGX QPL Library Settings ########

QPL_Lib_Cpp_Files := $(wildcard ../*.cpp)

QPL_Lib_Include_Paths := -I../../quote_wrapper/common/inc -I../inc -I$(SGX_SDK)/include -I../../common/inc/internal -I../../qcnl/inc 

QPL_Lib_C_Flags := $(COMMON_FLAGS) -g -fPIC -Wno-attributes $(QPL_Lib_Include_Paths)

LDUFLAGS:= -pthread $(COMMON_LDFLAGS)
LDUFLAGS += -Wl,--version-script=sgx_default_quote_provider.lds -Wl,--gc-sections

QPL_Lib_Cpp_Flags := $(QPL_Lib_C_Flags) -std=c++11

QPL_Lib_Link_Flags := $(SGX_COMMON_FLAGS) -g -L$(TOP_DIR)/build/linux -L$(SGX_SDK)/lib64 -lsgx_default_qcnl_wrapper -lpthread -ldl
 
ifndef DEBUG
QPL_Lib_Cpp_Flags += -DDISABLE_TRACE
QPL_Lib_Link_Flags += -DDISABLE_TRACE
endif

QPL_Lib_Cpp_Objects := $(QPL_Lib_Cpp_Files:.cpp=.o)
QPL_Lib_Cpp_Deps := $(QPL_Lib_Cpp_Objects:%.o=%.d)

QPL_Lib_Name_Dynamic  := libdcap_quoteprov.so

.PHONY: all run

all: $(QPL_Lib_Name) install_lib

install_lib: $(QPL_Lib_Name_Dynamic) | $(BUILD_DIR)
	@$(CP) $(QPL_Lib_Name_Dynamic) $|

run: all

######## QPL Library Objects ########

-include $(QPL_Lib_Cpp_Deps)

$(QPL_Lib_Cpp_Objects): %.o: %.cpp
	@$(CXX) $(QPL_Lib_Cpp_Flags) -MMD -c $< -o $@
	@echo "CXX  <=  $<"

$(QPL_Lib_Name_Dynamic): $(QPL_Lib_Cpp_Objects)
	$(CXX) $(CXXFLAGS) $(QPL_Lib_Cpp_Objects) -shared -Wl,-soname=$@.$(SGX_MAJOR_VER) $(LDUFLAGS) $(QPL_Lib_Link_Flags) -o $@

force_look:
	true

.PHONY: clean

clean:
	@rm -f .config_* $(QPL_Lib_Name) $(QPL_Lib_Cpp_Objects) $(QPL_Lib_Cpp_Deps) $(QPL_Lib_Name_Dynamic) $(QPL_Lib_Name_Dynamic).orig $(QPL_Lib_Name_Dynamic_Debug)


