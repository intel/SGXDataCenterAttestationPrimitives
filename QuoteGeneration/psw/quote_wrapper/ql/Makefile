#
# Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
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
TOP_DIR  = ../../..
include $(TOP_DIR)/buildenv.mk

Quote_Library_Dir := ../quote
Quote_Library := $(Quote_Library_Dir)/libquote.a

######## SGX QL Library Settings ########

QL_Lib_Cpp_Files := $(wildcard src/*.cpp)

QL_Lib_Include_Paths := -I../common/inc -I./ -I$(SGX_SDK)/include -I../../../common/inc/internal -I../quote/src -I../../../psw/pce_wrapper/inc

QL_Lib_C_Flags := $(COMMON_FLAGS) -g -fPIC -Wno-attributes $(QL_Lib_Include_Paths)

LDUFLAGS:= -pthread $(COMMON_LDFLAGS)
LDUFLAGS += -Wl,--version-script=dcap_ql_wrapper.lds -Wl,--gc-sections

QL_Lib_Cpp_Flags := $(QL_Lib_C_Flags) -std=c++11
QL_Lib_Link_Flags := $(SGX_COMMON_FLAGS) -g -L$(TOP_DIR)/build/linux -L$(SGX_SDK)/lib64 -lsgx_urts -lpthread -ldl

ifndef DEBUG
QL_Lib_Cpp_Flags += -DDISABLE_TRACE
QL_Lib_Link_Flags += -DDISABLE_TRACE
endif

QL_Lib_Cpp_Objects := $(QL_Lib_Cpp_Files:.cpp=.o)
QL_Lib_Cpp_Deps := $(QL_Lib_Cpp_Objects:%.o=%.d)

QL_Lib_Name_Dynamic  := libsgx_dcap_ql.so
ifndef DEBUG
QL_Lib_Name_Dynamic_Debug := libsgx_dcap_ql.so.debug
endif

.PHONY: all run

all: $(QL_Lib_Name) install_lib

install_lib: $(QL_Lib_Name_Dynamic) $(QL_Lib_Name_Dynamic_Debug) | $(BUILD_DIR)
	@$(CP) $(QL_Lib_Name_Dynamic) $|
ifndef DEBUG
	@$(CP) $(QL_Lib_Name_Dynamic_Debug) $|
endif

run: all

######## QL Library Objects ########

-include $(QL_Lib_Cpp_Deps)

$(QL_Lib_Cpp_Objects): %.o: %.cpp
	@$(CXX) $(QL_Lib_Cpp_Flags) -MMD -c $< -o $@
	@echo "CXX  <=  $<"

$(QL_Lib_Name_Dynamic): $(QL_Lib_Cpp_Objects) $(Quote_Library)
	$(CXX) $(CXXFLAGS) $(QL_Lib_Cpp_Objects) $(Quote_Library) -shared -Wl,-soname=$@.$(SGX_MAJOR_VER) $(LDUFLAGS) $(QL_Lib_Link_Flags) -o $@

$(QL_Lib_Name_Dynamic_Debug): $(QL_Lib_Name_Dynamic)
	((test -f $(QL_Lib_Name_Dynamic_Debug)) || $(MAKE) separate_debug_info)

.PHONY: separate_debug_info
separate_debug_info:
ifndef DEBUG
	$(CP) $(QL_Lib_Name_Dynamic) $(QL_Lib_Name_Dynamic).orig
	$(OBJCOPY) --only-keep-debug $(QL_Lib_Name_Dynamic) $(QL_Lib_Name_Dynamic_Debug)
	$(STRIP) -g $(QL_Lib_Name_Dynamic)
	$(OBJCOPY) --add-gnu-debuglink=$(QL_Lib_Name_Dynamic_Debug) $(QL_Lib_Name_Dynamic)
endif


$(Quote_Library): force_look
	@make -C $(Quote_Library_Dir)

force_look:
	true

.PHONY: clean

clean:
	@rm -f .config_* $(QL_Lib_Name) $(QL_Lib_Cpp_Objects) $(QL_Lib_Cpp_Deps) libdcapnocorequote.a $(QL_Lib_Name_Dynamic) $(QL_Lib_Name_Dynamic).orig $(QL_Lib_Name_Dynamic_Debug)
	@make -C $(Quote_Library_Dir) clean


