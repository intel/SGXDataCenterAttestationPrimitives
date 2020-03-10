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
TOP_DIR  = ../../..
include $(TOP_DIR)/buildenv.mk


PCE_Library_Dir := $(TOP_DIR)/pce_wrapper/linux
PCE_Library := $(PCE_Library_Dir)/libsgx_pce_wrapper.a

QE3_Dir := ../enclave/linux
QE3_Signed_Name := $(QE3_Dir)/libsgx_qe3.signed.so

######## Quote Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

Quote_Cpp_Files := $(wildcard ../*.cpp)

Quote_Include_Paths := -I$(SGX_SDK)/include -I../inc -I../../common/inc -I./ -I../enclave -I$(TOP_DIR)/pce_wrapper/inc -I$(COMMON_DIR)/inc/internal -I$(COMMON_DIR)/inc/internal/linux

Quote_C_Flags := $(COMMON_FLAGS) -g -fPIC -Wno-attributes $(Quote_Include_Paths)

Quote_Cpp_Flags := $(Quote_C_Flags) -std=c++11
Quote_Link_Flags := $(COMMON_FLAGS) -g -l$(Urts_Library_Name) -lpthread -ldl 

ifndef DEBUG
Quote_Cpp_Flags += -DDISABLE_TRACE
Quote_Link_Flags += -DDISABLE_TRACE
endif

Quote_Cpp_Objects := $(Quote_Cpp_Files:.cpp=.o)
Quote_Cpp_Deps := $(Quote_Cpp_Objects:%.o=%.d)

Quote_Name := libquote.a

.PHONY: all
all:  install_lib


install_lib: $(Quote_Name) | $(BUILD_DIR)
	@$(CP) $(Quote_Name) $|


######## Quote Objects ########

qe3_u.c: $(SGX_EDGER8R) ../enclave/qe3.edl
	$(SGX_EDGER8R) --untrusted ../enclave/qe3.edl --search-path ../enclave
	@echo "GEN  =>  $@"

-include $(Quote_Cpp_Deps)

qe3_u.o: qe3_u.c
	@$(CC) $(Quote_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Quote_Cpp_Objects): %.o: %.cpp
	@$(CXX) $(Quote_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Quote_Name): qe3_u.o $(Quote_Cpp_Objects) $(PCE_Library)
	@rm -f $@
	$(AR) rcs libquotenopce.a qe3_u.o $(Quote_Cpp_Objects)
	# Add the PCE static library to the Quote static library
	$(AR) -rcsT $@ libquotenopce.a $(PCE_Library)
	@echo "LINK =>  $@"

$(PCE_Library): force_look
	@make -C $(PCE_Library_Dir)

$(QE3_Signed_Name): force_look
	@make -C $(QE3_Dir)

force_look:
	true

.PHONY: clean

clean:
	@rm -f .config_* $(Quote_Name) $(Quote_Cpp_Objects) $(Quote_Cpp_Deps) qe3_u.* libquotenopce.a
	@make -C $(PCE_Library_Dir) clean
	@make -C $(QE3_Dir) clean


