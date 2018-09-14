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

######## App Settings ########

App_Name := quotegen 

APP_Include = $(addprefix -I, .) 
APP_Include += $(addprefix -I, Enclave) 
APP_Include += $(addprefix -I, $(SGX_SDK)/include) 
CFLAGS += -Wno-attributes $(APP_Include)
CXXFLAGS += -Wno-attributes $(APP_Include) -std=c++11


SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

OE_Library := -Wl,-Bdynamic -lsgx_dcap_ql
Urts_Library_Name := sgx_urts 

App_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,-Bdynamic -l$(Urts_Library_Name) -ldl -lpthread 


App_Cpp_Files :=  App/App.cpp
App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)



.PHONY: all 

all: $(App_Name)

######## App Objects ########

enclave_u.o: enclave_u.c
	@$(CC) $(CFLAGS) -c $< -o $@

enclave_u.c: Enclave/enclave.edl
	$(SGX_EDGER8R) --untrusted Enclave/enclave.edl --search-path Enclave --search-path $(SGX_SDK)/include

App/%.o: App/%.cpp
	@$(CXX) $(CXXFLAGS) -c $< -o $@

$(App_Name): enclave_u.o $(App_Cpp_Objects)
	@$(CXX) $^ -o $@ $(OE_Library) $(App_Link_Flags)
	@$(MAKE) -C Enclave
	@cp Enclave/enclave.signed.so $(TOPDIR)/$(BIN_DIR)/
	@cp $(App_Name) $(TOPDIR)/$(BIN_DIR)/	

.config_$(Build_Mode)_$(SGX_ARCH):
	@rm -f .config_* $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) App/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.*
	@touch .config_$(Build_Mode)_$(SGX_ARCH)


.PHONY: clean

clean:
	@$(MAKE) -C Enclave clean
	@rm -f .config_* $(App_Name)  $(App_Cpp_Objects) enclave.signed.so App/*.o 
	@rm -f libsgx_*
	@rm -f enclave_u*
