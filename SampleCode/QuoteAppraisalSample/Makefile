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

SGX_ARCH ?= x64
SGX_DEBUG ?= 0

# Don't support 32bit in this sample
SGX_COMMON_FLAGS := -m64
APPRAISAL_TOOL := tee_appraisal_tool
EC_PRIVATE_KEY := ec_priv.pem

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_FLAGS += -O0 -g3  -ggdb
else
        SGX_COMMON_FLAGS += -O2
endif

SGX_COMMON_FLAGS += -DSGX_TRUSTED -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++11

App_Cpp_Files := App/App.cpp
App_Include_Paths := -IApp -I../../external/jwt-cpp/include

App_C_Flags := -fPIC -Wno-attributes $(App_Include_Paths)

ifeq ($(SGX_DEBUG), 1)
        App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else
        App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(App_C_Flags)
App_Link_Flags := -fsanitize=undefined -lsgx_dcap_quoteverify -lssl -lcrypto -lpthread -ldl

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

App_Name := app

Policy_Manifest_Files := $(wildcard Policies/*.json)
Policy_Tokens := $(sort $(Policy_Manifest_Files:.json=.jwt))

.PHONY: all target run
all: target

target: $(App_Name) $(Policy_Tokens)

run: all
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [OK]"

App/%.o: App/%.cpp
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): $(App_Cpp_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"


%.jwt: %.json
ifeq ($(wildcard $(EC_PRIVATE_KEY)),)
	openssl ecparam -name secp384r1 -genkey -out $(EC_PRIVATE_KEY)
endif
	$(APPRAISAL_TOOL) sign_policy -in $< -key $(EC_PRIVATE_KEY) -out $@ 

.PHONY: clean

clean:
	@rm -f $(App_Name) $(App_Cpp_Objects) $(Policy_Tokens)
