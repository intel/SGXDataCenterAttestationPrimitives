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

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64

ifeq ($(shell getconf LONG_BIT), 32)
        SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
        SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
        SGX_COMMON_CFLAGS := -m32
        SGX_LIBRARY_PATH := $(SGX_SDK)/lib
        SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
        SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
        SGX_COMMON_CFLAGS := -m64
        SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
        SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
        SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

# turn on stack protector for SDK
CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
    COMMON_FLAGS += -fstack-protector
else
    COMMON_FLAGS += -fstack-protector-strong
endif

ifdef DEBUG
    COMMON_FLAGS += -O0 -ggdb -DDEBUG -UNDEBUG
else
    COMMON_FLAGS += -O2 -D_FORTIFY_SOURCE=2 -UDEBUG -DNDEBUG
endif


COMMON_FLAGS += -ffunction-sections -fdata-sections

# turn on compiler warnings as much as possible
COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                -Waddress -Wsequence-point -Wformat-security \
                -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                -Wcast-align -Wconversion -Wredundant-decls

# additional warnings flags for C
CFLAGS += -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants

# additional warnings flags for C++
CXXFLAGS += -Wnon-virtual-dtor

CXXFLAGS += -std=c++11



######## App Settings ########

App_Cpp_Files := $(wildcard App/linux/*.cpp App/*.cpp)
App_Include_Paths := -I$(SGX_SDK)/include -I./App -I ./App/inc
App_Include_Paths += -I ../../QuoteGeneration/common/inc/internal -I ../../QuoteGeneration/quote_wrapper/ql/inc 
App_Include_Paths += -I ../../QuoteGeneration/pce_wrapper/inc -I ../../QuoteGeneration/quote_wrapper/common/inc
App_Include_Paths += -I ../SGXPlatformRegistration/include

App_C_Flags := $(COMMON_FLAGS) -fPIC -Wno-attributes $(App_Include_Paths)

App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,-z,relro,-z,now,-z,noexecstack
App_Link_Flags +=  -lcurl -ldl -lpthread -Wl,-rpath=.


App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

App_Name := PCKIDRetrievalTool

######## Enclave Settings ########
Trts_Library_Name := sgx_trts
Service_Library_Name := sgx_tservice
Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files := Enclave/Enclave.cpp
Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx

CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
        Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector
else
        Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector-strong
endif
Enclave_C_Flags += $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++11 -nostdinc++

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
        -Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
        -Wl,--start-group -lsgx_tstdc -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
        -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
        -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
        -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
	-Wl,-z,relro,-z,now,-z,noexecstack             \
        -Wl,--version-script=Enclave/Enclave.lds

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)
ENCLAVE_LIBRARY_PATH := Enclave/
ENCLAVE_SIGNING_KEY := $(ENCLAVE_LIBRARY_PATH)test_enclave_signing_key.pem


Enclave_Name := pck_id_retrieval_tool_enclave.so
Signed_Enclave_Name := pck_id_retrieval_tool_enclave.signed.so
Enclave_Config_File := Enclave/config.xml

ifeq ($(DEBUG), 1)
	Build_Mode = HW_DEBUG
else
	Build_Mode = HW_RELEASE
endif





.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: $(App_Name) $(Signed_Enclave_Name)
	make -C Qpl/linux
	@cp -f Qpl/linux/libdcap_quoteprov.so.1 .
	@echo "The project has been built in release hardware mode."
else
all: $(App_Name) $(Signed_Enclave_Name)
	make -C Qpl/linux
	@cp -f Qpl/linux/libdcap_quoteprov.so.1 .
	@echo "The project has been built in debug hardware mode."
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif


######## App Objects ########

App/Enclave_u.c:
	cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl
	@echo "GEN  =>  $@"

App/Enclave_u.o: App/Enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

App/%.o: App/%.cpp
	$(CXX) $(App_Cpp_Flags) -c $< -o $@
	echo "CXX  <=  $<"

$(App_Name): App/Enclave_u.o $(App_Cpp_Objects)
	$(CXX) $^ $(App_Link_Flags) -o $@
	echo "LINK =>  $@"

.config_$(Build_Mode)_$(SGX_ARCH):
	@rm -f .config_* $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) App/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.*

######## Enclave Objects ########

$(ENCLAVE_SIGNING_KEY):
	@openssl genrsa -3 -out $@ 3072
	@echo "GEN  =>  $@"


Enclave/Enclave_t.h: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl 
	@echo "GEN  =>  $@"

Enclave/Enclave_t.c: Enclave/Enclave_t.h

Enclave/Enclave_t.o: Enclave/Enclave_t.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Enclave/%.o: Enclave/%.cpp Enclave/Enclave_t.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Name): Enclave/Enclave_t.o $(Enclave_Cpp_Objects)
	$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	echo "LINK =>  $@"


$(Signed_Enclave_Name): $(Enclave_Name) $(ENCLAVE_SIGNING_KEY)
	@$(SGX_ENCLAVE_SIGNER) sign -key $(ENCLAVE_SIGNING_KEY) -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@rm -f $(Enclave_Name)
	@echo "SIGN =>  $@"

.PHONY: clean

clean:
	@rm -f $(App_Name)  $(Signed_Enclave_Name) $(App_Cpp_Objects) App/Enclave_u.* $(Enclave_Cpp_Objects) $(ENCLAVE_SIGNING_KEY) Enclave/Enclave_t.* libdcap_quoteprov.so.1
	make -C Qpl/linux clean
