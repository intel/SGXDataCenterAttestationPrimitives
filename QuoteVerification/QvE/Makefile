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

######## SGX Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 0
QVL_SRC_PATH ?= ../QVL/Src/
SGXSSL_PACKAGE_PATH ?= ../sgxssl/Linux/package/
DCAP_DIR  ?= ../../
DCAP_QG_DIR  ?= $(DCAP_DIR)/QuoteGeneration/
include $(DCAP_QG_DIR)/buildenv.mk
###################################

SGX_COMMON_FLAGS := -m64
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        QVL_DIST_PATH := $(QVL_SRC_PATH)/Build/Debug/dist/
        QVL_LIB_NAME := QuoteVerificationd
        QVL_PARSER_NAME := QuoteVerificationd
        SGXSSL_TLIB = sgx_tsgxssld
        SGXSSL_TCRYPTO = sgx_tsgxssl_cryptod
        SGX_COMMON_FLAGS += -O0 -g3  -ggdb -DDEBUG_MODE=1
else
        QVL_DIST_PATH := $(QVL_SRC_PATH)/Build/Release/dist/
        QVL_LIB_NAME := QuoteVerification
        QVL_PARSER_NAME := AttestationParsers
        SGXSSL_TLIB = sgx_tsgxssl
        SGXSSL_TCRYPTO = sgx_tsgxssl_crypto
        SGX_COMMON_FLAGS += -O2 -fno-delete-null-pointer-checks
endif

SGX_COMMON_FLAGS += -DSGX_TRUSTED -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++14

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

TAttestation_Lib_DIR := $(QVL_SRC_PATH)/AttestationLibrary/
TAttestation_Parsers_DIR := $(QVL_SRC_PATH)/AttestationParsers/

COMMON_INCLUDE := -IInclude -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx -I$(SGXSSL_PACKAGE_PATH)/include -I../QVL/Src/ThirdParty/rapidjson/include
TAttestation_Lib_Include_Paths := $(COMMON_INCLUDE) -I$(TAttestation_Lib_DIR)/include -I$(TAttestation_Lib_DIR)/src -I$(TAttestation_Parsers_DIR)/include
TAttestation_Parsers_Include_Paths := $(COMMON_INCLUDE) -I$(TAttestation_Parsers_DIR)/include -I$(TAttestation_Parsers_DIR)/src -I$(TAttestation_Lib_DIR)/include

TAttestation_Lib_Cpp_Files := $(wildcard $(TAttestation_Lib_DIR)/src/*.cpp) $(wildcard $(TAttestation_Lib_DIR)/src/*/*.cpp)
TAttestation_Parsers_Cpp_Files0 := $(wildcard $(TAttestation_Parsers_DIR)/src/*.cpp) $(wildcard $(TAttestation_Parsers_DIR)/src/*/*.cpp)
GMTIM = ../QVL/Src//AttestationParsers//src/Utils/GMTime.cpp
TAttestation_Parsers_Cpp_Files := $(filter-out $(GMTIM),$(TAttestation_Parsers_Cpp_Files0))

TAttestation_Lib_Obj_Files := $(TAttestation_Lib_Cpp_Files:.cpp=.o)
TAttestation_Parsers_Obj_Files := $(TAttestation_Parsers_Cpp_Files:.cpp=.o)


Enclave_Cpp_Files := Enclave/qve.cpp

Enclave_Include_Paths := $(COMMON_INCLUDE) -I$(QVL_SRC_PATH) -I$(DCAP_QG_DIR)/quote_wrapper/common/inc -I$(DCAP_QG_DIR)/pce_wrapper/inc

Enclave_C_Flags := $(Enclave_Include_Paths) -nostdinc -fvisibility=hidden -fpie -fpic
ifneq ($(SGX_DEBUG), 1)
    Enclave_C_Flags += -ffunction-sections -fdata-sections
endif
CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
	Enclave_C_Flags += -fstack-protector
else
	Enclave_C_Flags += -fstack-protector-strong
endif

Enclave_Cpp_Flags := $(Enclave_C_Flags) -nostdinc++

# Enable the security flags
Enclave_Security_Link_Flags := -Wl,-z,relro,-z,now,-z,noexecstack

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(Enclave_Security_Link_Flags) -fPIC \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -Llib -L$(SGXSSL_PACKAGE_PATH)/lib64 -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -l$(SGXSSL_TLIB) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(SGXSSL_TCRYPTO) -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined -Wl,--gc-sections \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic -Wl,-Map,out.map \
	-Wl,--defsym,__ImageBase=0  \
	-Wl,--version-script=Enclave/linux/qve.lds

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

Enclave_Name := qve.so
Signed_Enclave_Name := libsgx_qve.signed.so
Enclave_Config_File := Enclave/linux/config.xml

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif


.PHONY: all target run PREPARE_SGX_SSL

all: .config_$(Build_Mode)_$(SGX_ARCH) install_lib PREPARE_SGX_SSL
	@$(MAKE) target

$(BUILD_DIR):
	@$(MKDIR) $@

PREPARE_SGXSSL := ../prepare_sgxssl.sh
SGXSSL_HEADER_CHECK := $(SGXSSL_PACKAGE_PATH)/include/openssl/opensslconf.h
PREPARE_SGX_SSL:
	chmod 755 $(PREPARE_SGXSSL)
	test -f $(SGXSSL_PACKAGE_PATH)/lib64/lib$(SGXSSL_TCRYPTO).a && test -f $(SGXSSL_PACKAGE_PATH)/lib64/lib$(SGXSSL_TLIB).a && test -f $(SGXSSL_HEADER_CHECK) || $(PREPARE_SGXSSL)



install_lib: $(Signed_Enclave_Name) | $(BUILD_DIR)
	@$(CP) $(Signed_Enclave_Name) $|

ifeq ($(Build_Mode), HW_RELEASE)
target: $(Enclave_Name)
	@echo "The QvE has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."


else
target: $(Signed_Enclave_Name)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif

endif

.config_$(Build_Mode)_$(SGX_ARCH):
	@rm -f $(Enclave_Name) $(Signed_Enclave_Name) $(Enclave_Cpp_Objects) Enclave/qve_t.*
	@touch .config_$(Build_Mode)_$(SGX_ARCH)

######## Enclave Objects ########

Enclave/qve_t.h: $(SGX_EDGER8R) Enclave/qve.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/qve.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

Enclave/qve_t.c: Enclave/qve_t.h

Enclave/qve_t.o: Enclave/qve_t.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(SGXSSL_PACKAGE_PATH)/lib64/lib$(SGXSSL_TCRYPTO).a: PREPARE_SGX_SSL
$(SGXSSL_PACKAGE_PATH)/lib64/lib$(SGXSSL_TLIB).a: PREPARE_SGX_SSL
$(SGXSSL_HEADER_CHECK): PREPARE_SGX_SSL

$(TAttestation_Lib_Obj_Files): %.o: %.cpp $(SGXSSL_HEADER_CHECK)
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Enclave_Cpp_Flags) $(TAttestation_Lib_Include_Paths) -c $< -o $@
	@echo "CXX  <=  $<"

$(TAttestation_Parsers_Obj_Files): %.o: %.cpp $(SGXSSL_HEADER_CHECK)
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Enclave_Cpp_Flags) $(TAttestation_Parsers_Include_Paths) -c $< -o $@
	@echo "CXX  <=  $<"

Enclave/%.o: Enclave/%.cpp Enclave/qve_t.h $(SGXSSL_HEADER_CHECK)
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Enclave_Cpp_Flags) -I$(TAttestation_Lib_DIR)/include -I$(TAttestation_Lib_DIR)/src -I$(TAttestation_Parsers_DIR)/include -I$(TAttestation_Parsers_DIR)/src -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Name): $(TAttestation_Parsers_Obj_Files) $(TAttestation_Lib_Obj_Files) $(Enclave_Cpp_Objects) Enclave/qve_t.o
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave/qve_key.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

print-%  : ; @echo $* = $($*)

.PHONY: clean SGXSSL_clean

clean:
	@echo "Cleaning objects"
	@rm -f .config_* $(Enclave_Name) $(Signed_Enclave_Name) Enclave/str_to_time.o Enclave/bionic_localtime.o $(Enclave_Cpp_Objects) $(TAttestation_Lib_Obj_Files) $(TAttestation_Parsers_Obj_Files) Enclave/qve_t.*

SGXSSL_clean:
	@rm -rf ../sgxssl/
