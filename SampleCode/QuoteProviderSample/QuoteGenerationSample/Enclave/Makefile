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

ENCLAVE_NAME = enclave.so
TARGET = enclave.signed.so

Enclave_Cpp_Files := enclave.cpp
Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)
Enclave_Config_File := enclave_config.xml

SGX_LIBRARY_PATH := $(SGX_SDK)/lib64

SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
SGX_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign

Enclave_Include_Paths = -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc  
Enclave_C_Flags := -O2 -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++03 -nostdinc++

Enclave_Link_Flags := -shared -O2 -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
        -Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
        -Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -lsgx_tcrypto -lsgx_tstdcxx -lsgx_tservice -Wl,--end-group \
        -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
        -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
        -Wl,--defsym,__ImageBase=0 \
        -Wl,--version-script=enclave.lds

all: $(TARGET)
       
$(TARGET): enclave_t.o $(Enclave_Cpp_Objects)
	$(CXX) $^ -MMD -o $(ENCLAVE_NAME) $(Enclave_Link_Flags)	
	$(SGX_SIGNER) sign -key enclave_private.pem -enclave $(ENCLAVE_NAME) -out $@ -config $(Enclave_Config_File)

$(Enclave_Cpp_Objects): %.o: %.cpp
	$(CXX) $(Enclave_Cpp_Flags) -c -MMD $< -o $@

enclave_t.o: enclave_t.c
	$(CC) $(Enclave_C_Flags) -c -MMD $< -o $@

enclave_t.c: $(SGX_EDGER8R) enclave.edl 
	$(SGX_EDGER8R) --trusted enclave.edl --search-path $(SGX_SDK)/include

clean:
	$(RM) *.o *.d enclave_t.* $(ENCLAVE_NAME) $(TARGET)

.PHONY: all clean
