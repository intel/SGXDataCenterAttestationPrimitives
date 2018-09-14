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


TOP_DIR := ../../../..
include ../../../ae/buildenv.mk

AENAME = qe3


CONFIG := config.xml
TCRYPTO_LIB_NAME := sgx_tcrypto

INCLUDE := -I$(SGX_SDK)/include                        \
           -I$(SGX_SDK)/include/tlibc                  \
           -I$(SGX_SDK)/include/ipp                    \
           -I$(COMMON_DIR)/inc                         \
           -I$(COMMON_DIR)/inc/internal                \
           -I$(LINUX_PSW_DIR)/ae/inc/internal             \
           -I../../common/inc                             \
           -I../../../pce_wrapper/inc                     \
           -I..
ifeq ($(USE_SGXSSL), 1)
	INCLUDE += -I$(OPENSSL_PACKAGE)/include
endif

EXTERNAL_LIB = $(EXTERNAL_LIB_NO_CRYPTO) -lsgx_tstdcxx -l$(TCRYPTO_LIB_NAME)

SRC := $(wildcard *.cpp)

OBJ := $(SRC:.cpp=.o)
OBJS := $(sort $(OBJ) version.o)

KEYFILE := qe3_private.pem
AENAME_OUT := libsgx_qe3.signed.so
QE3_COPY_OUT := $(AENAME_OUT)

.PHONY: all
all: $(AENAME_OUT) | $(BUILD_DIR)
	@$(CP) $(QE3_COPY_OUT) $|

$(AENAME_OUT): $(SONAME) $(KEYFILE) $(CONFIG)
	@echo ------------------------------------------------------
	@echo Signing $<...
	@$(SGX_ENCLAVE_SIGNER) sign -key $(KEYFILE) -enclave $< -out $@ -config $(CONFIG)
	@echo Signed Enclave: $@
	@echo Enclave mode: $(MODE)

$(SONAME): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@  $(OBJS)  -nostdlib -nodefaultlibs -nostartfiles $(LDTFLAGS) -fno-exceptions -fno-rtti

quoting_enclave_3.o: $(AENAME)_t.c

%.o:%.cpp 
	$(CXX) $(CXXFLAGS) $(INCLUDE) $(DEFINES) -fno-exceptions -c $< -o $@

$(AENAME)_t.c: $(AENAME).edl
	@$(SGX_EDGER8R) --trusted $<

$(BUILD_DIR):
	@$(MKDIR) $@

.PHONY: clean
clean:
	@$(RM) *.o
	@$(RM) *.so
	@$(RM) *.map
	@$(RM) *_t.* 

.PHONY: rebuild
rebuild:
	$(MAKE) clean
	$(MAKE) all
