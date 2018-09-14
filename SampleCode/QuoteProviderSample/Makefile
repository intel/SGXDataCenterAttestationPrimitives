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

ifeq ($(SGX_SDK),)
$(warning "import SGX SDK environment variable")
export SGX_SDK=/opt/intel/sgxsdk
endif

CFLAGS = -Wall -Wfatal-errors -fPIC
CXXFLAGS = -Wall -Wfatal-errors -fPIC

SGX_SDK_PATH ?= $(SGX_SDK)

ifeq ($(DEBUG), y)
CFLAGS += -g
CXXFLAGS += -g
else
endif

BIN_DIR := bin
TOPDIR = $(CURDIR)

ifneq ($(BIN_DIR),)
$(shell mkdir -p $(BIN_DIR))
endif

CP = cp

export CFLAGS
export CXXFLAGS
export TOPDIR
export BIN_DIR
export SGX_SDK_PATH
export CP

SUB_DIR:=QuoteGenerationSample platform_lib

App_Name := quotegen

Quote_Provider := libdcap_quoteprov.so

.PHONY: $(SUB_DIR) clean 

$(SUB_DIR):
	@for dir in $(SUB_DIR); do \
		$(MAKE) -C $$dir; \
	done 
	$(CP) cert/*.pem $(BIN_DIR)/
clean:
	@rm -rf $(BIN_DIR)
	@for dir in $(SUB_DIR); do \
		$(MAKE) -C $$dir clean; \
	done
