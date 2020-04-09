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

ifeq ($(SGX_SDK),)
$(error Error!!! Please make sure SGX-SDK is installed and environment script have been executed by: `source /opt/intel/sgxsdk/environment`. Stopping now)
endif 


# -----------------------------------------------------------------------------
# Function : parent-dir
# Arguments: 1: path
# Returns  : Parent dir or path of $1, with final separator removed.
# -----------------------------------------------------------------------------
parent-dir = $(patsubst %/,%,$(dir $(1:%/=%)))

# -----------------------------------------------------------------------------
# Macro    : my-dir
# Returns  : the directory of the current Makefile
# Usage    : $(my-dir)
# -----------------------------------------------------------------------------
my-dir = $(realpath $(call parent-dir,$(lastword $(MAKEFILE_LIST))))


ROOT_DIR              := $(call my-dir)
COMMON_DIR            := $(ROOT_DIR)/common


LOCAL_COMMON_DIR  := $(ROOT_DIR)/common
INCLUDE_DIR := $(ROOT_DIR)/include
LIBS_DIR := $(ROOT_DIR)/build/lib64
BINS_DIR := $(ROOT_DIR)/build/bin
CP := /bin/cp -f

CXXFLAGS := -fPIC

RA_VERSION= $(shell awk '$$2 ~ /STRFILEVER/ { print substr($$3, 2, length($$3) - 2); }' $(LOCAL_COMMON_DIR)/inc/internal/ra_version.h)
SPLIT_VERSION=$(word $2,$(subst ., ,$1))

# turn on stack protector
CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
    COMMON_FLAGS += -fstack-protector
else
    COMMON_FLAGS += -fstack-protector-strong
endif

# turn on cet
CC_GREAT_EQUAL_8 := $(shell expr "`$(CC) -dumpversion`" \>= "8")
ifeq ($(CC_GREAT_EQUAL_8), 1)
    COMMON_FLAGS += -fcf-protection
endif

ifdef DEBUG
    COMMON_FLAGS += -ggdb -DDEBUG -UNDEBUG
    COMMON_FLAGS += -DSE_DEBUG_LEVEL=SE_TRACE_DEBUG
else
    COMMON_FLAGS += -O2 -D_FORTIFY_SOURCE=2 -UDEBUG -DNDEBUG
endif

COMMON_FLAGS += -ffunction-sections -fdata-sections -fstack-clash-protection

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

CFLAGS   += $(COMMON_FLAGS)
CXXFLAGS += $(COMMON_FLAGS)

LDFLAGS += -shared

INCLUDE += -I$(INCLUDE_DIR)
INCLUDE += -I$(INCLUDE_DIR)/c_wrapper
INCLUDE += -I$(LOCAL_COMMON_DIR)/inc
INCLUDE += -Iinc

CPP_OBJS := $(CPP_SRCS:%.cpp=%.o)
CPP_DEPS := $(CPP_OBJS:%.o=%.d)

all: $(TARGET_LIB).so $(CPP_OBJS)
static: $(TARGET_LIB).a

.PHONY: clean all

$(TARGET_LIB).so : $(CPP_OBJS)
	$(CC) $(CCFLAGS) $(CFLAGS) $(CPP_OBJS) -Wl,-soname=$@.$(call SPLIT_VERSION,$(RA_VERSION),1)  $(LDFLAGS) -o $@
	$(CP) $@ $(LIBS_DIR)

$(CPP_OBJS): %.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $(INCLUDE) $(LDFLAGS) -MMD $< -o $@

clean:
	@$(RM) $(CPP_OBJS) $(TARGET_LIB).a $(TARGET_LIB).so $(CPP_DEPS)
