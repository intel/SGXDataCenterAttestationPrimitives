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
SGX_ARCH ?= x64

ifeq ($(shell getconf LONG_BIT), 32)
        SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
        SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
        SGX_COMMON_CFLAGS := -m32
        SGX_LIBRARY_PATH := $(SGX_SDK)/lib
else
        SGX_COMMON_CFLAGS := -m64
        SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
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

# additional warnings flags for C++
CXXFLAGS += -Wnon-virtual-dtor

CXXFLAGS += -std=c++11

# Enable the security flags
COMMON_LDFLAGS := -Wl,-z,relro,-z,now,-z,noexecstack
######## SGX QPL Library Settings ########

QPL_Lib_Cpp_Files := $(wildcard *.cpp ../*.cpp)

QPL_Lib_Include_Paths := -I../../../../QuoteGeneration/quote_wrapper/common/inc -I../../../../QuoteGeneration/common/inc/internal
QPL_Lib_Include_Paths += -I../../../../QuoteGeneration/pce_wrapper/inc -I../../../../QuoteGeneration/quote_wrapper/ql/inc 
QPL_Lib_Include_Paths += -I../inc -I$(SGX_SDK)/include 

QPL_Lib_C_Flags := $(COMMON_FLAGS) -fPIC -Wno-attributes $(QPL_Lib_Include_Paths)

LDUFLAGS:= -pthread $(COMMON_LDFLAGS)
LDUFLAGS += -Wl,--gc-sections

QPL_Lib_Cpp_Flags := $(QPL_Lib_C_Flags) -std=c++11

QPL_Lib_Link_Flags := $(SGX_COMMON_FLAGS) -L$(SGX_SDK)/lib64 -lpthread -ldl  -Wl,-rpath=.


QPL_Lib_Cpp_Objects := $(QPL_Lib_Cpp_Files:.cpp=.o)
QPL_Lib_Cpp_Deps := $(QPL_Lib_Cpp_Objects:%.o=%.d)

QPL_Lib_Name_Dynamic  := libdcap_quoteprov.so.1

.PHONY: all
all: $(QPL_Lib_Name_Dynamic)


######## QPL Library Objects ########

-include $(QPL_Lib_Cpp_Deps)

$(QPL_Lib_Cpp_Objects): %.o: %.cpp
	@$(CXX) $(QPL_Lib_Cpp_Flags) -MMD -c $< -o $@
	@echo "CXX  <=  $<"

$(QPL_Lib_Name_Dynamic): $(QPL_Lib_Cpp_Objects)
	$(CXX) $(CXXFLAGS) $(QPL_Lib_Cpp_Objects) -shared -Wl,-soname=$@ $(LDUFLAGS) $(QPL_Lib_Link_Flags) -o $@


.PHONY: clean
clean:
	@rm -f $(QPL_Lib_Cpp_Objects) $(QPL_Lib_Cpp_Deps) $(QPL_Lib_Name_Dynamic)


