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

# Makefile 
SDK_HEADER                := $(SGX_SDK)/include

TARGET =libdcap_quoteprov.so

#INC = $(addprefix -I, $(SGX_HEADER))
INC = -I/opt/intel/sgxsdk/include

SRC_CPP=$(wildcard *.cpp)

SRC_OBJ+=$(SRC_CPP:.cpp=.o)

all: $(TARGET)  

$(TARGET): $(SRC_OBJ)
	@$(CXX) $(SRC_OBJ) $(CXXFLAGS) $(INC) -Wl,--version-script=platform.lds -Wl,--gc-sections -shared -o $@
	@$(CP) $@ $(TOPDIR)/$(BIN_DIR)/	

platform.o: platform.cpp
	$(CXX) $< $(INC) $(CXXFLAGS) -c -o $@

certchain.o: certchain.cpp
	$(CXX) $< $(INC) $(CXXFLAGS) -c -o $@

clean:
	@$(RM) $(TARGET) $(SRC_OBJ) 

.PHONY:
	all clean
