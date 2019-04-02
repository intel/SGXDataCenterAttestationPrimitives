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

include ../../buildenv.mk

INCLUDE += -I. -I../inc
INCLUDE += -I$(SGX_SDK)/include         \
           -I$(COMMON_DIR)/inc/internal \
           -I$(COMMON_DIR)/inc/internal/linux \

INCLUDE += -I$(ROOT_DIR)/ae/common \
           -I$(ROOT_DIR)/ae/inc    \
           -I$(ROOT_DIR)/ae/inc/internal    \
           -I$(ROOT_DIR)/parser            \
           -I$(ROOT_DIR)/parser/linux

CXXFLAGS += -fPIC -Werror -g

CFLAGS += -fPIC -Werror -g

Link_Flags := $(SGX_COMMON_CFLAGS) -L$(ROOT_DIR)/build/linux -L$(SGX_SDK)/lib64 -lsgx_urts -lpthread -ldl

vpath %.cpp .. $(ROOT_DIR)/parser $(ROOT_DIR)/parser/linux
vpath %.c   $(COMMON_DIR)/src

pce_wrapper.o: pce_u.c

pce_u.c:  ${ROOT_DIR}/ae/pce/pce.edl
	@$(SGX_EDGER8R) --untrusted --untrusted-dir . $<

C_SRC   := pce_u.c se_trace.c se_map.c se_thread.c

SRC :=       pce_wrapper.cpp pce_parser.cpp section.cpp elfparser.cpp

OBJ := $(C_SRC:.c=.o) $(SRC:.cpp=.o)

LDUFLAGS:= -pthread $(COMMON_LDFLAGS)
LDUFLAGS += -Wl,--version-script=pce_wrapper.lds -Wl,--gc-sections

LIBNAME  = libsgx_pce_wrapper.so
LIBNAME_DEBUG  = libsgx_pce_wrapper.so.debug
STATIC_LIBNAME  = libsgx_pce_wrapper.a

.PHONY: all
all:  install_lib
 
.PHONY: install_lib
install_lib: $(LIBNAME) $(STATIC_LIBNAME)  $(LIBNAME_DEBUG) | $(BUILD_DIR)
	@$(CP) $(LIBNAME) $|
	@$(CP) $(STATIC_LIBNAME) $|
ifndef DEBUG
	@$(CP) $(LIBNAME_DEBUG) $|
endif

$(LIBNAME): $(OBJ)
	$(CXX) $(CXXFLAGS) $(OBJ) -shared $(LDUFLAGS) $(Link_Flags) -o $@

$(STATIC_LIBNAME): $(OBJ)
	$(AR) rcsD $@ $^

$(LIBNAME_DEBUG): $(LIBNAME)
	((test -f $(LIBNAME_DEBUG)) || $(MAKE) separate_debug_info)

.PHONY: separate_debug_info
separate_debug_info:
ifndef DEBUG
	$(CP) $(LIBNAME) $(LIBNAME).orig
	$(OBJCOPY) --only-keep-debug $(LIBNAME) $(LIBNAME_DEBUG)
	$(STRIP) -g $(LIBNAME)
	$(OBJCOPY) --add-gnu-debuglink=$(LIBNAME_DEBUG) $(LIBNAME)
endif

%.o :%.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDE) -c $< -o $@
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) -Werror -fPIC -c $< -o $@


$(BUILD_DIR):
	@$(MKDIR) $@

.PHONY: clean
clean:
	@$(RM) $(OBJ) $(LIBNAME).orig *_u.h *_u.c
	@$(RM) $(LIBNAME) $(BUILD_DIR)/$(LIBNAME) 
	@$(RM) $(STATIC_LIBNAME) $(BUILD_DIR)/$(STATIC_LIBNAME) 
	@$(RM) $(LIBNAME_DEBUG) $(BUILD_DIR)/$(LIBNAME_DEBUG)

.PHONY: rebuild
rebuild:
	$(MAKE) clean
	$(MAKE) all
