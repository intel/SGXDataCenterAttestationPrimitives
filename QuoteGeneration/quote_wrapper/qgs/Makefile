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
TOP_DIR  = ../..
include $(TOP_DIR)/buildenv.mk

QGS_SRCS = se_trace.c server_main.cpp qgs_server.cpp qgs_log.cpp qgs_ql_logic.cpp
QGS_OBJS = $(patsubst %.c,%.o,$(patsubst %.cc,%.o,$(patsubst %.cpp,%.o,$(QGS_SRCS))))

QGS_INC = -I$(SGX_SDK)/include \
		  -I$(COMMON_DIR)/inc/internal \
		  -I$(TOP_DIR)/qpl/inc \
		  -I$(TOP_DIR)/quote_wrapper/tdx_quote/inc \
		  -I$(TOP_DIR)/quote_wrapper/qgs_msg_lib/inc
QGS_CFLAGS = -g  -MMD $(CFLAGS) $(QGS_INC)
QGS_CXXFLAGS = -g  -MMD $(CXXFLAGS) $(QGS_INC)
ifeq ($(CC_NO_LESS_THAN_8), 1)
    QGS_CFLAGS += -fcf-protection=none
    QGS_CXXFLAGS += -fcf-protection=none
endif

DEPENDS = ${QGS_OBJS:.o=.d}

# SGX related libraries
QGS_LFLAGS = -L$(TOP_DIR)/build/linux -lsgx_tdx_logic -lsgx_pce_logic -ldl \
             -L$(SGX_SDK)/lib64 -lsgx_urts -g
# add boost_system for link
QGS_LFLAGS += -lboost_system -lboost_thread -lpthread
# add qgs_msg_lib for link
QGS_LFLAGS += -L../qgs_msg_lib/linux -lqgs_msg

vpath %.c $(COMMON_DIR)/src

-include ${DEPENDS}

all: qgs

qgs: $(QGS_OBJS)
	make -C ../qgs_msg_lib/linux
	make -C ../tdx_quote/linux
	$(CXX) -o $@ $^ $(QGS_LFLAGS)

%.o: %.cpp
	$(CXX) -c $(QGS_CXXFLAGS) $<

%.o: %.c
	$(CC) -c $(QGS_CFLAGS) $<

clean:
	make -C ../qgs_msg_lib/linux clean
	make -C ../tdx_quote/linux clean
	rm -f *.d
	rm -f *.o
	rm -f qgs
