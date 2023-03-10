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




ifdef DEBUG
    COMMON_FLAGS += -ggdb -DDEBUG -UNDEBUG
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

CFLAGS += $(COMMON_FLAGS)

JAVA_HOME=$(shell readlink -f /usr/bin/javac | sed "s:bin/javac::")

all: lib_jni_dcap_quoteverify
JNI_WRAPPER_VERSION = 1
jni_dcap_quoteverify_lib := libjni_dcap_quoteverify.so


QvL_BUILD_PATH := ../../QuoteVerification/dcap_quoteverify/linux
DISTDIR := src/main/c/lib
JNI_C_SRCS := src/main/c/jni/sgx_dcap_quoteverify_wrap.c
JNI_C_SRCS += src/main/c/jni/jni_native_lib_init.c
JNI_C_OBJS := $(JNI_C_SRCS:.c=.o)

INCLUDE_DIR = -I$(JAVA_HOME)/include
INCLUDE_DIR += -I$(JAVA_HOME)/include/linux
CFLAGS += $(INCLUDE_DIR)
CFLAGS += -fvisibility=hidden

lib_jni_dcap_quoteverify: $(JNI_C_OBJS)
	test -d "$(DISTDIR)" || mkdir "$(DISTDIR)"
	$(CC) -shared -Wl,-soname=$(jni_dcap_quoteverify_lib) -o $(DISTDIR)/$(jni_dcap_quoteverify_lib).$(JNI_WRAPPER_VERSION) $^
	ldconfig -n src/main/c/lib

%.o : %.c
	$(CC) $(CFLAGS) -fPIC -o $@ -c $<

clean:
	$(RM) $(JNI_C_OBJS) src/main/c/lib/*.so*

.PHONYT: clean all
