# This file is provided under a dual BSD/GPLv2 license.  When using or
# redistributing this file, you may do so under either license.
#
# GPL LICENSE SUMMARY
#
# Copyright(c) 2016-2018 Intel Corporation.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# Contact Information:
# Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
# Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
#
# BSD LICENSE
#
# Copyright(c) 2016-2018 Intel Corporation.
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
# Intel SGX
#

ifneq ($(KERNELRELEASE),)


ifneq ($(LE_ACTION),GENDATA)
	obj-m += intel_sgx.o
	intel_sgx-y := \
		sgx_le_proxy_piggy.o \
		sgx_ioctl.o \
		sgx_encl.o \
		sgx_main.o \
		sgx_page_cache.o \
		sgx_util.o \
		sgx_vma.o \
		sgx_le.o 
else
	obj-m += dummy_driver.o
	dummy_driver-y := dummy.o
endif

else
KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

ifneq ($(SIG_FILE),)
FULL_SIG_FILE = $(shell realpath $(SIG_FILE))
export FULL_SIG_FILE
endif

SGX_LE_SIGNING_KEY_PATH := sgx_signing_key.pem
SGX_LE_PUBLIC_KEY_PATH := sgx_public_key.pem
SGX_LE_SIGNING_MATERIAL := signing_material.bin

SIGNING_KEY_PATH := $(shell realpath $(SGX_LE_SIGNING_KEY_PATH))
PUBLIC_KEY_PATH := $(shell realpath $(SGX_LE_PUBLIC_KEY_PATH))
SIGNING_MATERIAL := $(shell realpath $(SGX_LE_SIGNING_MATERIAL))

export SIGNING_KEY_PATH
export PUBLIC_KEY_PATH
export SIGNING_MATERIAL

sign:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) CFLAGS_MODULE="-I$(PWD) -I$(PWD)/include" modules LE_ACTION=SIGN

gendata:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) CFLAGS_MODULE="-I$(PWD) -I$(PWD)/include" modules LE_ACTION=GENDATA

usesig:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) CFLAGS_MODULE="-I$(PWD) -I$(PWD)/include" modules LE_ACTION=USESIG

endif

ifeq ($(LE_ACTION)$(FULL_SIG_FILE),USESIG)
 $(error On usesig build - SIG_FILE must point to the signature input file)
endif

KBUILD_AFLAGS += -I$(PWD)/le 

$(eval $(call config_filename,INTEL_SGX_SIGNING_KEY))


$(SIGNING_KEY_PATH):
	$(Q)openssl genrsa -3 -out $(SIGNING_KEY_PATH) 3072

$(PUBLIC_KEY_PATH): $(SIGNING_KEY_PATH)
	$(Q)openssl rsa -in $(SIGNING_KEY_PATH) -outform PEM -pubout -out $(PUBLIC_KEY_PATH)


ifeq ($(LE_ACTION),SIGN)
SGX_LE_KEY_DEP := $(SIGNING_KEY_PATH)
else ifeq ($(LE_ACTION),USESIG)
SGX_LE_KEY_DEP := $(PUBLIC_KEY_PATH)
endif

$(obj)/dummy.o: $(SIGNING_MATERIAL)
$(obj)/sgx_le_proxy_piggy.o: $(SGX_LE_KEY_DEP) $(obj)/le/sgx_le_proxy
$(obj)/le/sgx_le_proxy $(SIGNING_MATERIAL): FORCE
	$(Q)$(MAKE) $(build)=$(obj)/le $@
 
clean:
	rm -vrf *.o *.ko *.order *.symvers *.mod.c .tmp_versions .*.cmd $(SIGNING_MATERIAL)
	$(Q)$(MAKE) -C le clean


