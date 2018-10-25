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
# Authors:
#
# Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>

KASAN_SANITIZE := n
OBJECT_FILES_NON_STANDARD := y
KCOV_INSTRUMENT := n
KBUILD_CFLAGS := -Wall -Werror -static -nostdlib -nostartfiles -fPIE \
		 -fno-stack-protector -mrdrnd  -I$(obj)/include -I$(obj)/../include \
		 -I$(srctree)/arch/x86/include -I$(PWD)/include

always := sgx_le.elf sgx_le.bin sgx_le.ss sgx_le_blob.h sgx_le_ss.h
clean-files := sgx_le.elf sgx_le.bin sgx_le.ss sgx_le_blob.h sgx_le_ss.h sgxsign bin2c

ifeq ($(INTEL_SIGNED),1)
SIGN_EXTRA := intel_signed
endif

#
# sgx_le.ss
#



HOST_EXTRACFLAGS += -I$(srctree)/arch/x86/include -I$(PWD)/include
HOSTLOADLIBES_sgxsign = -lcrypto
hostprogs-y += sgxsign
quiet_cmd_sgxsign = SGXSIGN $@
ifeq ($(LE_ACTION),SIGN)
      cmd_sgxsign = $(PWD)/le/enclave/sgxsign \
		    sign $(SIGNING_KEY_PATH) $< $@ $(SIGN_EXTRA)
else ifeq ($(LE_ACTION),GENDATA)
       cmd_sgxsign = $(PWD)/le/enclave/sgxsign \
		    gendata $< $@ $(SIGN_EXTRA)
else ifeq ($(LE_ACTION),USESIG)
       cmd_sgxsign = $(PWD)/le/enclave/sgxsign \
		    usesig $(PUBLIC_KEY_PATH) $< $(FULL_SIG_FILE) $@ $(SIGN_EXTRA)
endif

targets += sgx_le.ss
$(obj)/sgx_le.ss: $(obj)/sgx_le.bin $(obj)/sgxsign FORCE
	$(call if_changed,sgxsign)

$(SIGNING_MATERIAL): $(obj)/sgx_le.bin $(obj)/sgxsign FORCE
	$(call if_changed,sgxsign)
	
#
# sgx_le.bin
#

targets += sgx_le.bin
OBJCOPYFLAGS_sgx_le.bin := --remove-section=.got.plt -O binary
$(obj)/sgx_le.bin: $(obj)/sgx_le.elf FORCE
	$(call if_changed,objcopy)

#
# sgx_le_blob.h sgx_le_ss.h
#
hostprogs-y += bin2c
quiet_cmd_bin2c = BIN2C   $@
      cmd_bin2c = $(PWD)/le/enclave/bin2c $< $@ $(basename $(notdir $@))

targets += sgx_le_blob.h
$(obj)/sgx_le_blob.h: $(obj)/sgx_le.bin $(obj)/bin2c FORCE
	$(call if_changed,bin2c)
	
targets += sgx_le_ss.h
$(obj)/sgx_le_ss.h: $(obj)/sgx_le.ss $(obj)/bin2c FORCE
	$(call if_changed,bin2c)

#
# sgx_le.elf
#

sgx_le-y +=  main.o encl_bootstrap.o string.o cmac.o 
targets += $(sgx_le-y)
SGX_LE_OBJS = $(addprefix $(obj)/,$(sgx_le-y))

targets += sgx_le.elf
LDFLAGS_sgx_le.elf := -T
$(obj)/sgx_le.elf: $(obj)/sgx_le.lds $(SGX_LE_OBJS)
	$(call if_changed,ld)

clean:
	rm -vrf *.o .*.cmd $(clean-files)

