# SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
# Copyright(c) 2016-19 Intel Corporation.

ifneq ($(KERNELRELEASE),)

obj-m += intel_sgx.o
intel_sgx-y := encl.o main.o reclaim.o driver.o ioctl.o

else

KDIR := /lib/modules/$(shell uname -r)/build

INKERNEL_SGX :=$(shell cat $(KDIR)/.config | grep "CONFIG_INTEL_SGX=y")
ifneq ($(INKERNEL_SGX),)
default:
	$(error Can't install DCAP SGX driver with inkernel SGX support)

else

PWD  := $(shell pwd)
default:
	$(MAKE) -C $(KDIR) M=$(PWD) CFLAGS_MODULE="-I$(PWD) -I$(PWD)/include" modules

endif
endif

clean:
	rm -vrf *.o *.ko *.order *.symvers *.mod.c .tmp_versions .*.cmd *.o.ur-safe *.mod
