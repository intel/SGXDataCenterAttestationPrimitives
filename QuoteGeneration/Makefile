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

CUR_MKFILE:= $(lastword $(MAKEFILE_LIST))

.PHONY: all pkg dcap opt_check_failed clean rebuild sdk sample pce_wrapper quote_wrapper

all: pkg deb_pkg

pkg: dcap
	zip -j linux_dcap_interface.zip                       \
	README.txt                                            \
	$(SGX_SDK)/include/sgx_attributes.h                   \
	$(SGX_SDK)/include/sgx_defs.h                         \
	$(SGX_SDK)/include/sgx_error.h                        \
	$(SGX_SDK)/include/sgx_key.h                          \
	$(SGX_SDK)/include/sgx_report.h                       \
	pce_wrapper/inc/sgx_pce.h                             \
	quote_wrapper/ql/inc/sgx_dcap_ql_wrapper.h            \
	quote_wrapper/common/inc/sgx_ql_lib_common.h          \
	build/linux/libsgx_pce_wrapper.so                     \
	build/linux/libsgx_dcap_ql.so                         \
	psw/ae/data/prebuilt/libsgx_qe3.signed.so             \
	psw/ae/data/prebuilt/libsgx_pce.signed.so             \
	../SampleCode/sample.zip

# DCAP requires prebuilt enclaves.
CHECK_OPT :=
ifeq ("$(wildcard psw/ae/data/prebuilt)", "")
CHECK_OPT := opt_check_failed
endif

dcap: $(CHECK_OPT) pce_wrapper quote_wrapper sample

opt_check_failed:
	@echo "ERROR: Please decompress prebuilt enclave package before compiling."
	@echo "Exiting......"
	@exit -2

pce_wrapper: 
	$(MAKE) -C pce_wrapper/linux

quote_wrapper: pce_wrapper 
	$(MAKE) -C quote_wrapper/ql/linux

sample: quote_wrapper
	cd ../SampleCode && zip -r sample.zip ./

deb_sgx_dcap_ql_pkg: $(CHECK_OPT) pce_wrapper quote_wrapper
	./installer/linux/deb/libsgx-dcap-ql/build.sh

deb_sgx_dcap_ql_dbg_pkg: $(CHECK_OPT) pce_wrapper quote_wrapper
ifndef DEBUG
	./installer/linux/deb/libsgx-dcap-ql-dbg/build.sh
endif

deb_sgx_dcap_ql_dev_pkg:
	./installer/linux/deb/libsgx-dcap-ql-dev/build.sh

deb_pkg: deb_sgx_dcap_ql_pkg deb_sgx_dcap_ql_dbg_pkg deb_sgx_dcap_ql_dev_pkg
	@$(RM) -f ./installer/linux/deb/*.deb
	cp `find ./installer/linux/deb/ -name "*.deb"` ./installer/linux/deb/

clean:
	$(MAKE) -C pce_wrapper/linux clean
	$(MAKE) -C quote_wrapper/ql/linux clean
	@$(RM) -rf ../SampleCode/sample.zip
	@$(RM) -rf linux_dcap_interface.zip
	@$(RM) -rf ./build/
	@$(RM) -f ./installer/linux/deb/*.deb
	@$(RM) -f ./installer/linux/deb/libsgx-dcap-ql/libsgx-dcap-ql-dbgsym_*
	@$(RM) -f ./installer/linux/deb/libsgx-dcap-ql/libsgx-dcap-ql_*_amd64.*
	@$(RM) -f ./installer/linux/deb/libsgx-dcap-ql/libsgx-dcap-ql_*.tar.*
	@$(RM) -f ./installer/linux/deb/libsgx-dcap-ql/libsgx-dcap-ql_*.dsc
	@$(RM) -f ./installer/linux/deb/libsgx-dcap-ql-dev/libsgx-dcap-ql-dev_*.deb
	@$(RM) -f ./installer/linux/deb/libsgx-dcap-ql-dev/libsgx-dcap-ql_*_amd64.*
	@$(RM) -f ./installer/linux/deb/libsgx-dcap-ql-dev/libsgx-dcap-ql_*.tar.*
	@$(RM) -f ./installer/linux/deb/libsgx-dcap-ql-dev/libsgx-dcap-ql_*.dsc
	@$(RM) -f ./installer/linux/deb/libsgx-dcap-ql-dbg/libsgx-dcap-ql-dbg_*.deb
	@$(RM) -f ./installer/linux/deb/libsgx-dcap-ql-dbg/libsgx-dcap-ql_*_amd64.*
	@$(RM) -f ./installer/linux/deb/libsgx-dcap-ql-dbg/libsgx-dcap-ql_*.tar.*
	@$(RM) -f ./installer/linux/deb/libsgx-dcap-ql-dbg/libsgx-dcap-ql_*.dsc
	@$(RM) -f  ./installer/linux/common/libsgx-dcap-ql/gen_source.py
	@$(RM) -rf ./installer/linux/common/libsgx-dcap-ql/output
	@$(RM) -f  ./installer/linux/common/libsgx-dcap-ql-dev/gen_source.py
	@$(RM) -rf ./installer/linux/common/libsgx-dcap-ql-dev/output
	@$(RM) -f  ./installer/linux/common/libsgx-dcap-ql-dbg/gen_source.py
	@$(RM) -rf ./installer/linux/common/libsgx-dcap-ql-dbg/output


rebuild:
	$(MAKE) -f $(CUR_MKFILE) clean
	$(MAKE) -f $(CUR_MKFILE) pkg
