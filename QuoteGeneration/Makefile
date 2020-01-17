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

CUR_MKFILE:= $(lastword $(MAKEFILE_LIST))

.PHONY: all pkg dcap opt_check_failed clean rebuild sdk sample pce_wrapper quote_wrapper qcnl_wrapper qpl_wrapper qve_wrapper

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

dcap: $(CHECK_OPT) pce_wrapper quote_wrapper qcnl_wrapper qpl_wrapper qve_wrapper sample

opt_check_failed:
	@echo "ERROR: Please decompress prebuilt enclave package before compiling."
	@echo "Exiting......"
	@exit -2

pce_wrapper: 
	$(MAKE) -C pce_wrapper/linux

quote_wrapper: pce_wrapper 
	$(MAKE) -C quote_wrapper/ql/linux

qcnl_wrapper:
	$(MAKE) -C qcnl/linux

qpl_wrapper: qcnl_wrapper
	$(MAKE) -C qpl/linux

qve_wrapper:
	$(MAKE) -C ../QuoteVerification

sample: quote_wrapper
	cd ../SampleCode && zip -r sample.zip ./

.PHONY: deb_sgx_dcap_ql_pkg
deb_sgx_dcap_ql_pkg: $(CHECK_OPT) pce_wrapper quote_wrapper qve_wrapper
	./installer/linux/deb/libsgx-dcap-ql/build.sh

.PHONY: deb_sgx_dcap_default_qpl_pkg
deb_sgx_dcap_default_qpl_pkg: qcnl_wrapper qpl_wrapper
	./installer/linux/deb/libsgx-dcap-default-qpl/build.sh

.PHONY: deb_sgx_dcap_pccs_pkg
deb_sgx_dcap_pccs_pkg:
	$(MAKE) -C ../tools/PCKCertSelection/
	mkdir -p pccs/lib/
	cp ../tools/PCKCertSelection/out/libPCKCertSelection.so pccs/lib/
	./installer/linux/deb/sgx-dcap-pccs/build.sh

.PHONY: deb_sgx_ae_qe3_pkg
deb_sgx_ae_qe3_pkg: $(CHECK_OPT)
	./installer/linux/deb/libsgx-ae-qe3/build.sh

.PHONY: deb_sgx_ae_qve_pkg
deb_sgx_ae_qve_pkg: $(CHECK_OPT)
	./installer/linux/deb/libsgx-ae-qve/build.sh

.PHONY: deb_pkg
deb_pkg: deb_sgx_dcap_ql_pkg deb_sgx_dcap_default_qpl_pkg deb_sgx_dcap_pccs_pkg deb_sgx_ae_qe3_pkg deb_sgx_ae_qve_pkg
	@$(RM) -f ./installer/linux/deb/*.deb ./installer/linux/deb/*.ddeb
	cp `find ./installer/linux/deb/ -name "*.deb" -o -name "*.ddeb"` ./installer/linux/deb/

.PHONY: rpm_sgx_ae_qe3_pkg
rpm_sgx_ae_qe3_pkg: $(CHECK_OPT)
	./installer/linux/rpm/libsgx-ae-qe3/build.sh

.PHONY: rpm_sgx_ae_qve_pkg
rpm_sgx_ae_qve_pkg: $(CHECK_OPT)
	./installer/linux/rpm/libsgx-ae-qve/build.sh

.PHONY: rpm_pkg
rpm_pkg: rpm_sgx_ae_qe3_pkg rpm_sgx_ae_qve_pkg
	@$(RM) -f ./installer/linux/rpm/*.rpm
	cp `find ./installer/linux/rpm/ -name "*.rpm"` ./installer/linux/rpm/

clean:
	$(MAKE) -C pce_wrapper/linux clean
	$(MAKE) -C quote_wrapper/ql/linux clean
	$(MAKE) -C qcnl/linux clean
	$(MAKE) -C qpl/linux clean
	$(MAKE) -C ../QuoteVerification clean
	@$(RM) -rf ../SampleCode/sample.zip
	@$(RM) -rf linux_dcap_interface.zip
	@$(RM) -rf ./build/
	@$(RM) -f ./installer/linux/deb/*.deb
	@$(RM) -f ./installer/linux/deb/*.ddeb
	@$(RM) -f ./installer/linux/rpm/*.rpm
	./installer/linux/deb/libsgx-dcap-ql/clean.sh
	./installer/linux/deb/libsgx-ae-qe3/clean.sh
	./installer/linux/deb/libsgx-ae-qve/clean.sh
	./installer/linux/deb/libsgx-dcap-default-qpl/clean.sh
	./installer/linux/deb/sgx-dcap-pccs/clean.sh
	./installer/linux/rpm/libsgx-ae-qe3/clean.sh
	./installer/linux/rpm/libsgx-ae-qve/clean.sh


rebuild:
	$(MAKE) -f $(CUR_MKFILE) clean
	$(MAKE) -f $(CUR_MKFILE) pkg
