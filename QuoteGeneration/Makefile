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

CUR_MKFILE:= $(lastword $(MAKEFILE_LIST))

.PHONY: all dcap opt_check_failed clean rebuild pce_logic qe3_logic qcnl_wrapper qpl_wrapper qve_wrapper

all: dcap

# DCAP requires prebuilt enclaves.
CHECK_OPT :=
ifeq ("$(wildcard psw/ae/data/prebuilt)", "")
CHECK_OPT := opt_check_failed
endif

dcap: $(CHECK_OPT) pce_logic qe3_logic qcnl_wrapper qpl_wrapper qve_wrapper

opt_check_failed:
	@echo "Please run download_prebuilt.sh before compiling"
	@echo "Exiting......"
	@exit -2

pce_logic:
	$(MAKE) -C pce_wrapper/linux

qe3_logic: pce_logic
	$(MAKE) -C quote_wrapper/ql/linux

qcnl_wrapper:
	$(MAKE) -C qcnl/linux

qpl_wrapper: qcnl_wrapper
	$(MAKE) -C qpl/linux

qve_wrapper:
	$(MAKE) -C ../QuoteVerification


.PHONY: deb_sgx_dcap_ql_pkg
deb_sgx_dcap_ql_pkg: $(CHECK_OPT) pce_logic qe3_logic qve_wrapper
	./installer/linux/deb/libsgx-dcap-ql/build.sh

.PHONY: deb_sgx_dcap_quote_verify_pkg
deb_sgx_dcap_quote_verify_pkg: $(CHECK_OPT) qve_wrapper
	./installer/linux/deb/libsgx-dcap-quote-verify/build.sh

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

.PHONY: deb_sgx_ae_qve_pkg qve_wrapper
deb_sgx_ae_qve_pkg: $(CHECK_OPT)
	./installer/linux/deb/libsgx-ae-qve/build.sh

.PHONY: deb_sgx_qe3_logic_pkg
deb_sgx_qe3_logic_pkg: qe3_logic
	./installer/linux/deb/libsgx-qe3-logic/build.sh

.PHONY: deb_sgx_pce_logic_pkg
deb_sgx_pce_logic_pkg: pce_logic
	./installer/linux/deb/libsgx-pce-logic/build.sh

.PHONY: deb_sgx_pck_id_retrieval_tool_pkg
deb_sgx_pck_id_retrieval_tool_pkg:
	$(MAKE) -C ../tools/PCKRetrievalTool/
	../tools/PCKRetrievalTool/installer/deb/sgx-pck-id-retrieval-tool/build.sh

.PHONY: deb_sgx_ra_service_pkg
deb_sgx_ra_service_pkg:
	$(MAKE) -C ../tools/SGXPlatformRegistration/ deb_pkg


.PHONY: deb_pkg
deb_pkg: deb_sgx_pce_logic_pkg deb_sgx_qe3_logic_pkg deb_sgx_dcap_ql_pkg deb_sgx_dcap_quote_verify_pkg deb_sgx_dcap_default_qpl_pkg deb_sgx_dcap_pccs_pkg deb_sgx_ae_qe3_pkg deb_sgx_ae_qve_pkg deb_sgx_pck_id_retrieval_tool_pkg deb_sgx_ra_service_pkg
	@$(RM) -f ./installer/linux/deb/*.deb ./installer/linux/deb/*.ddeb
	cp `find ./installer/linux/deb/ -name "*.deb" -o -name "*.ddeb"` ./installer/linux/deb/
	cp `find ../tools/PCKRetrievalTool/installer/deb/ -name "*.deb" -o -name "*.ddeb"` ./installer/linux/deb/
	cp `find ../tools/SGXPlatformRegistration/build/installer/ -name "*.deb" -o -name "*.ddeb"` ./installer/linux/deb/

.PHONY: rpm_sgx_dcap_ql_pkg
rpm_sgx_dcap_ql_pkg: $(CHECK_OPT) pce_logic qe3_logic qve_wrapper
	./installer/linux/rpm/libsgx-dcap-ql/build.sh

.PHONY: rpm_sgx_dcap_default_qpl_pkg
rpm_sgx_dcap_default_qpl_pkg: qcnl_wrapper qpl_wrapper
	./installer/linux/rpm/libsgx-dcap-default-qpl/build.sh

.PHONY: rpm_sgx_dcap_pccs_pkg
rpm_sgx_dcap_pccs_pkg:
	$(MAKE) -C ../tools/PCKCertSelection/
	mkdir -p pccs/lib/
	cp ../tools/PCKCertSelection/out/libPCKCertSelection.so pccs/lib/
	./installer/linux/rpm/sgx-dcap-pccs/build.sh

.PHONY: rpm_sgx_ae_qe3_pkg
rpm_sgx_ae_qe3_pkg: $(CHECK_OPT)
	./installer/linux/rpm/libsgx-ae-qe3/build.sh

.PHONY: rpm_sgx_ae_qve_pkg
rpm_sgx_ae_qve_pkg: $(CHECK_OPT) qve_wrapper
	./installer/linux/rpm/libsgx-ae-qve/build.sh

.PHONY: rpm_sgx_dcap_quote_verify_pkg
rpm_sgx_dcap_quote_verify_pkg: $(CHECK_OPT) qve_wrapper
	./installer/linux/rpm/libsgx-dcap-quote-verify/build.sh

.PHONY: rpm_sgx_qe3_logic_pkg
rpm_sgx_qe3_logic_pkg: qe3_logic
	./installer/linux/rpm/libsgx-qe3-logic/build.sh

.PHONY: rpm_sgx_pce_logic_pkg
rpm_sgx_pce_logic_pkg: pce_logic
	./installer/linux/rpm/libsgx-pce-logic/build.sh

.PHONY: rpm_sgx_pck_id_retrieval_tool_pkg
rpm_sgx_pck_id_retrieval_tool_pkg:
	$(MAKE) -C ../tools/PCKRetrievalTool/
	../tools/PCKRetrievalTool/installer/rpm/sgx-pck-id-retrieval-tool/build.sh

.PHONY: rpm_sgx_ra_service_pkg
rpm_sgx_ra_service_pkg:
	$(MAKE) -C ../tools/SGXPlatformRegistration/ rpm_pkg

.PHONY: rpm_pkg
rpm_pkg: rpm_sgx_dcap_ql_pkg rpm_sgx_dcap_default_qpl_pkg rpm_sgx_dcap_pccs_pkg rpm_sgx_ae_qe3_pkg rpm_sgx_ae_qve_pkg rpm_sgx_dcap_quote_verify_pkg rpm_sgx_pce_logic_pkg rpm_sgx_qe3_logic_pkg rpm_sgx_pck_id_retrieval_tool_pkg rpm_sgx_ra_service_pkg
	@$(RM) -f ./installer/linux/rpm/*.rpm
	cp `find ./installer/linux/rpm/ -name "*.rpm"` ./installer/linux/rpm/
	cp `find ../tools/PCKRetrievalTool/installer/rpm/ -name "*.rpm"` ./installer/linux/rpm/
	cp `find ../tools/SGXPlatformRegistration/build/installer/ -name "*.rpm"`  ./installer/linux/rpm/

clean:
	$(MAKE) -C pce_wrapper/linux clean
	$(MAKE) -C quote_wrapper/ql/linux clean
	$(MAKE) -C qcnl/linux clean
	$(MAKE) -C qpl/linux clean
	$(MAKE) -C ../QuoteVerification clean
	$(MAKE) -C ../tools/PCKRetrievalTool clean
	$(MAKE) -C ../tools/SGXPlatformRegistration clean
	@$(RM) -rf ./build/
	@$(RM) -f ./installer/linux/deb/*.deb
	@$(RM) -f ./installer/linux/deb/*.ddeb
	@$(RM) -f ./installer/linux/rpm/*.rpm
	./installer/linux/deb/libsgx-dcap-ql/clean.sh
	./installer/linux/deb/libsgx-dcap-quote-verify/clean.sh
	./installer/linux/deb/libsgx-ae-qe3/clean.sh
	./installer/linux/deb/libsgx-ae-qve/clean.sh
	./installer/linux/deb/libsgx-pce-logic/clean.sh
	./installer/linux/deb/libsgx-qe3-logic/clean.sh
	./installer/linux/deb/libsgx-dcap-default-qpl/clean.sh
	./installer/linux/deb/sgx-dcap-pccs/clean.sh
	../tools/PCKRetrievalTool/installer/deb/sgx-pck-id-retrieval-tool/clean.sh
	./installer/linux/rpm/libsgx-dcap-ql/clean.sh
	./installer/linux/rpm/libsgx-ae-qe3/clean.sh
	./installer/linux/rpm/libsgx-ae-qve/clean.sh
	./installer/linux/rpm/libsgx-dcap-quote-verify/clean.sh
	./installer/linux/rpm/libsgx-pce-logic/clean.sh
	./installer/linux/rpm/libsgx-qe3-logic/clean.sh
	./installer/linux/rpm/libsgx-dcap-default-qpl/clean.sh
	./installer/linux/rpm/sgx-dcap-pccs/clean.sh
	../tools/PCKRetrievalTool/installer/rpm/sgx-pck-id-retrieval-tool/clean.sh

rebuild:
	$(MAKE) -f $(CUR_MKFILE) clean
	$(MAKE) -f $(CUR_MKFILE)
