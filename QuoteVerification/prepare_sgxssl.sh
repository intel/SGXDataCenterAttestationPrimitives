#!/usr/bin/env bash
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

ARG1=${1:-build}
top_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
sgxssl_dir=$top_dir/sgxssl
openssl_out_dir=$sgxssl_dir/openssl_source
openssl_ver_name=openssl-1.1.1t
sgxssl_github_archive=https://github.com/intel/intel-sgx-ssl/archive
sgxssl_file_name=lin_2.19_1.1.1t
build_script=$sgxssl_dir/Linux/build_openssl.sh
server_url_path=https://www.openssl.org/source/
full_openssl_url=$server_url_path/$openssl_ver_name.tar.gz
full_openssl_url_old=$server_url_path/old/1.1.1/$openssl_ver_name.tar.gz

sgxssl_chksum=bff5a9059911846e27447acb402c4690346abf46da8e1c26b66d406e8abb1588
openssl_chksum=8dee9b24bdb1dcbf0c3d1e9b02fb8f6bf22165e807f45adeb7c9677536859d3b
rm -f check_sum_sgxssl.txt check_sum_openssl.txt
if [ ! -f $build_script ]; then
	wget $sgxssl_github_archive/$sgxssl_file_name.zip -P $sgxssl_dir/ || exit 1
	sha256sum $sgxssl_dir/$sgxssl_file_name.zip > $sgxssl_dir/check_sum_sgxssl.txt
	grep $sgxssl_chksum $sgxssl_dir/check_sum_sgxssl.txt
	if [ $? -ne 0 ]; then
    	echo "File $sgxssl_dir/$sgxssl_file_name.zip checksum failure"
      rm -f $sgxssl_dir/$sgxssl_file_name.zip
    	exit -1
	fi
	unzip -qq $sgxssl_dir/$sgxssl_file_name.zip -d $sgxssl_dir/ || exit 1
	mv $sgxssl_dir/intel-sgx-ssl-$sgxssl_file_name/* $sgxssl_dir/ || exit 1
	rm $sgxssl_dir/$sgxssl_file_name.zip || exit 1
	rm -rf $sgxssl_dir/intel-sgx-ssl-$sgxssl_file_name || exit 1
fi
if [[ "$*" == *_TD_MIGRATION* ]];then
	if [ -f $build_script ]; then
		sed -i 's/no-idea/no-idea\ no-threads/' $build_script
	fi
	if [ -f $bypass_fun_header ]; then
		sed -i '/sgxssl_gmtime_r$/a #define\ gmtime\ sgxssl_gmtime' $bypass_fun_header
		sed -i 's/D),\ 0/D),\ 3/' Makefile    #for test project fail sigle thread
		sed -i 's/__thread//' $tls_time_source_file
	fi

	if [ -f $test_makefile ]; then
		sed -i 's/D),\ 0/D),\ 3/' $test_makefile
	fi
fi
if [ ! -f $openssl_out_dir/$openssl_ver_name.tar.gz ]; then
	wget $full_openssl_url_old -P $openssl_out_dir || wget $full_openssl_url -P $openssl_out_dir || exit 1
	sha256sum $openssl_out_dir/$openssl_ver_name.tar.gz > $sgxssl_dir/check_sum_openssl.txt
	grep $openssl_chksum $sgxssl_dir/check_sum_openssl.txt
	if [ $? -ne 0 ]; then
    	echo "File $openssl_out_dir/$openssl_ver_name.tar.gz checksum failure"
        rm -f $openssl_out_dir/$openssl_ver_name.tar.gz
    	exit -1
	fi
fi


if [ "$1" = "nobuild" ]; then
	exit 0
fi

pushd $sgxssl_dir/Linux/
if [[ "$*" == *_TD_MIGRATION* ]];then
make clean sgxssl_no_mitigation NO_THREADS=1 LINUX_SGX_BUILD=2 _TD_MIGRATION=1
else
make clean sgxssl_no_mitigation 
fi
popd


