#!/usr/bin/env bash
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

top_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
sgxssl_dir=$top_dir/sgxssl/
openssl_out_dir=$sgxssl_dir/openssl_source
openssl_ver_name=openssl-1.1.1d
sgxssl_github_archive=https://github.com/01org/intel-sgx-ssl/archive
sgxssl_ver_name=lin_2.5_1.1.1d
sgxssl_ver=lin_2.5_1.1.1d
build_script=$sgxssl_dir/Linux/build_openssl.sh
server_url_path=https://www.openssl.org/source/
full_openssl_url=$server_url_path/$openssl_ver_name.tar.gz
full_openssl_url_old=$server_url_path/old/1.1.1/$openssl_ver_name.tar.gz

sgxssl_chksum=abadc61c92c0488027dcb0a3681c6be0316c931461e887a728f64d3178149098
openssl_chksum=1e3a91bc1f9dfce01af26026f856e064eab4c8ee0a8f457b5ae30b40b8b711f2
rm -f check_sum_sgxssl.txt check_sum_openssl.txt
if [ ! -f $build_script ]; then
	wget $sgxssl_github_archive/$sgxssl_ver_name.zip -P $sgxssl_dir/ || exit 1
	sha256sum $sgxssl_dir/$sgxssl_ver_name.zip > $sgxssl_dir/check_sum_sgxssl.txt
	grep $sgxssl_chksum $sgxssl_dir/check_sum_sgxssl.txt
	if [ $? -ne 0 ]; then 
    	echo "File $sgxssl_dir/$sgxssl_ver_name.zip checksum failure"
        rm -f $sgxssl_dir/$sgxssl_ver_name.zip
    	exit -1
	fi
	unzip -qq $sgxssl_dir/$sgxssl_ver_name.zip -d $sgxssl_dir/ || exit 1
	mv $sgxssl_dir/intel-sgx-ssl-$sgxssl_ver/* $sgxssl_dir/ || exit 1
	rm $sgxssl_dir/$sgxssl_ver_name.zip || exit 1
	rm -rf $sgxssl_dir/intel-sgx-ssl-$sgxssl_ver || exit 1
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

pushd $sgxssl_dir/Linux/
make clean all
make clean all DEBUG=1
popd
