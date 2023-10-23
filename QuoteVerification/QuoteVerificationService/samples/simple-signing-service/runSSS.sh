#!/bin/bash

#
# Copyright (c) 2023, Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#  * Neither the name of Intel Corporation nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Get absolute path to the script itself
SSS_DIR="$(cd "$(dirname "$0")" || exit 1; pwd)"
QVS_CERT_DIR="${SSS_DIR}/../../configuration-default/certificates"

source ${SSS_DIR}/../../configUtils.sh
echo 'Starting SSS...'
docker run --name vcs-sss -p 8797:8797 -p 8796:8796 -v ${SSS_DIR}/certificates:/SSS/certificates --rm sss &

echo 'Veryfying SSS HTTP endpoint...'
waitForHttpServiceToStart 8796
echo 'Veryfying SSS MTLS endpoint...'
retryHealthCheack "curl --cacert ${QVS_CERT_DIR}/internal_ca/sss-mtls-cert.pem --key ${QVS_CERT_DIR}/qvs-to-sss-client-key.pem --cert ${QVS_CERT_DIR}/qvs-to-sss-client-cert.pem  https://localhost:8797/health"

