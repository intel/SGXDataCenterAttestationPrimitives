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

function fail {
    printf '%s\n' "$1" >&2 ## Send message to stderr.
    exit "${2-1}" ## Return a code specified by $2, or 1 by default.
}

# Waits until command passes for specified amount of time.
# Arg1: Command, default is: curl http://localhost:8797/health
# Arg2: Timeout (in seconds) - amount of retries
retryHealthCheack() {
    DEFAULT_RETRIES_COUNT=10
    command=${1:-'curl http://localhost:8797/health'}
    retriesLeft=${2:-$DEFAULT_RETRIES_COUNT}
    echo Waiting $retriesLeft seconds for service to start...
    while [[ $retriesLeft -gt 0 ]]
    do
        ((retriesLeft--))
        sleep 1
        result=$(${command})
        retCode=$?
        status=$(echo ${result} | jq .status)
        if [ ${retCode} != 0 ]; then
            echo Unable to fetch HealthCheck, return status: ${retCode}
        elif [ ${status} == '"OK"' ]; then
            echo "HealthCheck OK!"
            break
        elif [ ${status} == '"UNKNOWN"' ]; then
            echo "HealthCheck Failed (UNKNOWN)!"
        elif [ ${status} == '"FAILED"' ]; then
            echo "HealthCheck Failed!"
        else
            echo "HealthCheck Failed, unable to parse! ${result}"
        fi 
    done
}

# Waits until service http healthcheck passes on given port for 10 seconds.
# Arg1: Service port
waitForHttpServiceToStart() {
    retryHealthCheack "curl http://localhost:${1}/health"
}

# Waits until service https healthcheck passes on given port for 10 seconds.
# Arg1: Service port
waitForHttpsServiceToStart() {
    retryHealthCheack "curl -k https://localhost:${1}/health"
}

# Assures that specified certificate exists in ./certificates
# If no, new certificate is created.
# Arg1: Name
# Arg2: Subject
function prepareSelfSignedCert() {
  if [ ! -f "${1}cert.pem" ]; then
      generateSelfSignedCert "${1}" "${2}"
  fi
}

# Generates self-signed certificate
# Arg1: Name
# Arg2: Subject
function generateSelfSignedCert() {
  openssl genrsa -out ${1}key.pem 3072
  openssl req -subj "${2}" -new -key ${1}key.pem -out csr.pem
  openssl x509 -req -days 365 -in csr.pem -signkey  ${1}key.pem -out ${1}cert.pem
  chmod +r ${1}key.pem
  rm csr.pem
}

# Imports QVS MTLS certificate to SSS ./certificates
# Arg1: Name
# Arg2: CA location
function ImportCertificate() {
  if [ -f ${1} ]; then
      cp ${1} ${2}
  else
      echo "[ERROR] Unable to fetch ${1} certificate! Follow QVS instructions to generate one."
      exit 1
  fi
}

