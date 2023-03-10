#!/bin/bash

#
# Copyright (c) 2022, Intel Corporation
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

# Get absolute path to the script itself
SCRIPT_DIR="$(cd "$(dirname "$0")" || exit 1; pwd)"

# Check if QVL path has been provided
if [ -z "$1" ]
  then
    QVL_PATH="$(cd "$(dirname "$SCRIPT_DIR"/../QVL/Src)" || exit 2; pwd)/Src"
else
  QVL_PATH="$(cd "$(dirname "$1")" || exit 2; pwd)/$(basename "$1")"
fi

echo "QVL_PATH=$QVL_PATH"
cd "$QVL_PATH" || fail "Failed to access QVL path" 2

# Check if QVL_PATH contains absolute path
case $QVL_PATH in
     /*) ;;
     *) fail "Absolute path to QVL sources should be provided" 3 ;;
esac

# Build QVL
buildQvl() {
  (cd "$QVL_PATH" && ./runUT)
}

if ! buildQvl "$@"; then
    fail "Error when building QVL" 4
fi

# Build QVS
buildQvs() {
  (cd "$SCRIPT_DIR/src" && npm config set cmake_QVL_PATH="$QVL_PATH/Build/Release/dist" && npm install)
}

if ! buildQvs "$@"; then
    fail "Error when building QVS" 5
fi

# Copy built native libs
copyNativeLibs() {
  mkdir -p "$SCRIPT_DIR"/native/lib &&
  cp "$QVL_PATH"/Build/Release/dist/lib/*.so "$SCRIPT_DIR"/native/lib/ &&
  cp "$SCRIPT_DIR"/src/qvl/cmake-build-release/Release/*.node "$SCRIPT_DIR"/native/
}

if ! copyNativeLibs "$@"; then
    fail "Error when copying native files" 6
fi

# Build Docker Image
function buildDocker() {
  docker build "$SCRIPT_DIR" -t qvs
}

if ! buildDocker; then
    fail "Error when building Docker image" 7
fi

echo "Build - Done"
