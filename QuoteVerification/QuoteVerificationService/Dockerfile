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

FROM node:lts-slim AS qvl-builder

ENV DEBIAN_FRONTEND=noninteractive
# install QVL dependencies
RUN apt-get update \
 && apt-get upgrade --assume-yes -o Dpkg::Options::="--force-confold" \
 && apt-get install --assume-yes --no-install-recommends ca-certificates build-essential cmake
# copy QVL sources
COPY build/qvls /qvl
# build and test QVL
RUN cd /qvl && ./runUT -DBUILD_LOGS=ON

FROM node:lts-slim AS qvs-builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get upgrade --assume-yes -o Dpkg::Options::="--force-confold" \
 && apt-get install --assume-yes --no-install-recommends ca-certificates build-essential cmake
 
COPY --from=qvl-builder --chown=node:node /qvl /qvl
# copy QVS source files
COPY src /qvs/src
COPY configuration-default /qvs/configuration-default
# build QVS
RUN echo 'cmake_QVL_PATH=/qvl/Build/Release/dist' >> /qvs/src/.npmrc # workaround for npm 9+ https://github.com/npm/cli/issues/5852
RUN cd /qvs/src && npm install && npm run wait-for-cmake-js && npm run build-native # workaournd for Text file busy race condition https://github.com/nodejs/docker-node/issues/1918
# copy compiled binaries
RUN mkdir -p /qvs/native/lib/ \
 && cp /qvl/Build/Release/dist/lib/*.so /qvs/native/lib/ \
 && cp /qvs/src/qvl/cmake-build-release/Release/*.node /qvs/native/ \
 && rm -rf /qvs/src/qvl/cmake-build-release
# copy QVS test files
COPY test /qvs/test
# test QVS
RUN cd /qvs/test && npm install && NODE_ENV=production npm test

FROM node:lts-slim

LABEL description="Quote Verification Service"

# Remove Node package managers and its dependencies and clear apt cache
RUN rm -rf /usr/local/lib/node_modules/ \
    && rm -rf /usr/local/bin/npm \
    && rm -rf /usr/local/bin/npx \
    && rm -rf /opt \
    && rm -rf /var/cache/apt/archives

# Update the OS and install required dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get upgrade --assume-yes -o Dpkg::Options::="--force-confold" && \
    DEBIAN_FRONTEND=noninteractive apt-get install --assume-yes --no-install-recommends ca-certificates openssl && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Add QVS files from builder
COPY --from=qvs-builder --chown=node:node qvs/native /QVS/native
COPY --from=qvs-builder --chown=node:node qvs/configuration-default/config.yml /QVS/configuration-default/config.yml
COPY --from=qvs-builder --chown=node:node qvs/src /QVS/src

ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/QVS/native/lib \
    NODE_ENV=production
USER node
ENTRYPOINT ["nodejs", "/QVS/src/bootstrap.js"]

