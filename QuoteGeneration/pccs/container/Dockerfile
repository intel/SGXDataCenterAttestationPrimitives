# Use multi-stage builds to reduce final image size
FROM ubuntu:23.04 AS builder

# Define arguments used across multiple stages
ARG DCAP_VERSION=DCAP_1.20
ARG NODE_MAJOR=20
ARG NODE_MINOR=11
ARG NODE_PATCH=1
ARG NODE_REVISION=1nodesource1

# update and install packages, nodejs
RUN DEBIAN_FRONTEND=noninteractive \
    apt-get update -yq \
    && apt-get upgrade -yq \
    && apt-get install -yq --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        gnupg \
        git \
        zip \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /usr/share/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list \
    && apt-get update -yq \
    && apt-get install -yq --no-install-recommends nodejs=${NODE_MAJOR}.${NODE_MINOR}.${NODE_PATCH}-${NODE_REVISION} \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Clone the specific branch or tag 
RUN git clone --recurse-submodules https://github.com/intel/SGXDataCenterAttestationPrimitives.git # -b ${DCAP_VERSION} --depth 1

# Build libPCKCertSelection library
WORKDIR /SGXDataCenterAttestationPrimitives/tools/PCKCertSelection/
RUN make \
    && mkdir -p ../../QuoteGeneration/pccs/lib \
    && cp ./out/libPCKCertSelection.so ../../QuoteGeneration/pccs/lib/ \
    && make clean

# Build PCCS
WORKDIR /SGXDataCenterAttestationPrimitives/QuoteGeneration/pccs/
RUN npm config set proxy $http_proxy \
    && npm config set https-proxy $https_proxy \
    && npm config set engine-strict true \
    && npm install

# Start final image build
FROM ubuntu:23.04

# Create user and group before copying files
ARG USER=pccs
RUN useradd -M -U -r ${USER} -s /bin/false

# Copy only necessary files from builder stage
COPY --from=builder /usr/bin/node /usr/bin/node
COPY --from=builder --chown=${USER}:${USER} /SGXDataCenterAttestationPrimitives/QuoteGeneration/pccs/ /opt/intel/pccs/

# Set the working directory and switch user
WORKDIR /opt/intel/pccs/
USER ${USER}

# Define entrypoint
ENTRYPOINT ["/usr/bin/node", "pccs_server.js"]

