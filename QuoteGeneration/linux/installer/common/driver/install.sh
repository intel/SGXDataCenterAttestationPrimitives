#!/usr/bin/env bash
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


set -e 

SCRIPT_DIR=$(dirname "$0")
source ${SCRIPT_DIR}/installConfig

DRIVER_DST_PATH=${SGX_PACKAGES_PATH}/${DRIVER_PKG_NAME}
DRIVER_SOURCE_PATH="${DRIVER_DST_PATH}/package"

pushd ${DRIVER_SOURCE_PATH}

PACKAGE_NAME=`grep PACKAGE_NAME dkms.conf | cut -d= -f2 | sed -e 's/^"//' -e 's/"$//'`
PACKAGE_VERSION=`grep PACKAGE_VERSION dkms.conf | cut -d= -f2 | sed -e 's/^"//' -e 's/"$//'`
PACKAGE_PATH="/usr/src/${PACKAGE_NAME}-${PACKAGE_VERSION}"

trap "rm -fr $DRIVER_DST_PATH 2>/dev/null; rm -fr $PACKAGE_PATH 2>/dev/null; /bin/sed -i '/^intel_sgx$/d' /etc/modules; exit 3" HUP INT QUIT TERM EXIT

rm -fr ${PACKAGE_PATH}
mkdir -p ${PACKAGE_PATH}
cp -r * ${PACKAGE_PATH}/

/usr/sbin/dkms build ${PACKAGE_NAME}/${PACKAGE_VERSION}
/usr/sbin/dkms install ${PACKAGE_NAME}/${PACKAGE_VERSION} --force

# Automatically load the driver on startup
cat /etc/modules | grep -Fxq intel_sgx || echo intel_sgx >> /etc/modules
echo 'SUBSYSTEM=="sgx",KERNEL=="sgx",RUN+="/bin/chmod 666 /dev/$name"' | sudo tee /etc/udev/rules.d/10-sgx.rules

#RHEL auto load
if [ ! -d "/etc/sysconfig" ]; then
    mkdir /etc/sysconfig
fi

if [ ! -d "/etc/sysconfig/modules" ]; then
    mkdir /etc/sysconfig/modules
fi

if [ ! -f "/etc/sysconfig/modules/intel_sgx.modules" ]; then
    echo modprobe intel_sgx >> /etc/sysconfig/modules/intel_sgx.modules
    chmod +x /etc/sysconfig/modules/intel_sgx.modules
fi

#SUSE auto load
if [ ! -d "/etc/modules-load.d" ]; then
    mkdir -p /etc/modules-load.d
fi

if [ ! -f "/etc/modules-load.d/intel_sgx.conf" ]; then
    echo intel_sgx >> /etc/modules-load.d/intel_sgx.conf
fi

# Insert the driver
/sbin/modprobe intel_sgx

popd &> /dev/null

cat > $DRIVER_DST_PATH/uninstall.sh <<EOF
#!/usr/bin/env bash
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


if test \$(id -u) -ne 0; then
    echo "Root privilege is required."
    exit 1
fi

# Do no uninstall if the AESM service exists
/usr/sbin/service aesmd reload &> /dev/null
if [[ \$? == "0" ]]; then
  echo -e "Uninstall failed!"
  echo -e "\nPlease uninstall the PSW package first"
  exit 1
fi

# Removing the kernel module if it is inserted
/sbin/modinfo intel_sgx &> /dev/null && /sbin/modprobe -r intel_sgx
if [[ \$? != "0" ]]; then
  echo -e "\nUninstall failed because the kernel module is in use"
  exit 1
fi

/usr/sbin/dkms remove ${PACKAGE_NAME}/${PACKAGE_VERSION} --all

rm -fr ${PACKAGE_PATH}

rm -f /etc/udev/rules.d/10-sgx.rules

# Removing from /etc/modules
/bin/sed -i '/^intel_sgx$/d' /etc/modules

# Removing the current folder
rm -fr $DRIVER_DST_PATH

if [ -f "/etc/sysconfig/modules/intel_sgx.modules" ]; then
    rm -f /etc/sysconfig/modules/intel_sgx.modules
fi

if [ -f "/etc/modules-load.d/intel_sgx.conf" ]; then
    rm -f /etc/modules-load.d/intel_sgx.conf
fi
EOF

chmod +x $DRIVER_DST_PATH/uninstall.sh

rm -fr $DRIVER_DST_PATH/package
rm -fr $DRIVER_DST_PATH/scripts

echo -e "\nuninstall.sh script generated in $DRIVER_DST_PATH\n"
echo -e "Installation is successful!"

trap - EXIT
exit 0

