#
# Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
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


%define _install_path @install_path@

Name:           sgx-ra-service
Version:        @version@
Release:        1%{?dist}
Summary:        Intel(R) Software Guard Extensions Registration Agent Service
Group:          Development/System
Requires:       libsgx-ra-uefi >= %{version}-%{release}, libsgx-ra-network >= %{version}-%{release}

License:        BSD License
URL:            https://github.com/intel/SGXDataCenterAttestationPrimitives
Source0:        %{name}-%{version}.tar.gz

%description
Intel(R) Software Guard Extensions Registration Agent Service

%prep
%setup -qc

%install
make DESTDIR=%{?buildroot} install
echo "%{_install_path}" > %{_specdir}/list-%{name}
find %{?buildroot} | sort | \
awk '$0 !~ last "/" {print last} {last=$0} END {print last}' | \
sed -e "s#^%{?buildroot}##" | \
grep -v "^%{_install_path}" >> %{_specdir}/list-%{name} || :
sed -i 's#^/etc/rad.conf#%config &#' %{_specdir}/list-%{name}

%files -f %{_specdir}/list-%{name}

%debug_package

%post
################################################################################
# Set up SGX Registration Agent                                                #
################################################################################

# Generate the script to setup environment variables
MPA_DST_PATH=%{_install_path}

# Install the MPA service

if [ -d /run/systemd/system ]; then
    MPA_NAME=mpa_registration_tool.service
    MPA_TEMP=$MPA_DST_PATH/$MPA_NAME
    if [ -d /lib/systemd/system ]; then
        MPA_DEST=/lib/systemd/system/$MPA_NAME
    else
        MPA_DEST=/usr/lib/systemd/system/$MPA_NAME
    fi
#    sed -e "s:@mpa_folder@:$MPA_DST_PATH:" \
#        $MPA_TEMP > $MPA_DEST
    chmod 0644 $MPA_DEST
    systemctl enable mpa_registration_tool.service
    #systemctl enable systemd-networkd-wait-online
    retval=$?
elif [ -d /etc/init/ ]; then
    MPA_NAME=mpa_registration_tool.conf
    MPA_TEMP=$MPA_DST_PATH/$MPA_NAME
    MPA_DEST=/etc/init/$MPA_NAME
    sed -e "s:@mpa_folder@:$MPA_DST_PATH:" \
        $MPA_TEMP > $MPA_DEST
    chmod 0644 $MPA_DEST
    /sbin/initctl reload-configuration

    retval=$?
else
    echo "Failed."
    echo "Unsupported platform - neither systemctl nor initctl is no found."
    exit 5
fi

if test $retval -ne 0; then
    echo "failed to install $MPA_NAME."
    exit 6
fi

#Removing config files from temporary location
rm -f $MPA_DST_PATH/mpa_registration_tool.conf
rm -f $MPA_DST_PATH/mpa_registration_tool.service

echo -e "Installation succeed!"

#Run service
systemctl start mpa_registration_tool.service


%postun
# Generate the script to setup environment variables
MPA_DST_PATH=%{_install_path}

# Disable service
if [ -d /run/systemd/system ]; then
    systemctl disable mpa_registration_tool.service
fi

# Removing MPA configuration file
rm -f /etc/init/mpa_registration_tool.conf
rm -f /lib/systemd/system/mpa_registration_tool.service
rm -f /usr/lib/systemd/system/mpa_registration_tool.service
rm -f /etc/systemd/system/mpa_registration_tool.service

# Removing MPA folder
rm -rf $MPA_DST_PATH

#Removing log file
rm -f /var/log/mpa_registration.log

echo -e "Uninstallation succeed!"

%changelog
* Mon Feb 10 2020 SGX Team
- Initial Release
