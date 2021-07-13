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
%define _license_file COPYING

Name:           sgx-dcap-pccs
Version:        @version@
Release:        1%{?dist}
Summary:        Intel(R) Software Guard Extensions PCK Caching Service
Group:          Applications/Internet
Requires:       gcc gcc-c++ make

License:        BSD License
URL:            https://github.com/intel/SGXDataCenterAttestationPrimitives
Source0:        %{name}-%{version}.tar.gz

%description
Intel(R) Software Guard Extensions PCK Caching Service

%prep
%setup -qc

%install
make DESTDIR=%{?buildroot} install
install -d %{?buildroot}%{_docdir}/%{name}
find %{?_sourcedir}/package/licenses/ -type f -print0 | xargs -0 -n1 cat >> %{?buildroot}%{_docdir}/%{name}/%{_license_file}
echo "%{_install_path}" > %{_specdir}/listfiles
echo %{_docdir}/%{name}/%{_license_file} >> %{_specdir}/listfiles
echo "%config %{_install_path}/config/default.json" >> %{_specdir}/listfiles

%files -f %{_specdir}/listfiles

%post
PCCS_USER=pccs
PCCS_HOME=%{_install_path}
if [ ! $(getent group $PCCS_USER) ]; then
    groupadd $PCCS_USER
fi
if ! id "$PCCS_USER" &>/dev/null; then
    adduser --system $PCCS_USER -g $PCCS_USER --home $PCCS_HOME --no-create-home --shell /bin/bash
fi
chown -R $PCCS_USER:$PCCS_USER $PCCS_HOME
chmod 640 $PCCS_HOME/config/default.json
#Install PCCS as system service
echo -n "Installing PCCS service ..."
if [ -d /run/systemd/system ]; then
    PCCS_NAME=pccs.service
    PCCS_TEMP=$PCCS_HOME/$PCCS_NAME
    if [ -d /lib/systemd/system ]; then
        PCCS_DEST=/lib/systemd/system/$PCCS_NAME
    else
        PCCS_DEST=/usr/lib/systemd/system/$PCCS_NAME
    fi
    cp $PCCS_TEMP $PCCS_DEST
    chmod 0644 $PCCS_DEST
    systemctl daemon-reload
    systemctl enable pccs
elif [ -d /etc/init/ ]; then
    PCCS_NAME=pccs.service
    PCCS_TEMP=$PCCS_HOME/$PCCS_NAME
    PCCS_DEST=/etc/init/$PCCS_NAME
    cp $PCCS_TEMP $PCCS_DEST
    chmod 0644 $PCCS_DEST
    /sbin/initctl reload-configuration
else
    echo " failed."
    echo "Unsupported platform - neither systemctl nor initctl was found."
    exit 5
fi
echo "finished."
echo "Installation completed successfully."

%postun
if [ $1 == 0 ]; then
    echo -n "Uninstalling PCCS service ..."
    if [ -d /run/systemd/system ]; then
        PCCS_NAME=pccs.service
        if [ -d /lib/systemd/system ]; then
            PCCS_DEST=/lib/systemd/system/$PCCS_NAME
        else
            PCCS_DEST=/usr/lib/systemd/system/$PCCS_NAME
        fi
        systemctl stop pccs || true
        systemctl disable pccs || true
        rm $PCCS_DEST || true
        systemctl daemon-reload
    elif [ -d /etc/init/ ]; then
        PCCS_NAME=pccs.service
        PCCS_DEST=/etc/init/$PCCS_NAME
        rm $PCCS_DEST || true
        /sbin/initctl reload-configuration
    fi
    echo "finished."

    if [ -d %{_install_path} ]; then
        pushd %{_install_path} &> /dev/null
        rm -rf node_modules || true
        popd &> /dev/null
    fi
fi

%changelog
* Mon Mar 10 2020 SGX Team
- Initial Release
