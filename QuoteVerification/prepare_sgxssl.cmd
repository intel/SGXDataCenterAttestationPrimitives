Rem
Rem Copyright (C) 2011-2022 Intel Corporation. All rights reserved.
Rem
Rem Redistribution and use in source and binary forms, with or without
Rem modification, are permitted provided that the following conditions
Rem are met:
Rem
Rem   * Redistributions of source code must retain the above copyright
Rem     notice, this list of conditions and the following disclaimer.
Rem   * Redistributions in binary form must reproduce the above copyright
Rem     notice, this list of conditions and the following disclaimer in
Rem     the documentation and/or other materials provided with the
Rem     distribution.
Rem   * Neither the name of Intel Corporation nor the names of its
Rem     contributors may be used to endorse or promote products derived
Rem     from this software without specific prior written permission.
Rem
Rem THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
Rem "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
Rem LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
Rem A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
Rem OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
Rem SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
Rem LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
Rem DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
Rem THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
Rem (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
Rem OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
Rem
Rem

setlocal enabledelayedexpansion

set PFM=%1
set CFG=%2

set top_dir=%~dp0
set sgxssl_dir=%top_dir%\sgxssl

set openssl_out_dir=%sgxssl_dir%\openssl_source
set openssl_ver_name=openssl-3.1.6
set sgxssl_github_archive=https://github.com/intel/intel-sgx-ssl/archive
set sgxssl_ver_name=3.1.6_Rev1
set sgxssl_ver=%sgxssl_ver_name%
set build_script=%sgxssl_dir%\Windows\build_package.cmd

@Rem set server_url_path=https://www.openssl.org/source/
set server_url_path=https://af01p-igk.devtools.intel.com/artifactory/sgxdcapprerequisites-igk-local/prebuilt/ssl

set full_openssl_url=%server_url_path%/%openssl_ver_name%.tar.gz
set sgxssl_chksum=8fbacac2612f6117c11d04cd7989f1a035f978683a4626055133b2fbf332d016
set openssl_chksum=5d2be4036b478ef3cb0a854ca9b353072c3a0e26d8a56f8f0ab9fb6ed32d38d7

if not exist %sgxssl_dir% (
	mkdir %sgxssl_dir%
)

if not exist %build_script% (
	call powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;Invoke-WebRequest -URI %sgxssl_github_archive%/%sgxssl_ver_name%.zip -OutFile %sgxssl_dir%\%sgxssl_ver_name%.zip"
	call powershell -Command "$sgxsslfilehash = Get-FileHash %sgxssl_dir%\%sgxssl_ver_name%.zip; Write-Output $sgxsslfilehash.Hash | out-file -filepath %sgxssl_dir%\check_sum_sgxssl.txt -encoding ascii"
	findstr /i %sgxssl_chksum% %sgxssl_dir%\check_sum_sgxssl.txt>nul
	if !errorlevel! NEQ 0  (
	echo "File %sgxssl_dir%\%sgxssl_ver_name%.zip checksum failure"
	del /f /q %sgxssl_dir%\%sgxssl_ver_name%.zip
	exit /b 1
	)
	call powershell -Command "Expand-Archive -LiteralPath '%sgxssl_dir%\%sgxssl_ver_name%.zip' -DestinationPath %sgxssl_dir%"
    xcopy /y "%sgxssl_dir%\intel-sgx-ssl-%sgxssl_ver%" %sgxssl_dir% /e
	del /f /q %sgxssl_dir%\%sgxssl_ver_name%.zip
	rmdir /s /q %sgxssl_dir%\intel-sgx-ssl-%sgxssl_ver%
)

if not exist %openssl_out_dir%\%openssl_ver_name%.tar.gz (
@Rem	call powershell -Command "Invoke-WebRequest -URI %full_openssl_url% -OutFile %openssl_out_dir%\%openssl_ver_name%.tar.gz"
	call powershell -Command " [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; (New-Object Net.WebClient).DownloadFile('%full_openssl_url%', '%openssl_out_dir%\%openssl_ver_name%.tar.gz'); exit" > nul
)
call powershell -Command " $opensslfilehash = Get-FileHash %openssl_out_dir%\%openssl_ver_name%.tar.gz; Write-Output $opensslfilehash.Hash | out-file -filepath %sgxssl_dir%\check_sum_openssl.txt -encoding ascii"
findstr /i %openssl_chksum% %sgxssl_dir%\check_sum_openssl.txt>nul
if !errorlevel! NEQ 0  (
	echo "File %openssl_out_dir%\%openssl_ver_name%.tar.gz checksum failure"
	del /f /q %openssl_out_dir%\%openssl_ver_name%.tar.gz
	exit /b 1
)

if not exist %sgxssl_dir%\Windows\package\lib\%PFM%\%CFG%\libsgx_tsgxssl.lib (
	cd %sgxssl_dir%\Windows\
	start /WAIT cmd /C call %build_script% %PFM%_%CFG% %openssl_ver_name% no-clean SIM || exit /b 1
    xcopy /E /H /y %sgxssl_dir%\Windows\package %top_dir%\package\

	cd ..\
)

cd %top_dir%
exit /b 0
