@REM  Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
@REM 
@REM  Redistribution and use in source and binary forms, with or without
@REM  modification, are permitted provided that the following conditions
@REM  are met:
@REM 
@REM    * Redistributions of source code must retain the above copyright
@REM      notice, this list of conditions and the following disclaimer.
@REM    * Redistributions in binary form must reproduce the above copyright
@REM      notice, this list of conditions and the following disclaimer in
@REM      the documentation and/or other materials provided with the
@REM      distribution.
@REM    * Neither the name of Intel Corporation nor the names of its
@REM      contributors may be used to endorse or promote products derived
@REM      from this software without specific prior written permission.
@REM 
@REM  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
@REM  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
@REM  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
@REM  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
@REM  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
@REM  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
@REM  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
@REM  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
@REM  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
@REM  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
@REM  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
@REM 

@echo off 

set svn_ver=%1%
set rel_dir_base=PCKIDRetrievalTool_v1.6.100.2
set rel_dir_name=%rel_dir_base%%svn_ver%


del /Q %rel_dir_name%\*
rd %rel_dir_name% 

mkdir %rel_dir_name%
copy x64\release\enclave.signed.dll %rel_dir_name%
copy x64\release\dcap_quoteprov.dll %rel_dir_name%
copy x64\release\PCKIDRetrievalTool.exe %rel_dir_name%
copy network_setting.conf %rel_dir_name%
copy README.txt %rel_dir_name%
copy License.txt %rel_dir_name%

powershell Compress-Archive -Path '%rel_dir_name%\*' -DestinationPath '%rel_dir_name%.zip' -Force 


