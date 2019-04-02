echo off

set HEADERFILEFOLDER="..\..\"
set DEBUGFILEFOLDER="..\..\x64\Debug\"
set RELEASEFILEFOLDER="..\..\x64\Release\"
set PACKAGETNAME=DCAP_Components.1.1.100.1
set pwd=%~dp0DCAP_Components

pushd "%~dp0"

if not exist "%pwd%\Header Files\" mkdir "%pwd%\Header Files"
if not exist "%pwd%\lib\native\Debug Support\" mkdir "%pwd%\lib\native\Debug Support"
if not exist "%pwd%\lib\native\Libraries\" mkdir "%pwd%\lib\native\Libraries"

copy /y "%HEADERFILEFOLDER%\quote_wrapper\common\inc\sgx_ql_lib_common.h" "%pwd%\Header Files\sgx_ql_lib_common.h"
copy /y "%HEADERFILEFOLDER%\quote_wrapper\ql\inc\sgx_dcap_ql_wrapper.h" "%pwd%\Header Files\sgx_dcap_ql_wrapper.h"
copy /y "%HEADERFILEFOLDER%\pce_wrapper\inc\sgx_pce.h" "%pwd%\Header Files\sgx_pce.h"
copy /y "%SGXSDKInstallPath%\include\sgx_attributes.h" "%pwd%\Header Files\sgx_attributes.h"
copy /y "%SGXSDKInstallPath%\include\sgx_key.h" "%pwd%\Header Files\sgx_key.h"
copy /y "%SGXSDKInstallPath%\include\sgx_report.h" "%pwd%\Header Files\sgx_report.h"

copy /y "%DEBUGFILEFOLDER%\sgx_dcap_ql.lib" "%pwd%\lib\native\Debug Support\sgx_dcap_ql.lib"

copy /y "%RELEASEFILEFOLDER%\sgx_dcap_ql.lib" "%pwd%\lib\native\Libraries\sgx_dcap_ql.lib"

if exist %PACKAGETNAME%.nupkg del /Q %PACKAGETNAME%.nupkg

"nuget.exe" pack "%~dp0DCAP_Components\DCAP_Components.nuspec"

popd
