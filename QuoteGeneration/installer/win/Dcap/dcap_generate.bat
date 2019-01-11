echo off

set BUILDNUM="0"
set TOOLSFOLDER="..\Tools"
set RELEASEFILEFOLDER="..\..\..\x64\Release"

:GETPSWEXENAME
if "%1" =="" (
  echo Please input Version number: dcap_generate.bat X.X.X.X
  goto Build_failure
)

:STARTBUILD


if not exist "%~dp0Output" (
  echo Please first execute dcap_copy_file.bat ...
  goto Build_failure
)

echo **************************************************
echo * Generate INF installer *
echo **************************************************
pushd "%~dp0"
copy /y "%~dp0\sgx_dcap_default.inf" "%~dp0output\sgx_dcap.inf"
copy /y "%~dp0\sgx_dcap_dev_default.inf" "%~dp0output\sgx_dcap_dev.inf"
"%WindowsSdkDir%\bin\x86\stampinf.exe" -f "%~dp0output\sgx_dcap.inf" -k "1.9" -d "*" -a "amd64" -v "%1"
"%WindowsSdkDir%\bin\x86\stampinf.exe" -f "%~dp0output\sgx_dcap_dev.inf" -k "1.9" -d "*" -a "amd64" -v "%1"
"%WindowsSdkDir%\bin\x86\Inf2Cat.exe" /driver:%~dp0output /os:"10_x64"

echo **************************************************
echo * Signing INF installer *
echo **************************************************
call "%TOOLSFOLDER%\Sign.bat" "%~dp0output\*.cat"

echo **************************************************
echo * Done *
echo **************************************************

popd

goto END

:Build_failure
echo -----------------------------------------
echo - Failed to build INF installer -
echo -----------------------------------------
:End
