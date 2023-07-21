@echo off
SETLOCAL

IF "%selfWrapped%"=="" (
  REM ***** this is necessary so that we can use "exit" to terminate the batch file, ****
  REM ***** and all subroutines, but not the original cmd.exe                        ****
  SET selfWrapped=true
  %ComSpec% /s /c ""%~0" %*"
  GOTO :EOF
)

IF "%1"=="" (
      SET VERSION=1.6.90.0
  ) ELSE (
      SET VERSION=%1
)

echo *** Welcome to the SGX MPRA Installer Build Script ***
echo:

SET SRC_DIR=..\
SET DST_DIR=.\Output
SET BIN_DIR=%SRC_DIR%\x64\Release
set TOOLSFOLDER=.\..\..\..\..\..\installer_tools\Tools\standalone_build_se\sign
set SIGNTOOL="%TOOLSFOLDER%\SignFile.exe"
set SIGNCERT=%TOOLSFOLDER%\Certificates\intel-ca.crt

SET INF2CAT="C:\Program Files (x86)\Windows Kits\10\bin\x86\inf2cat.exe"
SET STAMPINF="C:\Program Files (x86)\Windows Kits\10\bin\x86\stampinf.exe"
SET INFVER="C:\Program Files (x86)\Windows Kits\10\Tools\x64\infverif.exe"
SET DBG_SIGN_TOOL="C:\Program Files (x86)\Windows Kits\10\App Certification Kit\signtool.exe"



echo ========== Creating Target Folder(s) =============
rd /s /q %DST_DIR%
mkdir %DST_DIR%
echo:

echo ============ Copying binaries ==============
CALL :COPY_FILE %SRC_DIR%\inf\sgx_mpa.inf %DST_DIR%\
CALL :COPY_FILE %SRC_DIR%\license.txt %DST_DIR%\
CALL :COPY_FILE %BIN_DIR%\events.dll %DST_DIR%\
CALL :COPY_FILE %BIN_DIR%\mp_uefi.dll %DST_DIR%\
CALL :COPY_FILE %BIN_DIR%\mp_network.dll %DST_DIR%\

CALL :COPY_FILE %BIN_DIR%\mpa_manage.exe %DST_DIR%\
CALL :COPY_FILE ..\..\..\..\..\SDK_installer\InstallBinaries\bin\x64\Release\sgx_capable.dll %DST_DIR%\
CALL :COPY_FILE %BIN_DIR%\mpa.exe %DST_DIR%\

echo ========== Stamping INF file ================
%STAMPINF% -f "%DST_DIR%\sgx_mpa.inf" -k "1.9" -d "*" -a "amd64" -v "%VERSION%"
IF /I "%ERRORLEVEL%" NEQ "0" (
	goto exit
)

echo:

echo ========== Verifing INF file ================
%INFVER% /v /u %DST_DIR%\sgx_mpa.inf
IF /I "%ERRORLEVEL%" NEQ "0" (
	goto exit
)
echo:
echo ========= Creating The Catalog File ==============
%INF2CAT% /driver:%DST_DIR% /os:10_x64 /uselocaltime /VERBOSE 
IF /I "%ERRORLEVEL%" NEQ "0" (
    goto exit
)
echo:

echo ========= Signing The Catalog File and executibales ===============
%SIGNTOOL% -cafile %SIGNCERT% -ha SHA256 "%DST_DIR%\sgx_mpa.cat"
%SIGNTOOL% -cafile %SIGNCERT% -ha SHA256 %DST_DIR%\mpa.exe
%SIGNTOOL% -cafile %SIGNCERT% -ha SHA256 %DST_DIR%\mpa_manage.exe
%SIGNTOOL% -cafile %SIGNCERT% -ha SHA256 %DST_DIR%\mp_network.dll
%SIGNTOOL% -cafile %SIGNCERT% -ha SHA256 %DST_DIR%\mp_uefi.dll
%SIGNTOOL% -cafile %SIGNCERT% -ha SHA256 %DST_DIR%\events.dll

echo:
echo *** SGX MPRA INF Installer Build Succesful. Bye bye.***
goto fin

:COPY_FILE
echo f | xcopy %1 %2 /Y /F 
IF /I "%ERRORLEVEL%" NEQ "0" (
	goto copy_failure
)
EXIT /B

:copy_failure
echo -----------------------------------------
echo -        Failed to copy files           -
echo -----------------------------------------

:exit
echo:
echo *** SGX MPRA INF Installer Build Script exiting. Bye bye. ***
exit

:fin
