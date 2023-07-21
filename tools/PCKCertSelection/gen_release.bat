@echo on

REM Set the relative directory name and tool folder paths
set rel_dir_name=PCKCertSelection_Release
set TOOLSFOLDER=..\..\..\..\installer_tools\Tools\standalone_build_se\sign

REM Set the path to the SignFile.exe executable located in the tools folder
set SIGNTOOL="%TOOLSFOLDER%\SignFile.exe"

REM Set the path to the certificate file located in the Certificates subfolder of the tools folder
set SIGNCERT=%TOOLSFOLDER%\Certificates\intel-ca.crt

REM Delete the target directory if it exists and create a new one
echo Deleting and creating directory...
if exist %rel_dir_name% (
    rmdir /s /q %rel_dir_name%
)
mkdir %rel_dir_name%
echo Directory created successfully.

REM Check if the files to be copied exist
echo Checking files...
if not exist "x64\release\PCKSelectionSample.exe" (
    echo ERROR: PCKSelectionSample.exe does not exist.
    exit /b 1
)

if not exist "x64\release\PCKCertSelectionLib.dll" (
    echo ERROR: PCKCertSelectionLib.dll does not exist.
    exit /b 1
)

REM Copy two files to the directory specified by the rel_dir_name variable
echo Copying files...
COPY "x64\release\PCKSelectionSample.exe" %rel_dir_name%
COPY "x64\release\PCKCertSelectionLib.dll" %rel_dir_name%
echo Files copied successfully.

REM Sign two files using the SignFile.exe executable and the specified certificate file
echo ========= Signing the binary Files  ===============
%SIGNTOOL% -cafile %SIGNCERT% -ha SHA256 %rel_dir_name%\PCKSelectionSample.exe
if errorlevel 1 (
    echo ERROR: Signing PCKSelectionSample.exe failed.
    exit /b 1
)
echo pck_id_retrieval_tool_enclave.signed.dll signed successfully.

%SIGNTOOL% -cafile %SIGNCERT% -ha SHA256 %rel_dir_name%\PCKCertSelectionLib.dll
if errorlevel 1 (
    echo ERROR: Signing PCKCertSelectionLib.dll failed.
    exit /b 1
)
echo dcap_quoteprov.dll signed successfully.
