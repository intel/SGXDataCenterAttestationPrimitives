@echo off
SETLOCAL EnableExtensions EnableDelayedExpansion
::
:: ========================================================================================================
:: ==== OpenSSL Library compilation with MSVC
:: ========================================================================================================
:: 
::      Author: stathis <stathis@npcglib.org>
::    Revision: $Id: build-openssl-1.0.2l.bat 4869 2017-05-29 18:56:54Z stathis $
::
:: Description: This script can be used to compile the OpenSSL Library with MSVC
::              The script builds all (8) permutations of:
::              (x86 | x64) - (static | shared) - (debug | release)
::
::              ATTENTION: Before compiling OpenSSL, you need to patch the sources to enable building 
::                         the libraries with different suffixes. (see usage on how to patch)
::
::  Changelog:
::
:: 11/04/2017 - Support for VS2017.
::
:: 26/01/2017 - Added compiling of tests and improved logging while building.
::
:: 02/12/2015 - Added some of the OpenSSL info files (e.g. LICENSE, README, etc.)
::
:: 22/10/2015 - Headers of 64-bit and 32-bit builds are now in separate directories (include vs include64)
::              [thanks Paul H.]
::
:: 22/07/2015 - Build log files are now produced during builds.
::
:: 25/10/2013 - Various fixes to enable packaging the required debug symbols for the produced libraries.
::            - Patching has now been migrated to a single patch per release (for the whole source tree)
::
:: 04/03/2013 - created patches for mk1mf.pl, mkdef.pl and util/VC-32.pl to enable different library
::              suffixes, according to the run-time library linked against:
::
::              {libname}MT   -- statically linked release OpenSSL libraries
::              {libname}MTd  -- statically linked debug OpenSSL libraries
::              {libname}MD   -- dynamically linked release OpenSSL libraries
::              {libname}MDd  -- dynamically linked release OpenSSL libraries
::
:: ========================================================================================================
:: ==== <CONFIGURATION>
:: ========================================================================================================
::
:: Set the version of Visual Studio. This will just add a suffix to the string
:: of your directories to avoid mixing them up.
SET VS_VERSION=2015

:: Set this to the directory that contains vcvarsall.bat file of the 
:: VC Visual Studio version you want to use for building the library.
SET VISUAL_STUDIO_VC=C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC

:: Set CYGWIN_DIR to the location of your Cygwin root ( one level up from /bin )
:: You can use any Cygwin installation, including a portable cygwin: 
:: https://github.com/search?q=cygwin+portable
:: Make sure you install the following cygwin packages: p7zip, md5sum, patch

SET CYGWIN_DIR=C:\Cygwin64

SET PERL_ROOT=C:\Perl64

rem ========================================================================================================

:: Set here the 7z command line to use for creating packages
:: Use an absolute path to the 7z.exe utility if it is not in your path.
:: -mx0 store compression
:: -mx9 ultimate compression
SET SEVENZIP_CMD=7z
::SET SEVENZIP_CMD_OPTIONS=a -r -mx9

:: Set here the location of the md5sum command, which is used to create md5 
:: checksums for the archives after packaging
:: Use an absolute path to the md5sum.exe utility or append its directory in your PATH.
SET MD5SUM_CMD=md5sum

:: Set here the date command
:: Use an absolute path to the date.exe utility or append its directory in your PATH.
SET DATE_CMD=date

:: Set here the patch command
:: Use an absolute path to the patch.exe utility or append its directory in your PATH.
SET PATCH_CMD=patch

:: Set here the patch command
:: Use an absolute path to the patch.exe utility or append its directory in your PATH.
SET DOS2UNIX_CMD=dos2unix.exe

rem ========================================================================================================

:: Set this to the name of the project
SET BUILD_PROJECT=openssl

:: Set this to the version of the project you are building
SET PROJECT_VERSION=1.0.2p

:: SET PROJECT_SRC_DIR=D:\opensource\!BUILD_PROJECT!-!PROJECT_VERSION!
SET PROJECT_SRC_DIR=C:\sgx\trunk\external\openssl\!BUILD_PROJECT!-!PROJECT_VERSION!

SET PROJECT_INSTALL_DIR=C:\sgx\trunk\external\openssl\!BUILD_PROJECT!-dist-!PROJECT_VERSION!-vs!VS_VERSION!

rem ========================================================================================================
rem == PLEASE DO NOT EDIT BELOW THIS LINE
rem ========================================================================================================

rem We load the config file first
call :loadconfig "%~dpn0"

rem we then carry on execution
call :execScript %0 %1 %2 %3 %4

ENDLOCAL

@exit /B 0

rem ========================================================================================================
rem == Pseudo-function to load config
rem ========================================================================================================

:loadconfig
rem set the variable HOSTNAME by executing the command (that's the computer's name)
FOR /F "delims=" %%a IN ('hostname') DO @set HOSTNAME=%%a

rem strip double quotes
set scriptFile=%1
set scriptFile=%scriptFile:"=%

rem We use two files: myScript.conf and myScript.<HOSTNAME>
rem myScript.<HOSTNAME> overrides myScript.conf
rem %~dpn0 is the full file minus the extension.
FOR %%c IN (
	"!scriptFile!.conf"
	"!scriptFile!.!HOSTNAME!"
) DO (
	IF EXIST "%%c" (
		ECHO.
		ECHO # Loading local configuration from: %%c
		ECHO.
		FOR /F "usebackq delims=" %%v IN (%%c) DO (set %%v)
	)
)

GOTO :eof

rem ========================================================================================================

:execScript
rem Use this pseudo-function to write the code of your main script
SETLOCAL EnableExtensions EnableDelayedExpansion

SET scriptName=%1
SET arg[0]=%2
SET arg[1]=%3
SET arg[2]=%4
SET arg[3]=%5

:: ATTENTION: this is down here because out-of-source builds are not supported DO NOT CHANGE IT!
SET PROJECT_BUILD_DIR=!PROJECT_SRC_DIR!\build

IF "!SEVENZIP_CMD_OPTIONS!" == "" (
	SET SEVENZIP_CMD_OPTIONS=a -r -mx9
)

FOR /F "delims=" %%a IN ('!CYGWIN_DIR!/bin/cygpath -p -u !SEVENZIP_CMD!') DO @set __SEVENZIP_CMD=%%a


IF "!arg[0]!" == "" GOTO usage
IF NOT EXIST "!PROJECT_SRC_DIR!" (
	ECHO.
	CALL :exitB "ERROR: Source directory !PROJECT_SRC_DIR! does not exist or does not contain the !BUILD_PROJECT! sources. Aborting."
	GOTO :eof
)

IF "!VS_VERSION!" == "2017" (
	SET VISUAL_STUDIO_VC=!VISUAL_STUDIO_VC!\Auxiliary\Build
	pushd "!VISUAL_STUDIO_VC!\..\..\..\Common7\Tools\"
	call "!VISUAL_STUDIO_VC!\..\..\..\Common7\Tools\vsdevcmd.bat" -clean_env
	popd
)

IF NOT EXIST "!VISUAL_STUDIO_VC!\vcvarsall.bat" (
	ECHO.
	CALL :exitB "ERROR: !VISUAL_STUDIO_VC!\vcvarsall.bat does not exist. Aborting."
	GOTO :eof
)


IF "!DATE_CMD_OPTIONS!" == "" (
	SET DATE_CMD_OPTIONS=%%d %%b %%Y
)


SET argC=-1
FOR %%x in (%*) DO SET /A argC+=1

if /i "!arg[0]!" == "build" (

	if !argC! == 2 (

		if /i "!arg[1]!" == "all" (

			echo.
			echo You are about to build all permutations [x86^|x64] [static^|shared] [debug^|release]
			echo.

			timeout /t 5
					
			call :buildall
			goto :eof
			
		) else (
			goto usage
		)
		
	) else if !argC! == 4 (

		call :callArch !arg[1]! !arg[2]! !arg[3]!
		goto :eof
		
	) else (
		goto usage
	)
	
) else if /i "!arg[0]!" == "package" (

	if !argC! == 2 (

		if /i "!arg[1]!" == "all" (

			echo.
			echo You are about to package all permutations [x86^|x64] [static^|shared] [debug^|release]
			echo.

			timeout /t 5
			
			call :createPackage
			goto :eof
			
		) else (
			goto usage
		)
		
	) else if !argC! == 3 (
		
		echo.
		echo This feature is currently unsupported. Only "package all" is supported at this time.
		echo.
			
		goto usage
		
		REM set archGood=false
		REM if /i "!arg[1]!" == "x86" set archGood=true
		REM if /i "!arg[1]!" == "x64" set archGood=true

		REM if /i "!archGood!" == "true" (

			REM call :createPackage !arg[0]! !arg[1]!
			REM goto :eof
			
		REM ) else (
			REM goto usage
		REM )
	) else (
		goto usage
	)
	
) else if /i "!arg[0]!" == "patch" (
	call :patch !PROJECT_VERSION!
) else if /i "!arg[0]!" == "unpatch" (
	call :unpatch !PROJECT_VERSION!
) else if !argC! == 3 (
	call :callArch !arg[0]! !arg[1]! !arg[2]!
	GOTO :eof
) else (
	GOTO usage
)

ENDLOCAL
GOTO :eof

rem ========================================================================================================
:printConfiguration
SETLOCAL EnableExtensions EnableDelayedExpansion
SET PATH=!CYGWIN_DIR!\bin;!CYGWIN_DIR!\usr\bin;!PATH!

echo.
echo                    PATH: !PATH!
echo.

echo              VS_VERSION: !VS_VERSION!
echo        VISUAL_STUDIO_VC: !VISUAL_STUDIO_VC!
echo              CYGWIN_DIR: !CYGWIN_DIR!
echo.
bash -c "echo -n \"           SEVENZIP_CMD: \" & which !__SEVENZIP_CMD!"
echo    SEVENZIP_CMD_OPTIONS: !SEVENZIP_CMD_OPTIONS!
bash -c "echo -n \"             MD5SUM_CMD: \" & which !MD5SUM_CMD!"
bash -c "echo -n \"               DATE_CMD: \" & which !DATE_CMD!"
bash -c "echo -n \"              PATCH_CMD: \" & which !PATCH_CMD!"
echo.
echo           BUILD_PROJECT: !BUILD_PROJECT!
echo         PROJECT_VERSION: !PROJECT_VERSION!
echo         PROJECT_SRC_DIR: !PROJECT_SRC_DIR!
echo       PROJECT_BUILD_DIR: !PROJECT_BUILD_DIR!
echo     PROJECT_INSTALL_DIR: !PROJECT_INSTALL_DIR!
ENDLOCAL
goto :eof

rem ========================================================================================================

:callArch
set archGood=false
if /i "%1" == "x86" set archGood=true
if /i "%1" == "x64" set archGood=true
if /i "!archGood!" == "true" (

	set linkGood=false
	if /i "%2"=="static" set linkGood=true
	if /i "%2"=="shared" set linkGood=true

	if /i "!linkGood!" == "true" (

		set buildGood=false
		if /i "%3" == "debug" set buildGood=true
		if /i "%3" == "release" set buildGood=true

		if /i "!buildGood!" == "true" (
		
			call :build %1 %2 %3
			goto :eof
			
		)
	)
	
)
goto usage
goto :eof

rem ========================================================================================================

:usage
call :printConfiguration
ECHO: 
ECHO Error in script usage. The correct usage is:
ECHO:
ECHO     !scriptName! [patch^|unpatch] - apply/remove patches to the sources
ECHO     !scriptName! build [all^|x86^|x64] ^<[static^|shared] [debug^|release]^> - builds all or specific permutations
ECHO     !scriptName! package [all^|x86^|x64] ^<[static^|shared]^> - creates a package file
ECHO:    
GOTO :eof

rem ========================================================================================================

:unpatch
rem remove patches from the sources
call :patch %1 unpatch
goto :eof

:patch
rem patch sources
::
:: To create a patch for mkdef.pl:
:: $ diff -u "F:\openssl-1.0.1e-orig\util\mk1mf.pl" "F:\openssl-1.0.1e\util\mk1mf.pl" > "%SSBUILDER_ROOT%\misc\openssl-1.0.1e-mk1mf.pl.patch"
:: $ diff -u "F:\openssl-1.0.1e-orig\util\mkdef.pl" "F:\openssl-1.0.1e\util\mkdef.pl" > "%SSBUILDER_ROOT%\misc\openssl-1.0.1e-mkdef.pl.patch"
:: $ diff -u "F:\openssl-1.0.1e-orig\util\pl\VC-32.pl" "F:\openssl-1.0.1e\util\pl\VC-32.pl" > "%SSBUILDER_ROOT%\misc\openssl-1.0.1e-VC-32.pl.patch"
::
:: To apply the patch:
::   cd into the unmodified openssl-x.x.x source directory
::   patch [--dry-run] -p2 -i "D:\dev\ssbuilder\misc\openssl-1.0.1e-mkdef.pl.patch"
::   patch [--dry-run] -p2 -i "D:\dev\ssbuilder\misc\openssl-1.0.1e-mkdef.pl.patch"
::
SETLOCAL EnableExtensions EnableDelayedExpansion

if /i "%2" == "unpatch" (
	SET EXTRA_TEXT=Removing
	SET EXTRA_FLAGS=-R
) else (
	SET EXTRA_TEXT=Applying
)

SET PATH=!CYGWIN_DIR!\bin;!CYGWIN_DIR!\usr\bin;

SET CYGWIN=nodosfilewarning

ECHO.
ECHO !EXTRA_TEXT! patches to [!BUILD_PROJECT! v%~1] sources
ECHO.

pushd "!PROJECT_SRC_DIR!"

	call :applyPatch !BUILD_PROJECT!-%~1.patch
	
popd

ENDLOCAL
goto :eof

:applyPatch
SET PATCH_FILE=%~dp0
SET PATCH_FILE=!PATCH_FILE!%1

IF NOT EXIST "!PATCH_FILE!" (

	call :exitB "Patch: [!PATCH_FILE!] does not exist. Aborting."

) ELSE (

	!DOS2UNIX_CMD! "!PATCH_FILE!"
	!PATCH_CMD! --binary !EXTRA_FLAGS! -N -p1 -i "!PATCH_FILE!"
	
)
goto :eof

rem ========================================================================================================

:createPackage

call :printConfiguration

echo:
echo Packaging OpenSSL Library
echo:

SET DIST_DIR=!PROJECT_INSTALL_DIR!\!BUILD_PROJECT!-!PROJECT_VERSION!-vs!VS_VERSION!

echo !DIST_DIR!

@mkdir !DIST_DIR!\bin 2>nul
@mkdir !DIST_DIR!\bin64 2>nul
@mkdir !DIST_DIR!\lib 2>nul
@mkdir !DIST_DIR!\lib64 2>nul
@mkdir !DIST_DIR!\include 2>nul
@mkdir !DIST_DIR!\include64 2>nul

call :packagetype

echo:


ENDLOCAL
@exit /B 0

rem ========================================================================================================

:: %1 library type (e.g. static)
:packagetype

SET DST_DIST=!BUILD_PROJECT!-!PROJECT_VERSION!-vs!VS_VERSION!
SET DST_DIST_DIR=!PROJECT_INSTALL_DIR!\!DST_DIST!

for %%l in (static shared) do (
	for %%a in (x86 x64) do (
	
		if /i "%%a" == "x86" (
			SET BITS=32
			SET BITSTR=
		) else (
			SET BITS=64
			SET BITSTR=!BITS!
			SET PREFIX_WIN=!PREFIX_WIN!!BITS!
		)
		
		for %%b in (debug release) do (

			SET __ARCH=%%a
			SET __BUILD=%%b
			SET __LINK=%%l
			
			SET SRC_DIST_DIR=!PROJECT_INSTALL_DIR!\!BUILD_PROJECT!-!__ARCH!-!__LINK!-!__BUILD!-vs!VS_VERSION!

			echo [copy] !SRC_DIST_DIR! =^> !DST_DIST_DIR!
		
			if exist "!SRC_DIST_DIR!" (
						
				xcopy /E /Q /Y !SRC_DIST_DIR!\bin\*.* !DST_DIST_DIR!\bin!BITSTR!\
				xcopy /E /Q /Y !SRC_DIST_DIR!\lib\*.* !DST_DIST_DIR!\lib!BITSTR!\
				xcopy /E /Q /Y !SRC_DIST_DIR!\include\*.* !DST_DIST_DIR!\include!BITSTR!\
				xcopy /E /Q /Y !SRC_DIST_DIR!\ssl\*.* !DST_DIST_DIR!\ssl\
				
			)
			
		)
	)
)



echo Copied all files for: !BUILD_PROJECT! v!PROJECT_VERSION!

set README=!DST_DIST_DIR!\readme.precompiled.txt
echo !README!

pushd !PROJECT_INSTALL_DIR!

	SETLOCAL EnableExtensions EnableDelayedExpansion

	SET PATH=!CYGWIN_DIR!\bin;!CYGWIN_DIR!\usr\bin;!PATH!

	echo. > !README!
	bash -c "!DATE_CMD! +\"!DATE_CMD_OPTIONS!\"" >> !README!
	echo ====================================================================================================================== >> !README!	
	echo  url: http://www.npcglib.org/~stathis/blog/precompiled-openssl >> !README!	
	echo ====================================================================================================================== >> !README!
	echo These are custom and unsupported, pre-built OpenSSL Libraries v!PROJECT_VERSION! (http://www.openssl.org). >> !README!
	echo They are compiled with Cygwin/MSVC for 32/64-bit Windows, using Visual Studio !VS_VERSION!. >> !README!
	echo. >> !README!
	echo Please note that the OpenSSL Project (http://www.openssl.org) is the only official source of OpenSSL. >> !README!
	echo These builds are created for my own personal use and therefore you are utilizing them at your own risk. >> !README!
	echo My builds are unsupported and not endorsed by The OpenSSL Project. >> !README!
	echo. >> !README!
	echo I build these in the context of my own work and spare time,  >> !README!
	echo I do NOT charge any money, I do NOT make any money ... and NO I do NOT accept any donations^^! >> !README!
	echo If you really like OpenSSL, if it has helped you or your company in any way, >> !README!
	echo or you are feeling like giving back anyway, then please  >> !README!
	echo donate directly to the OpenSSL Project: https://www.openssl.org/support/donations.html >> !README!
	echo The developers and countless contributors deserve it^^!  >> !README!
	echo. >> !README!
	echo ------------------------------------------------------------------------------ >> !README!
	echo 32-bit OpenSSL Libraries [shared] [runtime: dynamic (/MD)]]>> !README!
	echo ------------------------------------------------------------------------------ >> !README!
	echo release runtime dlls: bin\libeay32MD.dll bin\ssleay32MD.dll >> !README!
	echo  release import libs: lib\libeay32MD.lib lib\ssleay32MD.lib >> !README!	
	echo   debug runtime dlls: bin\libeay32MDd.dll bin\ssleay32MDd.dll >> !README!
	echo    debug import libs: lib\libeay32MDd.lib lib\ssleay32MDd.lib >> !README!
	echo. >> !README!
	echo ------------------------------------------------------------------------------ >> !README!
	echo 32-bit OpenSSL Libraries [static] [runtime: static (/MT)]]>> !README!
	echo ------------------------------------------------------------------------------ >> !README!
	echo         release libs: lib\libeay32MT.lib lib\ssleay32MT.lib >> !README!	
	echo           debug libs: lib\libeay32MTd.lib lib\ssleay32MTd.lib >> !README!	
	echo. >> !README!
	echo ------------------------------------------------------------------------------ >> !README!
	echo 64-bit OpenSSL Libraries [shared] [runtime: dynamic (/MD)]]>> !README!
	echo ------------------------------------------------------------------------------ >> !README!
	echo release runtime dlls: bin64\libeay32MD.dll bin64\ssleay32MD.dll >> !README!
	echo  release import libs: lib64\libeay32MD.lib lib64\ssleay32MD.lib >> !README!	
	echo   debug runtime dlls: bin64\libeay32MDd.dll bin64\ssleay32MDd.dll >> !README!
	echo    debug import libs: lib64\libeay32MDd.lib lib64\ssleay32MDd.lib >> !README!
	echo. >> !README!
	echo ------------------------------------------------------------------------------ >> !README!
	echo 64-bit OpenSSL Libraries [static] [runtime: static (/MT)]]>> !README!
	echo ------------------------------------------------------------------------------ >> !README!
	echo         release libs: lib64\libeay32MT.lib lib64\ssleay32MT.lib >> !README!	
	echo           debug libs: lib64\libeay32MTd.lib lib64\ssleay32MTd.lib >> !README!	
	echo. >> !README!
	echo ====================================================================================================================== >> !README!
	echo. >> !README!
	echo If you have any comments or problems send me an email at: >> !README!
	echo stathis ^<stathis@npcglib.org^> >> !README!

	bash -c "cp -f \"!PROJECT_SRC_DIR!\CHANGES\" \"!DST_DIST_DIR!\CHANGES.txt\""
	bash -c "cp -f \"!PROJECT_SRC_DIR!\README\" \"!DST_DIST_DIR!\README.txt\""
	bash -c "cp -f \"!PROJECT_SRC_DIR!\NEWS\" \"!DST_DIST_DIR!\NEWS.txt\""
	bash -c "cp -f \"!PROJECT_SRC_DIR!\LICENSE\" \"!DST_DIST_DIR!\LICENSE.txt\""

	set __FILENAME=!DST_DIST!

	set COMPRESSED_FILE=!__FILENAME!.7z

	echo.
	echo Packaging !BUILD_PROJECT! Library [v!PROJECT_VERSION!]
	echo ----------------------------------------------------------------------------
	echo [     Build in: !PROJECT_BUILD_DIR!] 
	echo [ Installation: !PROJECT_INSTALL_DIR!] 
	echo [    Packaging: !PROJECT_INSTALL_DIR!]
	echo [   Compressed: !COMPRESSED_FILE!]
	echo [       Readme: !README!]
	echo ----------------------------------------------------------------------------
	echo.

	echo Compressing with: !__SEVENZIP_CMD! !SEVENZIP_CMD_OPTIONS! !COMPRESSED_FILE! !DST_DIST!
	bash -c "!__SEVENZIP_CMD! !SEVENZIP_CMD_OPTIONS! !COMPRESSED_FILE! !DST_DIST!" 

	echo Compressing in: !COMPRESSED_FILE!

	IF EXIST !COMPRESSED_FILE! (
		
		for %%I in (!COMPRESSED_FILE!) do (
			SET /A _fsize=%%~zI / 1024 / 1024
		)
		
		!MD5SUM_CMD! !COMPRESSED_FILE! 1> !__FILENAME!.md5
		
		echo Generated md5sum !__FILENAME!.md5 [!_fsize!MB]

	)

	ENDLOCAL

popd

goto :eof

rem ========================================================================================================

:buildall



for %%a in (x86 x64) do (
	for %%l in (shared static) do (
		for %%b in (debug release) do (
			call :build %%a %%l %%b
		)
	)
)

goto :eof

rem ========================================================================================================

:: call :build <x86|x64> <static|shared> <debug|release>
:build
SET __ARCH=%~1
SET __LINK=%~2
SET __BUILD=%~3

if /i "!__ARCH!" == "x86" (
	SET BITS=32
	SET BIT_STR=
) else (
	SET BITS=64
	SET BIT_STR=64
)




echo:
echo Building OpenSSL Library [!__ARCH!] [!__LINK!] [!__BUILD!]
echo:

SETLOCAL EnableExtensions EnableDelayedExpansion

	IF "!VS_VERSION!" == "2017" (
		pushd "!VISUAL_STUDIO_VC!\..\..\..\Common7\Tools\"
		call "!VISUAL_STUDIO_VC!\..\..\..\Common7\Tools\vsdevcmd.bat" -clean_env
		popd
	)
	
	call "!VISUAL_STUDIO_VC!\vcvarsall.bat" !__ARCH!
	
	rem Place the linker and compiler of Visual Studio infront of any other binaries when searching
	SET PATH=!PATH!;!CYGWIN_DIR!\bin;!CYGWIN_DIR!\usr\bin;
	
	call :printConfiguration
	call :buildtype !__ARCH! !__LINK! !__BUILD!
	
ENDLOCAL
goto :eof


rem ========================================================================================================

:: call :build <x86|x64> <static|shared> <debug|release>
:buildtype
SET __ARCH=%~1
SET __LINK=%~2
SET __BUILD=%~3

SET CYGWIN=nodosfilewarning

if /i "!__ARCH!" == "x86" (
	SET BITS=32
	SET BIT_STR=
) else (
	SET BITS=64
	SET BIT_STR=64
)

IF NOT EXIST "!PROJECT_BUILD_DIR!" (
	mkdir "!PROJECT_BUILD_DIR!"
)


SET RUNTIME_SUFFIX=
if /i "!__LINK!" == "shared" (
	SET RUNTIME_SUFFIX=MD
)

if /i "!__LINK!" == "static" (
	SET RUNTIME_SUFFIX=MT
)

SET LIBSUFFIX=
if /i "!__BUILD!" == "debug" (
	SET LIBSUFFIX=d
)

SET RUNTIME_FULL_SUFFIX=!RUNTIME_SUFFIX!!LIBSUFFIX!

SET DLL_STR=
if /i "!__LINK!" == "shared" (
	SET DLL_STR=dll
)
	

SET B_CMD=perl Configure
SET COMMON_OPTIONS=enable-static-engine no-idea no-mdc2 no-rc5
SET MODE=VC-WIN

if /i "!__BUILD!" == "debug" (
	SET MODE=!__BUILD!-!MODE!
)

if /i "!__ARCH!" == "x86" (
	SET MODE=!MODE!!BITS!
	rem SET MS_CMD=call ms\do_nasm.bat
		
	SET COMMON_OPTIONS=!COMMON_OPTIONS! no-asm
) else (
	SET MODE=!MODE!!BITS!A
	rem SET MS_CMD=call ms\do_win64a.bat
)

SET INSTALL_DIR=!PROJECT_INSTALL_DIR!\!BUILD_PROJECT!-!__ARCH!-!__LINK!-!__BUILD!-vs!VS_VERSION!

IF NOT EXIST "!INSTALL_DIR!" (
	mkdir "!INSTALL_DIR!"
)

SET CONFIG_LOG_FILE=!INSTALL_DIR!\!BUILD_PROJECT!-!__ARCH!-!__LINK!-!__BUILD!-vs!VS_VERSION!.config.log
SET BUILD_LOG_FILE=!INSTALL_DIR!\!BUILD_PROJECT!-!__ARCH!-!__LINK!-!__BUILD!-vs!VS_VERSION!.build.log
SET TEST_LOG_FILE=!INSTALL_DIR!\!BUILD_PROJECT!-!__ARCH!-!__LINK!-!__BUILD!-vs!VS_VERSION!.test.log
SET INSTALL_LOG_FILE=!INSTALL_DIR!\!BUILD_PROJECT!-!__ARCH!-!__LINK!-!__BUILD!-vs!VS_VERSION!.install.log

ECHO. > !CONFIG_LOG_FILE!

SET B_CMD=!B_CMD! !MODE! !COMMON_OPTIONS! --prefix=!INSTALL_DIR!

echo Commands: !B_CMD!
rem echo Commands: !MS_CMD!
rem echo Commands: !MK_CMD!

timeout /t 10

pushd !PROJECT_SRC_DIR!
!B_CMD! > !CONFIG_LOG_FILE! 2>&1

SET BUILD_STR_PLAIN=
if /i "!__BUILD!" == "debug" (
	SET BUILD_STR_PLAIN=debug
)

SET BUILD_STR=
if /i "!__BUILD!" == "debug" (
	SET BUILD_STR=debug_lib
)

SET LINK_STR=
if /i "!__LINK!" == "static" (
	SET LINK_STR=static_lib
)

perl util\mkfiles.pl >MINFO

if /i "!__ARCH!" == "x86" (

	echo perl util\mk1mf.pl !DLL_STR! !BUILD_STR_PLAIN! !BUILD_STR! !LINK_STR! nasm VC-WIN32 >ms\nt!DLL_STR!-!__ARCH!.mak
	perl util\mk1mf.pl !DLL_STR! !BUILD_STR_PLAIN! !BUILD_STR! !LINK_STR! nasm VC-WIN32 >ms\nt!DLL_STR!-!__ARCH!.mak
	
) else (
	
	perl ms\uplink-x86_64.pl masm > ms\uptable.asm
	ml64 -c -Foms\uptable.obj ms\uptable.asm

	rem perl ms\uplink-x86_64.pl nasm > ms\uptable.asm
	rem nasm -f win64 -o ms\uptable.obj ms\uptable.asm

	echo perl util\mk1mf.pl !DLL_STR! !BUILD_STR_PLAIN! !BUILD_STR! !LINK_STR! VC-WIN64A >ms\nt!DLL_STR!-!__ARCH!.mak
	perl util\mk1mf.pl !DLL_STR! !BUILD_STR_PLAIN! !BUILD_STR! !LINK_STR! VC-WIN64A >ms\nt!DLL_STR!-!__ARCH!.mak
	
)

echo perl util\mkdef.pl !BUILD_STR! !LINK_STR! 32 libeay > ms\libeay32!RUNTIME_FULL_SUFFIX!.def
perl util\mkdef.pl !BUILD_STR! !LINK_STR! 32 libeay > ms\libeay32!RUNTIME_FULL_SUFFIX!.def

echo perl util\mkdef.pl !BUILD_STR! !LINK_STR! 32 ssleay > ms\ssleay32!RUNTIME_FULL_SUFFIX!.def
perl util\mkdef.pl !BUILD_STR! !LINK_STR! 32 ssleay > ms\ssleay32!RUNTIME_FULL_SUFFIX!.def


SET MK_CMD=nmake -f ms\nt!DLL_STR!-!__ARCH!.mak

ECHO. > !BUILD_LOG_FILE!

!MK_CMD! > !BUILD_LOG_FILE! 2>&1

!MK_CMD! test >> !TEST_LOG_FILE! 2>&1

!MK_CMD! install >> !INSTALL_LOG_FILE! 2>&1


rem There is debug symbols produced in this library for both Debug and Release libraries. We keep it all :)
if /i "!__BUILD!" == "debug" (
	SET TMPDIR_SUFFIX=.dbg
) ELSE (
	SET TMPDIR_SUFFIX=
)

copy /Y out32!DLL_STR!!TMPDIR_SUFFIX!\openssl!RUNTIME_FULL_SUFFIX!.pdb !INSTALL_DIR!\bin\

if /i "!__LINK!" == "shared" (
	copy /Y out32!DLL_STR!!TMPDIR_SUFFIX!\libeay32!RUNTIME_FULL_SUFFIX!.pdb !INSTALL_DIR!\bin\
	copy /Y out32!DLL_STR!!TMPDIR_SUFFIX!\ssleay32!RUNTIME_FULL_SUFFIX!.pdb !INSTALL_DIR!\bin\

	copy /Y out32!DLL_STR!!TMPDIR_SUFFIX!\libeay32!RUNTIME_FULL_SUFFIX!.exp !INSTALL_DIR!\lib\
	copy /Y out32!DLL_STR!!TMPDIR_SUFFIX!\ssleay32!RUNTIME_FULL_SUFFIX!.exp !INSTALL_DIR!\lib\
)

rem The following two are debug symbols that will be searched for when linking against the .lib files from client applications
rem That's why they are placed in the lib/ folder.
rem For some reason the appXX.pdb and libXX.pdb files are lower case (?) 
copy /Y tmp32!DLL_STR!!TMPDIR_SUFFIX!\app!RUNTIME_FULL_SUFFIX!.pdb !INSTALL_DIR!\lib\app!RUNTIME_FULL_SUFFIX!.pdb
copy /Y tmp32!DLL_STR!!TMPDIR_SUFFIX!\lib!RUNTIME_FULL_SUFFIX!.pdb !INSTALL_DIR!\lib\lib!RUNTIME_FULL_SUFFIX!.pdb

rem This is necessary for building on different architectures. (there are conf files being left behind)
!MK_CMD! vclean

popd

goto :eof

rem ========================================================================================================

:toLower str -- converts uppercase character to lowercase
::           -- str [in,out] - valref of string variable to be converted
:$created 20060101 :$changed 20080219 :$categories StringManipulation
:$source http://www.dostips.com
if not defined %~1 EXIT /b
for %%a in ("A=a" "B=b" "C=c" "D=d" "E=e" "F=f" "G=g" "H=h" "I=i"
            "J=j" "K=k" "L=l" "M=m" "N=n" "O=o" "P=p" "Q=q" "R=r"
            "S=s" "T=t" "U=u" "V=v" "W=w" "X=x" "Y=y" "Z=z" "Ä=ä"
            "Ö=ö" "Ü=ü") do (
    call set %~1=%%%~1:%%~a%%
)
EXIT /b

rem ========================================================================================================

:: %1 an error message
:exitB
echo:
echo Error: %1
echo:
echo Contact stathis@npcglib.org
@exit /B 0
