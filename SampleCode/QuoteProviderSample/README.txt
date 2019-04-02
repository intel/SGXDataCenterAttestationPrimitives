Decription:
	This tool aims to demo how to develop quote provider library and use it to generate quote.
	In this sample, quote provider library use prebuilt PCK cert chain and hardcoded all-0 TCB level.
	
------------------------------------
How to Build/Execute the Sample Code
------------------------------------
On Windows:
==========
1. Open the solution "QuoteProviderSample.sln" with Microsoft Visual Studio
2. Install Intel(R)_SGX_Windows_SDK_${version}, NuGet package DCAP_Components.${version}.nupkg, DCAP INF installer,
3. Build and execute it directly

On Linux:
========
1. Install prebuilt Intel(R) SGX SDK and PSW Installer
    a. sgx_linux_x64_sdk_${version}.bin
    b. libsgx-enclave-common_{version}-{revision}_{arch}.deb
2. Install bellow DCAP Debian packages:
    a. libsgx-dcap-ql_{version}-{revision}_{arch}.deb
    b. libsgx-dcap-ql-dev_{version}-{revision}_{arch}.deb
3. Build the project with the prepared Makefile.
    a. Release build:
        make
    b. Debug build:
        make DEBUG=1
4. Go to bin subfolder and execute the binary:
    $ cd bin/
    $ LD_LIBRARY_PATH=./ ./quotegen

