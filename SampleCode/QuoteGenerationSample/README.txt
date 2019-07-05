The project demonstrates:
- How an application can use the Quote Generation APIs.
        sgx_qe_set_enclave_load_policy
        sgx_qe_cleanup_by_policy
        sgx_qe_get_target_info
        sgx_qe_get_quote_size
        sgx_qe_get_quote

------------------------------------
How to Build/Execute the Sample Code
------------------------------------
For Windows:
============
1. Open the solution "QuoteGenerationSample.sln" with Microsoft Visual Studio
2. Install Intel(R)_SGX_Windows_SDK_2.2.xxx.xxx, NuGet package DCAP_Components.1.0.100.1.nupkg, DCAP INF installer,
3. Build and execute it directly

For Linux:
=========
1. Install prebuilt Intel(R) SGX SDK and PSW Installer
    a. sgx_linux_x64_sdk_${version}.bin
    b. libsgx-enclave-common_{version}-{revision}_{arch}.deb
2. Install bellow DCAP Debian packages: 
    a. libsgx-dcap-ql_{version}-{revision}_{arch}.deb
    b. libsgx-dcap-ql-dev_{version}-{revision}_{arch}.deb
3. Build the project with the prepared Makefile:
    a. Release build:
        $ make
    b. Debug build:
        $ make DEBUG=1
4. Execute the binary:
    $ ./app
5. Remember to "make clean" before switching build mode

