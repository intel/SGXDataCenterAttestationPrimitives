The project demonstrates:
- How an application can use the Quote Generation APIs.

------------------------------------
How to Build/Execute the Sample Code
------------------------------------
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
