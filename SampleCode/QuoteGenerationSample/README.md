Intel(R) Software Guard Extensions Data Center Attestation Primitives (Intel(R) SGX DCAP) Quote Generation SampleCode
================================================

## Linux
Supported operating systems:
* Ubuntu* 18.04 LTS Desktop 64bits
* Ubuntu* 18.04 LTS Server 64bits
* Ubuntu\* 20.04 LTS Server 64bits
* Red Hat Enterprise Linux Server release 8.2 64bits
* CentOS 8.2 64bits

Requirements:
* make
* gcc
* g++
* bash shell

Prerequisite:
* Intel(R) SGX DCAP Driver
* Intel(R) SGX SDK
* Intel(R) SGX DCAP Packages
* Intel(R) SGX DCAP PCCS (Provisioning Certificate Caching Service)

*Please refer to SGX DCAP Linux installation guide "https://download.01.org/intel-sgx/sgx-dcap/#version#/linux/docs/Intel_SGX_DCAP_Linux_SW_Installation_Guide.pdf" to install above dependencies*<br/>
*Note that you need to change **\#version\#** to actual version number in URL, such as 1.4.*

### Apps with "in-process" quote

If your app uses Intel(R) SGX AESM service for "out-of-process" quote generation (quote generated in AESM process using Intel(R) signed PCE and QE), then the AESM installer will do the configuration described here and you can ignore this section.

If your app is doing so-called "in-process" quote generation, i.e., it loads provisioning/quoting enclaves by itself including Intel(R) signed PCE, QE, then the app needs to be run with an uid in `sgx_prv` group.

Use below command to add the user running the process to `sgx_prv` group, then run app again:
```
    $ sudo usermod -a -G sgx_prv <user name>
```
Note that you need to `open another terminal to make above command take effect`.

Details please refer to driver [README](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/driver/linux#launching-an-enclave-with-provision-bit-set).

*Note:* Without proper access, the app will fail on loading the provisioning enclaves with error. e.g. SGX_ERROR_SERVICE_INVALID_PRIVILEGE(0x4004) from enclave loader.


### Build and run QuoteGenerationSample to generate SGX ECDSA quote

*Note that you need to install libsgx-quote-ex-dev package and all its dependencies and recommends in order to build and run this sample. Or you can remove the `-l$(Uae_Library_Name)` in Makefile.
```
   Release build:
   $ make
   Or Debug build:
   $ make SGX_DEBUG=1
   Run application in "in-proc" mode:
   $ ./app
   Run application in "out-of-proc" mode:
   $ SGX_AESM_ADDR=1 ./app
```


## Windows
Supported operating systems:
   * Windows* Server 2016 (Long-Term Servicing Channel)
   * Windows* Server 2019 (Long-Term Servicing Channel)

Requirements:
* Microsoft Visual Studio 2019 or newer.

Prerequisite:
* Intel(R) SGX DCAP Driver
* Intel(R) SGX SDK
* Intel(R) SGX DCAP Packages
* Intel(R) SGX DCAP PCCS (Provisioning Certificate Caching Service)


*Please refer to [SGX DCAP Windows installation guide](https://software.intel.com/en-us/sgx/sdk) to install above dependencies*<br/>
*Note that you need to sign in IDZ first, then download & extract product "Intel(R) Software Guard Extensions Data Center Attestation Primitives"*

Build and run QuoteGenerationSample to generate an ECDSA quote
```
   a. Open VS solution QuoteGenerationSample.sln, build with Debug/Release | x64 configuration
   b. Run App.exe
```
