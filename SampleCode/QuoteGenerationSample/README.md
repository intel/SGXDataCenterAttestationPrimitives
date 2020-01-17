Intel(R) Software Guard Extensions Data Center Attestation Primitives (Intel(R) SGX DCAP) Quote Generation SampleCode
================================================

## Linux
Supported operating systems:
* Ubuntu* 16.04 LTS Desktop 64bits - minimal kernel 4.10
* Ubuntu* 16.04 LTS Server 64bits - minimal kernel 4.10
* Ubuntu* 18.04 LTS Desktop 64bits
* Ubuntu* 18.04 LTS Server 64bits

Requirements:
* make
* gcc
* g++
* bash shell

Pre-requisets:
* Intel(R) SGX DCAP Driver
* Intel(R) SGX SDK
* Intel(R) SGX DCAP Packages
* Intel(R) SGX DCAP PCCS (Provisioning Certificate Caching Service)

*Please refer to SGX DCAP Linux installation guide "https://download.01.org/intel-sgx/sgx-dcap/#version#/linux/docs/Intel_SGX_DCAP_Linux_SW_Installation_Guide.pdf" to install above dependencies*<br/>
*Note that you need to change **\#version\#** to actual version number in URL, such as 1.4.*


Build and run QuoteGenerationSample to generate an ECDSA quote
```
   Release build:
   $ make
   Or Debug build:
   $ make SGX_DEBUG=1
   $ ./app
```


## Windows
Supported operating systems:
   * Windows* Server 2016 (Long-Term Servicing Channel)
   * Windows* Server 2019 (Long-Term Servicing Channel)

Requirements:
* Microsoft Visual Studio 2017 or newer.

Pre-requisets:
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
