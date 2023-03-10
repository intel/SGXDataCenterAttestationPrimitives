Intel(R) Software Guard Extensions Data Center Attestation Primitives (Intel(R) SGX DCAP) Quote Verification SampleCode
================================================

# Linux
## Supported operating systems:
* Ubuntu\* 18.04 LTS Desktop 64bits
* Ubuntu\* 18.04 LTS Server 64bits
* Ubuntu\* 20.04 LTS Desktop 64bits
* Ubuntu\* 20.04 LTS Server 64bits
* Ubuntu\* 22.04 LTS Server 64bits
* Red Hat Enterprise Linux Server release 8.6 64bits
* CentOS Stream 8 64bits
* CentOS 8.3 64bits
* SUSE Linux Enterprise Server 15.4 64bits
* Anolis OS 8.6 64bits
* Debian 10 64bits

## Requirements:
* make
* gcc
* g++
* bash shell

## Prerequisite:
* Linux 5.11 and above, or Intel(R) SGX DCAP Driver
* Intel(R) SGX SDK
* Intel(R) SGX DCAP Development Packages

`libsgx-enclave-common-dev`, ` libsgx-dcap-quote-verify-dev` and `libsgx-dcap-default-qpl-dev`. Or `libsgx-enclave-common-devel`, ` libsgx-dcap-quote-verify-devel` and `libsgx-dcap-default-qpl-devel`
* Intel(R) SGX DCAP PCCS (Provisioning Certificate Caching Service)

*Please refer to [SGX DCAP Linux installation guide](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf) to install above dependencies*
## Prepare quote file `quote.dat`
You need to follow [QuoteGenerationSample](../QuoteGenerationSample) to generate an ECDSA quote with certification data of type 5.
## Build QuoteVerificationSample

Release build:
```
$ make #You need to sign ISV enclave with your own key in this mode
```
Or Debug build:

Prepare Enclave test key(two options):
1. Install openssl first, then the project will generate a test key `Enclave_private_sample.pem` automatically when you build the project.
2. Rename your test key(3072-bit RSA private key) to `Enclave_private_sample.pem` and put it under the `Enclave` folder.
```
$ make SGX_DEBUG=1
```
## Run QuoteVerificationSample to verify a given SGX or TDX quote
```
$ ./app -quote </path/to/quote.dat [default=../QuoteGenerationSample/quote.dat]>
```
## Build and run QuoteVerificationSample inside TD VM
```
$ make TD_ENV=1 SGX_DEBUG=1
$ ./app -quote </path/to/quote.dat [default=../QuoteGenerationSample/quote.dat]>
```

**Note**: Our libdcap_quoteprov.so is not built with Intel(R) Control Flow Enforcement Technology(CET) feature. If the sample is built with CET feature(it can be enabled by the compiler's default setting) and it is running on a CET enabled platform, you may encounter such an error message(or something similar): "Couldn't find the platform library. rebuild shared object with SHSTK support enabled". It means the system glibc enforces that a CET-enabled application can't load a non-CET shared library. You need to rebuild the sample by adding `-fcf-protection=none` option explicitly to disable CET.

# Windows
## Supported operating systems:
* Windows* Server 2016 (Long-Term Servicing Channel)
* Windows* Server 2019 (Long-Term Servicing Channel)

## Requirements:
* Microsoft Visual Studio 2019 or newer.

## Prerequisite:
* Intel(R) SGX DCAP Driver
* Intel(R) SGX SDK
* Intel(R) SGX DCAP Packages
* Intel(R) SGX DCAP PCCS (Provisioning Certificate Caching Service)

*Please refer to [SGX DCAP Windows installation guide](https://software.intel.com/en-us/sgx/sdk) to install above dependencies*<br/>
*Note that you need to sign in IDZ first, then download & extract product "Intel(R) Software Guard Extensions Data Center Attestation Primitives"*

## Prepare quote file `quote.dat`
You need to follow [QuoteGenerationSample](../QuoteGenerationSample) to generate an ECDSA quote with certification data of type 5.

## Build and run QuoteVerificationSample to verify a given quote
1. Open VS solution QuoteVerificationSample.sln, butil with `Debug/Release | x64` configuration. Note that Release mode need to sign ISV enclave with your own key.
2. Run App.exe
```
> App.exe -quote </path/to/quote.dat [default=..\..\..\QuoteGenerationSample\x64\Debug\quote.dat]>
```