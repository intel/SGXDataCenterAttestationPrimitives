Intel(R) Software Guard Extensions Data Center Attestation Primitives (Intel(R) SGX DCAP) Rust SGX Quote Generation SampleCode
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
* clang
* Rust and Cargo
## Prerequisite:
* Linux 5.11 and above, or Intel(R) SGX DCAP Driver
* Intel(R) SGX SDK
* Intel(R) SGX DCAP Development Packages

`libsgx-enclave-common-dev`, `libsgx-dcap-ql-dev` and `libsgx-dcap-default-qpl-dev`. Or `libsgx-enclave-common-devel`, `libsgx-dcap-ql-devel` and `libsgx-dcap-default-qpl-devel`
* Intel(R) SGX DCAP PCCS (Provisioning Certificate Caching Service)
* If you want to use "out-of-process" quote generation, you need to install `libsgx-quote-ex-dev` or `libsgx-quote-ex-devel` package in Intel(R) SGX PSW Packages

*Please refer to [SGX DCAP Linux installation guide](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf) to install above dependencies*

## Apps with "in-process" quote
If your app uses Intel(R) SGX AESM service for "out-of-process" quote generation (quote generated in AESM process using Intel(R) signed PCE and QE), then the AESM installer will do the configuration described here and you can ignore this section.

If your app is doing so-called "in-process" quote generation, i.e., it loads provisioning/quoting enclaves by itself including Intel(R) signed PCE, QE, then the app needs to be run with an uid in `sgx_prv` group.

Use below command to add the user running the process to `sgx_prv` group, then run app again:
```
$ sudo usermod -a -G sgx_prv <user name>
```
Note that you need to open another terminal to make above command take effect.

Details please refer to driver [README](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/driver/linux#launching-an-enclave-with-provision-bit-set).

*Note:* Without proper access, the app will fail on loading the provisioning enclaves with error. e.g. `SGX_ERROR_SERVICE_INVALID_PRIVILEGE(0x4004)` from enclave loader.

## Build and run RustSGXQuoteGenerationSample to generate SGX ECDSA quote
An enclave is required to create a report that will be converted to quote. In this sample, we use [QuoteGenerationSample](../QuoteGenerationSample) to create the report. Users can use a 3rd party Rust SGX SDK to develop an enclave and create the report.

Build and run *RustTDQuoteGenerationSample* to "in-process" generate a TD quote

```
$ cargo build
$ ./target/debug/app target-info
$ pushd ../QuoteGenerationSample
$ ./app TargetInfo ../RustSGXQuoteGenerationSample/target_info.dat
$ popd
$ ./target/debug/app quote ../QuoteGenerationSample/report.dat
```

Build and run *RustTDQuoteGenerationSample* to "out-of-process" generate a TD quote

```
$ cargo build
$ export SGX_AESM_ADDR=1
$ ./target/debug/app target-info
$ pushd ../QuoteGenerationSample
$ ./app TargetInfo ../RustSGXQuoteGenerationSample/target_info.dat
$ popd
$ ./target/debug/app quote ../QuoteGenerationSample/report.dat
```