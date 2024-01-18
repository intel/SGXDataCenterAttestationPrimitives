# Attestation Library For Service TD
## Overview
This is Attestation Library for Intel(R) Trust Domain Extensions (Intel(R) TDX)'s Service TD, implemented in C/C++ for reference.   

This README file contains "Attestation Library for Service TD" build instructions.

## How to build
### Prerequisites

* Ensure that you have the following required operation systems: 
  * Red Hat Enterprise Linux Server release 9.2 64bits
  * CentOS Stream 9 64bits
  * Ubuntu* 22.04 LTS Server 64bits
  * Ubuntu* 23.10 Server 64bits
* Use the following commands to install the required tools:
  *  On Red Hat Enterprise Linux 9.2
  ```
    $ sudo yum groupinstall 'Development Tools'
    $ sudo yum install ocaml ocaml-ocamlbuild wget rpm-build pkgconf libtool
  ```
  *  On CentOS Stream 9
  ```
    $ sudo dnf group install 'Development Tools'
    $ sudo dnf install ocaml ocaml-ocamlbuild wget rpm-build pkgconf perl-FindBin libtool
  ```
  * On Ubuntu 22.04 and Ubuntu 23.10
  ```
    $ sudo apt-get install build-essential ocaml ocamlbuild wget pkgconf
  ```
 
### Build the Attestation Library for Service TD
* Download the source code of [linux-sgx](https://github.com/intel/linux-sgx) and prepare the submodule [dcap-source](https://github.com/intel/SGXDataCenterAttestationPrimitives) by:
  ```
   $ git clone https://github.com/intel/linux-sgx.git
   $ cd linux-sgx && make servtd_attest_preparation
  ```
* To build the Intel(R) Attestation library for Service TD with default configuration, and enter the following command:
  ```
    $ make servtd_attest
  ```
  You can find the generated Intel(R) Attestation library for Service TD - `libservtd_attest.a` located under `external/dcap_source/QuoteGeneration/quote_wrapper/servtd_attest/linux`.
* To build the Intel(R) Attestation library for Service TD with debug information, enter the following command:
  ```
    $ make servtd_attest DEBUG=1
  ```
* To clean the files, enter the following command:
  ```
    $ make clean
  ```