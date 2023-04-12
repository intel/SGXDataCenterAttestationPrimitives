# Attestation Library For Migration TD
## Overview
This is Attestation Library for Intel(R) Trust Domain Extensions (Intel(R) TDX) module's Live Migration, implemented in C/C++ for reference.   

This README file contains "attestation library for Mig-TD" build instructions.

## How to build
### Prerequisites

* Ensure that you have the following required operation systems: 
  * Red Hat Enterprise Linux Server release 8.5 64bits
  * CentOS Stream 8 64bit
  * Ubuntu* 22.04 LTS Server 64bits
* Use the following commands to install the required tools:
  *  On Red Hat Enterprise Linux 8.5
  ```
    $ sudo yum groupinstall 'Development Tools'
    $ sudo yum install ocaml ocaml-ocamlbuild wget rpm-build pkgconf
  ```
  *  On CentOS Stream 8
  ```
    $ sudo dnf group install 'Development Tools'
    $ sudo dnf --enablerepo=powertools install ocaml ocaml-ocamlbuild wget rpm-build pkgconf
  ```
  * On Ubuntu 22.04
  ```
    $ sudo apt-get install build-essential ocaml ocamlbuild wget pkgconf
  ```
 
### Build the Attestation Library for Migration TD
* Download the source code of [linux-sgx](https://github.com/intel/linux-sgx) and prepare the submodule [dcap-source](https://github.com/intel/SGXDataCenterAttestationPrimitives) by:
  ```
   $ git clone https://github.com/intel/linux-sgx.git
   $ cd linux-sgx && make td_migration_preparation
  ```
* To build the Intel(R) Attestation library for TD Migration with default configration, and enter the following command:
  ```
    $ make td_migraiton
  ```
  You can find the generated Intel(R) Attestation library for TD Migration `libmigtd_attest.a` located under `external/dcap_source/QuoteGeneration/quote_wrapper/td_migration/linux`.
* To build the Intel(R) Attestation library for TD Migration with debug information, enter the following command:
  ```
    $ make td_migraiton DEBUG=1
  ```
* To clean the files, enter the following command:
  ```
    $ make clean
  ```