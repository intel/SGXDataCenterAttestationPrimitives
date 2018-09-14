Intel(R) Software Guard Extensions Data Center Attestation Primitives for Linux\* OS
================================================

Introduction
-------
Intel(R) Software Guard Extensions (Intel(R) SGX) Data Center Attestation Primitives (Intel(R) SGX DCAP) provides SGX attestation support targeted for data centers, cloud services providers and enterprises. This attestation model leverages Elliptic Curve Digital Signature algorithm (ECDSA) versus the current client based SGX attestation model which is EPID based (Enhanced Privacy Identification).

License
-------
This project is BSD license. See [License.txt](License.txt)

But driver code is licensed under GPL v2. See [License.txt](driver/License.txt) 

Third-party code is also used in this project. See [ThirdPartyLicenses.txt](QuoteGeneration/ThirdPartyLicenses.txt) and [ThirdPartyLicenses.txt](QuoteVerification/ThirdPartyLicenses.txt) for details.

Contributing
-------
See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

Instruction
-------
## Build and Install Intel(R) SGX Driver
A [README.md](driver/README.md) is provided under [driver](driver) folder. Please follow the instructions in the `README.md` to build and install Intel(R) SGX driver.

## Build and Install Intel(R) SGX DCAP Quote Generation Library
A [README.md](QuoteGeneration/README.md) is provided under [QuoteGeneration](QuoteGeneration) folder. Please follow the instructions in the `README.md` to build and install Intel(R) SGX DCAP Quote Generation Library.

## Build and Install Intel(R) SGX DCAP Quote Verification Library
A [README.md](QuoteVerification/README.md) is provided under [QuoteVerification](QuoteVerification) folder. Please follow the instructions in the `README.md` to build and install Intel(R) SGX DCAP Quote Verification Library.

