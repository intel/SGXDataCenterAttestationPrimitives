Intel(R) Software Guard Extensions Data Center Attestation Primitives
================================================

Introduction
-------
Intel(R) Software Guard Extensions (Intel(R) SGX) Data Center Attestation Primitives (Intel(R) SGX DCAP) provides SGX attestation support targeted for data centers, cloud services providers and enterprises. This attestation model leverages Elliptic Curve Digital Signature algorithm (ECDSA) versus the current client based SGX attestation model which is EPID based (Enhanced Privacy Identification).

License
-------
This project is BSD license. See [License.txt](License.txt)

But Linux driver code is dual licensed under BSD/GPL v2. See [License.txt](driver/linux/License.txt)

Third-party code is also used in this project. See [ThirdPartyLicenses.txt](QuoteGeneration/ThirdPartyLicenses.txt), [ThirdPartyLicenses.txt](QuoteVerification/ThirdPartyLicenses.txt) and [ThirdPartyLicenses.txt](driver/win/ThirdPartyLicenses.txt) for details.

Contributing
-------
See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

Instruction
-------
## Build and Install Intel(R) SGX Driver
**Windows* OS**:    
    You can open the Micrsoft Visual Studio* solution under [Windows driver](driver/win) folder to trigger a build and then follow the instructions in the [Driver Install Guide.txt](driver/win/Driver%20Install%20Guide.txt) to install the Intel(R) SGX driver for Windows.  
**Linux* OS**:    
    A [README.md](driver/linux/README.md) is provided under [Linux driver](driver/linux) folder. Please follow the instructions in the `README.md` to build and install Intel(R) SGX driver.

## Build and Install Intel(R) SGX DCAP Quote Generation Library
A [README.md](QuoteGeneration/README.md) is provided under [QuoteGeneration](QuoteGeneration) folder. Please follow the instructions in the `README.md` to build and install Intel(R) SGX DCAP Quote Generation Library.

## Build and Install Intel(R) SGX DCAP Quote Verification Library for Linux* OS
A [README.md](QuoteVerification/README.md) is provided under [QuoteVerification](QuoteVerification) folder. Please follow the instructions in the `README.md` to build and install Intel(R) SGX DCAP Quote Verification Library.

