Intel(R) Software Guard Extensions Data Center Attestation Primitives (Intel(R) SGX DCAP) Quote Verification Enclave SampleCode
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
* Intel(R) SGX SDK
* Intel(R) SGX PSW
* Intel(R) SGX DCAP Driver
* Intel(R) SGX DCAP Provisioning Certificate Caching Service
* Intel(R) SGX Quote Verification Library (dcap_quoteverify.so)
* Intel(R) SGX Quote Verification Enclave (libsgx_qve.signed.so)

### Generate a quote with cetification data of type 5 using QuoteGenerationSample and copy it to sampleData directory:
````
$ cd dcap_source/SampleCode/QuoteGenerationSample/
$ make
$ ./app
$ cp quote.dat ../../QuoteVerification/sampleData/
````

### Build Sample application and Sample ISV enclave (report will be targeted for this enclave), and verify a given quote: 
````
$ cd dcap_source/QuoteVerification/SampleISVEnclave/
$ make
$ ./app -quote </path/to/quote.dat[default=../sampleData/quote.dat]>
````

## Windows
Supported operating systems:
   * Windows* Server 2016 (Long-Term Servicing Channel)
   * Windows* Server 2019 (Long-Term Servicing Channel)

Requirements:
* Microsoft Visual Studio 2015 or newer.
* 7-Zip
* Perl
* NASM (Netwide Assembler)

Pre-requisets:
* Intel(R) SGX SDK
* Intel(R) SGX PSW
* Intel(R) SGX DCAP Driver
* Intel(R) SGX DCAP Provisioning Certificate Caching Service
* Intel(R) SGX Quote Verification Library (dcap_quoteverify.dll)
* Intel(R) SGX Quote Verification Enclave (qve.signed.dll)

### Generate a quote with cetification data of type 5 using QuoteGenerationSample and copy it to sampleData directory:
###### Follow instructions in dcap_source\SampleCode\QuoteGenerationSample\README.txt to build and generate a quote.dat file.
###### Copy quote.dat to dcap_source\QuoteVerification\sampleData\

### Verify generated quote:
###### In dcap_source\QuoteVerification\SampleISVEnclave directory, open SampleISVEnclave.sln using Visual studio, build and execute it. This will verify the quote located in ../../../sampleData or provided by -quote arg.


