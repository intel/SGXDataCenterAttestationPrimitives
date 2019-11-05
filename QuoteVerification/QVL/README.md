Intel(R) Software Guard Extensions Data Center Attestation Primitives for Linux\* OS
================================================

# Intel(R) Software Guard Extensions Quote Verification Library
## SGX Quote Verification Library

Reference implementation of QUOTE verification in SGX ECDSA model.

This library is an interface encapsulating all the processing involved in ECDSA Quote verification.
It requires providing Intel-issued PCK Certificate, PCK Revocation List and TCB Information corresponding to the platform that is attested.
Library is exposed via C-like API and is implemented in a thread-safe-manner to enable simultaneous Quote verifications by the Attestation Service.

## SGX QVL Sample App
This repository contains also a sample application meant to present the way dynamic-link QVL application is implemented.
Sample Application can be used to perform quote verification using QVL.

## Build
Currently only unix like system are supported out of the box.
Requirements:

* cmake version 3.2 or higher
* make
* clang++ with c++11 support (5.0.2 or higher is recommended)
* doxygen version 1.8.14 if BUILD_DOCS is enabled
* gcc to compile dependant openssl
* bash shell
* due to self contained third parties, ~230MB disk space is required for full build - debug, release, tests and doc

Additional libraries will be downloaded from official, public repositories and compiled during first build:

* openssl v1.1.1 -  http://www.openssl.org/source/openssl-1.1.1.tar.gz (AttestationLibrary dependency)
* googletest - https://github.com/google/googletest/archive/release-1.8.0.tar.gz (Tests dependency)


See build scripts (release, debug) to set options:

| Option | Description | Default |
| ----- | ----- | :-----: |
| BUILD_ATTESTATION_LIBRARY | Enable/Disable building of the library files | ON |
| BUILD_ATTESTATION_APP | Enable/Disable building of the sample app | ON |
| BUILD_TESTS | Enable/Disable building of the unit and integration tests | ON |
| BUILD_DOCS | Enable/Disable building of the doxygen based documentation | OFF |


### Build in release:
````
$ cd Src
$ ./release
````

Binaries to be found in `Src/Build/Release/dist`

### Build in debug:

````
$ cd Src
$ ./debug
````

Binaries to be found in `Src/Build/Debug/dist`

### Run unit tests:

````
$ cd Src
$ ./runUT
````

### Run code coverage analysis
(requires Bullseye to be installed on the system)

Default Bullseye install location is `/opt/bullseye`, but you can specify a different one using a '-b' option:

````
$ cd Src
$ ./coverage [-b custom/bullseye/location]
````

## Run SGX QVL Sample App
After build sample app can be found in `Src/Build/Release/dist/bin` for release or `Src/Build/Debug/dist/bin` for debug.

To see usage run following:

````
$ LD_LIBRARY_PATH=../lib ./AttestationApp --help
````
### Provided sample data
Build includes sample data for SGX QVL Sample App in `Src/Build/Debug/dist/bin/sampleData` directory. All files use default names so they will be loaded by app without any parameters. In sampleData directory run:
```
LD_LIBRARY_PATH=../../lib ../AttestationApp
```
## Clion setup
To use the project in Clion it is necessary to set Clang as a compiler. This is done in *File->Settings->Build, Execution, Deployment->CMake* menu by adding `-DCMAKE_CXX_COMPILER=clang++` to *CMake options*.
