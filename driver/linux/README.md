Intel(R) Software Guard Extensions for Linux\* OS
================================================

# SGX Linux Driver with Launch Enclave(LE) for Intel(R) SGX DCAP

Introduction
------------
This Intel(R) SGX driver package is for Intel(R) SGX DCAP and is derived from the upstream version of the SGX driver, including the in-driver Launch Enclave.


Documentation
-------------
- [Intel(R) SGX for Linux\* OS](https://01.org/intel-softwareguard-extensions) project home page on [01.org](http://01.org)
- [Intel(R) SGX Programming Reference](https://software.intel.com/sites/default/files/managed/48/88/329298-002.pdf)


Build and Install the Intel(R) SGX Driver
-----------------------------------------
### Prerequisites         
- Ensure that you have the following required operating systems:  
  * Ubuntu* 16.04 LTS Desktop 64bits - minimal kernel 4.10
  * Ubuntu* 16.04 LTS Server 64bits - minimal kernel 4.10
  * Ubuntu* 18.04 LTS Desktop 64bits
  * Ubuntu* 18.04 LTS Server 64bits
- Ensure that you have the following required hardware:  
  * 8th Generation Intel(R) Core(TM) Processor or newer with **Flexible Launch Control** and **Intel(R) AES New Instructions** support*
  * Intel(R) Atom(TM) Processor with **Flexible Launch Control** and **Intel(R) AES New Instructions** support*
- Configure the system with the **SGX hardware enabled** option.
- Ensure that the version of installed kernel headers matches the active kernel version on the system.
   * To check if matching kernel headers are installed:
        ```
        $ dpkg-query -s linux-headers-$(uname -r)
        ```
   * To install matching headers:
        ```
        $ sudo apt-get install linux-headers-$(uname -r)
        ```
- OpenSSL is required for the Launch Enclave signing.
   * To install OpenSSl:
 		```
        $ sudo apt-get install libssl-dev
        ```
  
**Note:** Refer to the *"Intel® SGX Resource Enumeration Leaves"* section in the [Intel SGX Programming reference guide](https://software.intel.com/sites/default/files/managed/48/88/329298-002.pdf) to make sure your cpu has the SGX feature.


### Build the Intel(R) SGX Driver 
The driver build process is also building and integrating the Launch Enclave as part of the build process.
As the Launch Enclave must be signed, the driver build process supports two methods of build:
- Single step / debug:     
  In this method the LE is built and signed as part of the driver build process, the private key may be provided to the build command or auto-generated during the build
- Two steps / production:      
  In this method the first step builds the Launch Enclave and generates the signing materials, which should be signed by some signing entity separately. In the second step the signature and the public key are used to continue the build and generate the driver.

These build options are provided to support the above two build methods:
- sign:     
   Build option for the single step build process. It builds the Launch Enclave, signs it and integrate it into the driver. The private key may be provided to the build command by specifying ```SGX_LE_SIGNING_KEY_PATH=<path/to/private/key>``` (default: ./sgx_signing_key.pem), if the key does not exist it will be generated.
- gendata:     
   Build option for the first step in the two steps process. It builds the Launch Enclave and prepared the signing materials for it. The output of the build may be defined by specifying ```SGX_LE_SIGNING_MATERIAL=<path/to/signing/material>``` (default: ./signing_material.bin).
- usesig:    
   Build option for the second step in the two steps process. It gets the signature file and the public key, and uses them to integrate with the driver build. 
   The signature file **must** be provided by specifying ```SIG_FILE=<path/to/signature>```.  
   In addition the public key file may be specified by using ```SGX_LE_PUBLIC_KEY_PATH=<path/to/public/key>``` (default: ./sgx_public_key.pem).

#### Build Intel(R) SGX Driver Using Single Step Process

The following is an example for a single step make command:
```
$ make sign SGX_LE_SIGNING_KEY_PATH=~/my_private_key.pem 
```
**Note:** The **SGX_LE_SIGNING_KEY_PATH** is NOT a mandatory parameter. 

#### Build Intel(R) SGX Driver Using Two Steps Process
The following lines are an example for two steps make process:
```
$ make gendata SGX_LE_SIGNING_MATERIAL=~/signing_material.bin
$ [sign the generated signing material]
$ make usesig SIG_FILE=~/signature_file.bin SGX_LE_PUBLIC_KEY_PATH=~/my_public_key.pem
```
**Note:**  The **SGX_LE_SIGNING_MATERIAL** and **SGX_LE_PUBLIC_KEY_PATH** are NOT mandatory parameters.  
**Note:**  To generate "Intel signed" compatible sigstruct file, add **INTEL_SIGNED=1** for each of the make commands.  

#### Build Intel(R) SGX Driver using a pre-built Permissive LE  
The Permissive LE (PLE) includes two headers representing the binary content of the PLE (sgx_le_blob.h) and the sigstruct (sgx_le_ss.h) located in the ```driver/le/enclave``` directory.  
If these files exist, the PLE will not be built and they will be integrated into the driver build. Use a single step make command to complete the driver build and integrate the PLE into it:
```
$ make 
```

**Note:** To ensure execution of the PLE build when **NOT** using pre-built PLE, clean all the previously built content before any other build command:
```
$ make clean
``` 

### Install the Intel(R) SGX Driver
The Intel(R) SGX driver supports DKMS installation, to install the driver follow the following steps:  
- Ensure that the DKMS package is installed, or install it using:
  ``` $ sudo apt-get install dkms  ```
- With root priviledge, copy the sources to ``/usr/src/sgx-<version>/`` 
	- ``<version>`` should match the version specified in the dkms.conf file 
- Follow the following steps to add and install the driver into the DKMS tree:
```
$ sudo dkms add -m sgx -v <version>
$ sudo dkms build -m sgx -v <version>
$ sudo dkms install -m sgx -v <version>
$ sudo /sbin/modprobe intel_sgx
```
### Uninstall the Intel(R) SGX Driver
To uninstall the Intel(R) SGX driver, enter the following commands with root privilege: 
```
$ sudo /sbin/modprobe -r intel_sgx
$ sudo dkms remove -m sgx -v <version> --all
```
You should also remove the sources from ``/usr/src/sgx-<version>/``
