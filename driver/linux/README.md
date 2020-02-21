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

**Note:** Refer to the *"Intel® SGX Resource Enumeration Leaves"* section in the [Intel SGX Programming reference guide](https://software.intel.com/sites/default/files/managed/48/88/329298-002.pdf) to make sure your cpu has the SGX feature.


### Build the Intel(R) SGX Driver
To build the Intel(R) SGX Driver use the following command line:
```
$ make
```
To clean the build area and remove all the generated and build files use:
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
