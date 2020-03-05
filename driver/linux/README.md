Intel(R) Software Guard Extensions for Linux\* OS
================================================

# SGX Linux Driver for Intel(R) SGX DCAP

Introduction
------------
This Intel(R) SGX driver package is for Intel(R) SGX DCAP and is derived from the upstream version of the SGX driver.


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
  * Red Hat Enterprise Linux Server 8 (RHEL 8) 64bits
- Ensure that you have the following required hardware:
  * 8th Generation Intel(R) Core(TM) Processor or newer with **Flexible Launch Control** and **Intel(R) AES New Instructions** support*
  * Intel(R) Atom(TM) Processor with **Flexible Launch Control** and **Intel(R) AES New Instructions** support*
- Configure the system with the **SGX hardware enabled** option.
- Ensure that the version of installed kernel headers matches the active kernel version on the system.
  * On Ubuntu
     * To check if matching kernel headers are installed:
        ```
        $ dpkg-query -s linux-headers-$(uname -r)
        ```
     * To install matching headers:
        ```
        $ sudo apt-get install linux-headers-$(uname -r)
        ```
  * On RHEL 8
     * To check if matching kernel headers are installed:
        ```
        $ ls /usr/src/kernels/$(uname -r)
        ``` 
     * To install matching headers:
        ```
        $ sudo yum install kernel-devel
        ```
     * After the above command, if the matching headers are still missing in /usr/src/kernels, try update kernel and reboot using commands below. Then choose updated kernel on boot menu.
        ```
        $ sudo yum install kernel
        $ sudo reboot
        ```
     * Additional packages need be installed:
        ```
        $ sudo yum install -y elfutils-libelf-devel
        $ sudo yum groupinstall 'Development Tools'
        ```
     * To enable DKMS, setup [EPEL repo](https://fedoraproject.org/wiki/EPEL) and install DKMS package:
        ```
        $ sudo yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
        $ sudo yum install -y dkms
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

- Add udev rules and sgx_prv group to properly set permissions of the sgx and sgx_prv device nodes, more [background below](#launching-an-enclave-with-provision-bit-set).

```
$ sudo cp  10-sgx.rules /etc/udev/rules.d
$ sudo groupadd sgx_prv
$ sudo udevadm trigger
```

### Uninstall the Intel(R) SGX Driver

```
$ sudo /sbin/modprobe -r intel_sgx
$ sudo dkms remove -m sgx -v <version> --all
$ sudo rm -rf /usr/src/sgx-<version>
```
You should also remove the udev rules and sgx_prv user group.

Launching an Enclave with Provision Bit Set
-------------------------------------------
### Background
An enclave may set the provision bit in its attributes to be able to request provision key. Acquiring provision key may have privacy implications and should be limited. Such enclaves are referred to as provisioning enclaves below.

The current Intel(R) SGX driver allows Intel(R)’s provisioning enclaves to be launched with provision bit set without any additional permissions. But, for 3rd party signed provisioning enclaves, the platform owner (administrator) must modify the permissions of the process loading the provisioning enclaves as described below.

### Driver Settings
The Intel(R) SGX driver installation process described above creates 2 new devices on the platform, and setup these devices with the following permissions:
```
crw-rw-rw- root root /dev/sgx
crw-rw---- sgx_prv sgx_prv /dev/sgx_prv
```
**Note:** The driver installer [BIN file provided by Intel(R)](https://01.org/intel-software-guard-extensions/downloads) automatically copy the udev rules and run ``udevadm trigger`` to activate the rules so that the permissions are set as above.

This configuration enables every user to launch an enclave, but only members of the sgx_prv group are allowed to launch an enclave with provision bit set.
Failing to set these permissions may prevent processes that are not running under root privilege from launching a provisioning enclave.

### Process Permissions and Flow
As mentioned above, Intel(R) provisioning enclaves are signed with Intel(R) owned keys that will enable them to get launched unconditionally.
A process that launches other provisioning enclaves is required to use the SET_ATTRIBUTE IOCTL before the INIT_ENCLAVE IOCTL to notify the driver that the enclave being launched requires provision key access.
The SET_ATTRIBUTE IOCTL input is a file handle to /dev/sgx_prv, which will fail to open if the process doesn't have the required permission.
To summarize, the following flow is required by the platform admin and a process that require provision key access:
 - Software installation flow:
	- Add the user running the process to the `sgx_prv` group:
    ```
    $ sudo usermod -a -G sgx_prv <user name>
    ```
 - Enclave launch flow:
	 - Create the enclave
	 - Open handle to /dev/sgx_prv
	 - Call SET_ATTRIBUTE with the handle as a parameter
	 - Add pages and initialize the enclave

**Note:** The Enclave Common Loader library is following the above flow and launching enclave based on it, failure to grant correct access to the launching process will cause a failure in the enclave initialization.
