
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

Change Log
----------
### V1.36
- Sync with upstream patch v36, rebased for kernel release 5.8.
### V1.35
- Sync with upstream patch v32, mostly stability fixes, documentation improvement, code re-org.
### V1.34
- Fix build for RHEL 8.2
### V1.33
- Fix incorrect usage of X86_FEATURE_SGX1 which is not supported by current kernel
### V1.32
- Port the upstream candidate patch version 28.
- Impact to [installation](#install):
  * The device nodes are moved to /dev/sgx/enclave, /dev/sgx/provision
  * The udev rules are updated to match sgx device nodes in "misc" subsystem.
  * To load the driver on boot, the driver need be added to the auto-load list, e.g., /etc/modules.
- Impact to user space code:
  * One fd to /dev/sgx/enclave should be opened for each enclave.
  * Source and target address/offset passed to EADD ioctl should be page aligned
  * Page permissions are capped by the EPCM permissions(flags in secinfo) specified during EADD ioctl. Subsequent mprotect/mmap calls can not add more permissions.
  * The application hosting enclaves can not have executable stack, i.e., use -z noexecstack linker flag.
- **Note**: Intel(R) SGX PSW 2.9+ release and DCAP 1.6+ release are compatible with these changes.

### V1.22
- Exposed a new device for provisioning control: /dev/sgx_prv. This requires udev rules and user group "sgx_prv" to set proper permissions. See [installation section](#install) for details.
- Added a new ioctl SET_ATTRIBUTE. Apps loading provisioning enclave need to call this ioctl before INIT_ENCLAVE ioctl. 
- Added instructions for RHEL 8.
- Removed in-kernel Launch Enclave.
- Changed Makefile to fail the build on an SGX enabled kernel. This driver can't co-exist with in-kernel driver.
- Minor bug fixes



Build and Install the Intel(R) SGX Driver
-----------------------------------------
### Prerequisites
- Ensure that you have the following required operating systems:
  * Ubuntu* 16.04 LTS Desktop 64bits - minimal kernel 4.15
  * Ubuntu* 16.04 LTS Server 64bits - minimal kernel 4.15
  * Ubuntu* 18.04 LTS Desktop 64bits
  * Ubuntu* 18.04 LTS Server 64bits
  * Red Hat Enterprise Linux Server 8 (RHEL 8) 64bits
  * CentOS 8 64bits
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


### Build
To build the Intel(R) SGX Driver use the following command line:
```
$ make
```
To clean the build area and remove all the generated and build files use:
```
$ make clean
```
### Install
The Intel(R) SGX driver supports DKMS installation, to install the driver follow the following steps:
- Ensure that the DKMS package is installed, or install it using:
  ```$ sudo apt-get install dkms ```
- With root priviledge, copy the sources to `/usr/src/sgx-<version>/`
	- `<version>` should match the version specified in the dkms.conf file
- Follow the following steps to add and install the driver into the DKMS tree:
```
$ sudo dkms add -m sgx -v <version>
$ sudo dkms build -m sgx -v <version>
$ sudo dkms install -m sgx -v <version>
$ sudo /sbin/modprobe intel_sgx
```

- Add udev rules and sgx_prv group to properly set permissions of the /dev/sgx/enclave and /dev/sgx/provision nodes, more [background below](#launching-an-enclave-with-provision-bit-set).

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
$ sudo dracut --force   # only needed on RHEL/CentOS 8
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
crw-rw-rw- root root      /dev/sgx/enclave
crw-rw---- root sgx_prv   /dev/sgx/provision
```
**Note:** The driver installer [BIN file provided by Intel(R)](https://01.org/intel-software-guard-extensions/downloads) automatically copy the udev rules and run ``udevadm trigger`` to activate the rules so that the permissions are set as above.

This configuration enables every user to launch an enclave, but only members of the sgx_prv group are allowed to launch an enclave with provision bit set.
Failing to set these permissions may prevent processes that are not running under root privilege from launching a provisioning enclave.

### Process Permissions and Flow
As mentioned above, Intel(R) provisioning enclaves are signed with Intel(R) owned keys that will enable them to get launched unconditionally.
A process that launches other provisioning enclaves is required to use the SET_ATTRIBUTE IOCTL before the INIT_ENCLAVE IOCTL to notify the driver that the enclave being launched requires provision key access.
The SET_ATTRIBUTE IOCTL input is a file handle to /dev/sgx/provision, which will fail to open if the process doesn't have the required permission.
To summarize, the following flow is required by the platform admin and a process that require provision key access:
 - Software installation flow:
	- Add the user running the process to the `sgx_prv` group:
    ```
    $ sudo usermod -a -G sgx_prv <user name>
    ```
 - Enclave launch flow:
	 - Create the enclave
	 - Open handle to /dev/sgx/provision
	 - Call SET_ATTRIBUTE with the handle as a parameter
	 - Add pages and initialize the enclave

**Note:** The Enclave Common Loader library is following the above flow and launching enclave based on it, failure to grant correct access to the launching process will cause a failure in the enclave initialization.

Compatibility with Intel(R) SGX PSW releases
----------------------------------------------
This table lists the equivalent upstream kernel patch for each version of the driver and summarizes compatibility between driver versions and PSW releases. 

  
| Driver version | Equivalent kernel patch | PSW 2.7 | PSW 2.8 | PSW 2.9/2.9.1 |PSW 2.10 |
| -------------- | ------------------------| ------- | ------- | ------------- |-------- |
| 1.21           | N/A                     | YES     | YES     | YES           | YES     |   
| 1.22           | V14(approximate)        | NO      | YES     | YES           | YES     |
| 1.32/1.33      | V28                     | NO      | NO\*    | YES           | YES     |
| 1.34           | V29                     | NO      | NO      | NO            | YES     |
| 1.35           | V32                     | NO      | NO      | NO            | YES     |
| 1.36           | V36                     | NO      | NO      | NO            | YES     |

\* Requires updated [udev rules](./10-sgx.rules)

Monitoring (Proposal)
-----------------------------------------------

### Export stats to user space via sysfs

The driver built with a compile time flag, CONFIG_SGX_STATS, exports following sysfs files.

```
* /sys/kernel/sgx: (global stats)
	- free_epc_pages
	- accumulative_swapped_out_epc_pages
	- accumulative_swapped_in_epc_pages
	* /sys/kernel/sgx/<pid> (per process stats)
		* /sys/kernel/sgx/<pid>/<fd> (per enclave stats)
			- enclave_resident_size = pages loaded in EPC
			- enclave_epc_size = EPC pages EADDed (and EAUGed with EDMM implemented) - EREMOVED = resident + swapped out pages
			- enclave_elrange_size = enclave->secs->size in pages
			- enclave_accumulative_swapped_out_epc_pages
			- enclave_accumulative_swapped_in_epc_pages
```

### Design considerations

- Monitoring is not yet considered in upstream patches. To avoid divergence with future kernel implementation, we only enable this feature for driver build with the compiler flag CONFIG_SGX_STATS turned on.
- These changes may overlap/interact with upstreaming sgx cgroups implementation, likely in following areas
  * Global stats likely are covered by cgroups, accessible from cgroups fs. We may drop them when sgx cgroups is implemented. 
  * Implementation code of per enclave stats will overlap with sgx cgroups implementation. But cgroups fs will less likely expose these stats.
  * Current Intel cgroups candidate patches: https://github.com/intel/kvm-sgx/releases/tag/sgx-v5.8.0-rc4-r3
- Future kernel may have [statsfs implementation](https://lwn.net/Articles/818710/) and the per enclave stats proposed here may be implemented with statsfs.
- All leaf files are read-only sysfs files, each containing one value in ASCII characters. 
- User space open those files to read corresponding values out, and calculate additional values if needed, such as:
  * current pages swapped out per enclave = enclave_epc_size – enclave_resident_size
  * total resident for $pid = sum of all enclave_resident_size under /sys/kernel/sgx/$pid
- The stats only account enclave fd under PID of the host process that initially opened an fd to /dev/sgx/enclave
  * If a process send the open fd to another process (via socket or forking a child) to share the enclave, the target process pid won't be added under /sys/kernel/sgx folder. 
- Following global stats are not exposed 
  * EPC usage for va pages, for current implementation it can be calculated from ceil(enclave_epc_size/512).
  * Total EPC size, can be obtained from cpuid
  

