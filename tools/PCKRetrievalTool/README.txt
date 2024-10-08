Intel(R) Software Guard Extensions Data Center Attestation Primitives (Intel(R) SGX DCAP): PCK Cert ID Retrieval Tool
===============================================

## Prerequisites
- Ensure that you have the following required hardware:
    * 8th Generation Intel(R) Core(TM) Processor or newer with **Flexible Launch Control** support*
    * Intel(R) Atom(TM) Processor with **Flexible Launch Control** support*

- Configure the system with the **Intel(R) SGX hardware enabled** option.

For Linux version:
- Now this tool supports two modes: 
    a. enclave mode: it means that to retrieve the platform's information, enclave load is needed. Thus in this mode, the following requirements are needed.
        - Please install Intel(R) Software Guard Extensions driver for Intel(R) Software Guard Extensions Data Center Attestation Primitives:
             sudo ./sgx_linux_x64_driver.bin
          or you can use Linux kernel 5.11 or higher version kernel 
        - Please install these Debian or RPM packages, you can download it from [download.01.org](https://download.01.org/intel-sgx/latest/linux-latest/distro/)
             a. libsgx-enclave-common_{version}-{revision}_{arch}.deb or libsgx-enclave-common-{version}-{revision}_{arch}.rpm
             b. libsgx-urts_{version}-{revision}_{arch}.deb or libsgx-urts-{version}-{revision}_{arch}.rpm
             c. libsgx-ae-pce_{version}-{revision}_{arch}.deb or libsgx-ae-pce-{version}-{revision}_{arch}.rpm
             d. libsgx-ae-id-enclave_{version}-{revision}_{arch}.deb or libsgx-ae-id-enclave-{version}-{revision}_{arch}.rpm
    b. non-enclave mode: in this mode, this tool is used to retrieve the platform manifest for multi-package. command line: -platform_id is used, and 
                         user need provide the platform_id.
- If this tool is used on multi-package platform:
    a. please install  libsgx-ra-uefi_{version}-{revision}_{arch}.deb or libsgx-ra-uefi_{version}-{revision}_{arch}.rpm

For Windows version:
- Now this tool supports two modes: 
    a. enclave mode: it means that to retrieve the platform's information, enclave load is needed. Thus in this mode, the following requirements are needed.
        - If your platform is connected with internet, you don't need to do anything, otherwise you need to install SGX base driver manually.
    b. non-enclave mode: in this mode, this tool is used to retrieve the platform manifest for multi-package. command line: -platform_id is used, and 
                         user need provide the platform_id.
- If this tool is used on multi-package platform:  Please install INF installer: sgx_mpa_{version}

## Usage
PCKIDRetrievalTool [OPTION]
Example: PCKIDRetrievalTool -f retrieval_result.csv -url https://localhost:8081 -user_token 123456 -use_secure_cert true

Options:
  -f filename                          - output the retrieval result to the "filename"
  -url cache_server_address            - cache server's address 
  -user_token token_string             - user token to access the cache server 
  -proxy_type proxy_type               - proxy setting when access the cache server 
  -proxy_url  proxy_server_address     - proxy server's address 
  -use_secure_cert {true | false}      - accept secure/insecure https cert,default value is true
  -tcb_update_type {stardard,early,all}  - update type for tcb material,default value is stardard
  -platform_id \"platform_id_string\"  - in this mode, enclave is not needed to load, but platform id need to input
  -?                                   - show command help
  -h                                   - show command help
  -help                                - show command help

If option is not specified, it will write the retrieved data to file: pckid_retrieval.csv

user can also use the configuration file(network_setting.conf) to configure these options, but
command line option has higher priority.

## Output file
If the retrieved data is saved to file:
   the outputed file is CSV format and the values are CSV delimited Base16(HEX):

in enclave mode:
 EncryptedPPID(384 byte array),PCE_ID (16 bit integer),CPUSVN (16 byte array),PCE ISVSVN (16 bit integer),QE_ID (16 byte array)[,PLATFORM_MANIFEST (variable length byte array)]
   Big Endian                    Little Endian        Big Endian                Little Endian               Big Endian                    Big Endian

in non-enclave mode:
 ,PCE_ID (16 bit integer),,,PLATFORM_ID (variable length byte array),PLATFORM_MANIFEST (variable length byte array)
     Little Endian                  Big Endian                                 Big Endian

And the retrieved data can also be uploaded to cache server if user provide the cache server's url and access token.

#Notes:
  1. If you are using DCAP driver 1.41 or higher version to drive SGX, 
     you need run this tool with root permission or add your account to sgx_prv group like: 
       $ sudo usermod -a -G sgx_prv <user name>
  2. If you are using Linux Kernel 5.11 or higher version to drive SGX, 
     you need run this tool with root permission or add your account to sgx_prv group like:
       $ sudo usermod -a -G sgx_prv <user name>
  3. If you are using this tool in Ubuntu 20.04, please execute the following command:
       $ sudo mount -o remount,exec /dev

