Intel(R) Software Guard Extensions Data Center Attestation Primitives (Intel(R) SGX DCAP): PCK Cert ID Retrieval Tool
===============================================


## Prerequisites
- Ensure that you have the following required hardware:
    * 8th Generation Intel(R) Core(TM) Processor or newer with **Flexible Launch Control** support*
    * Intel(R) Atom(TM) Processor with **Flexible Launch Control** support*

For Linux version:
- Please build and install Intel(R) Software Guard Extensions driver for Intel(R) Software Guard Extensions Data Center Attestation Primitives:
    sudo ./sgx_linux_x64_driver.bin
- Please install bellow Debian or RPM packages, you can download it from [01.org](https://01.org/intel-software-guard-extensions/downloads)
    a. libsgx-enclave-common_{version}-{revision}_{arch}.deb or libsgx-enclave-common_{version}-{revision}_{arch}.rpm
    b. libsgx-dcap-ql_{version}-{revision}_{arch}.deb or libsgx-dcap-ql_{version}-{revision}_{arch}.rpm
- If this tool is used on multi-package platform:
    a. please install  libsgx-ra-uefi_{version}-{revision}_{arch}.deb or libsgx-ra-uefi_{version}-{revision}_{arch}.rpm
- Configure the system with the **Intel(R) SGX hardware enabled** option.

For Windows version:
- Please install DCAP INF installer
- Please Install Intel(R)_SGX_Windows_x64_PSW_2.x.xxx.xxx for Windows Server 2016 or 2019
- If this tool is used on multi-package platform:  Please install INF installer: sgx_mpa_{version}
    


## Usage
PCKIDRetrievalTool [OPTION]
Example: PCKIDRetrievalTool -f retrieval_result.csv -url https://localhost:8081 -user_token 123456 -use_secure_cert true

Options:
  -f filename                       - output the retrieval result to the "filename"
  -url cache_server_address         - cache server's address 
  -user_token token_string          - user token to access the cache server 
  -proxy_type proxy_type            - proxy setting when access the cache server 
  -proxy_url  proxy_server_address  - proxy server's address 
  -use_secure_cert [true | false]   - accept secure/insecure https cert,default value is true
  -?                                - show command help
  -h                                - show command help
  -help                             - show command help

If option is not specified, it will write the retrieved data to file: pckid_retrieval.csv


user can also use the configuration file(network_configuration.conf) to configure these options, but
command line option has higher priority.

## Output file
If the retrieved data is saved to file:
   the outputed file is CSV format and the values are CSV delimited Base16(HEX):

 EncryptedPPID(384 byte array),PCE_ID (16 bit integer),CPUSVN (16 byte array),PCE ISVSVN (16 bit integer),QE_ID (16 byte array)[,PLATFORM_MANIFEST (28221 byte array)]
   Big Endian                    Little Endian        Big Endian                Little Endian               Big Endian                    Big Endian

And the retrieved data can also be uploaded to cache server if user provide the cache server's url and access token.

#Notes:
