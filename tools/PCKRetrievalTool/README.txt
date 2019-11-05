Intel(R) Software Guard Extensions Data Center Attestation Primitives (Intel(R) SGX DCAP): PCK ID Retrieval Tool
===============================================


## Prerequisites
- Ensure that you have the following required hardware:
    * 8th Generation Intel(R) Core(TM) Processor or newer with **Flexible Launch Control** support*
    * Intel(R) Atom(TM) Processor with **Flexible Launch Control** support*

For Linux version:
- Please build and install Intel(R) Software Guard Extensions driver for Intel(R) Software Guard Extensions Data Center Attestation Primitives:
    sudo ./sgx_linux_x64_driver.bin
- Please install bellow Debian packages:
    a. libsgx-enclave-common_{version}-{revision}_{arch}.deb
    b. libsgx-dcap-ql_{version}-{revision}_{arch}.deb
- Configure the system with the **Intel(R) SGX hardware enabled** option.

For Windows version:
- Please install Intel(R)_SGX_Windows_SDK_2.x.xxx.xxx and DCAP INF installer,
- Please Install Intel(R)_SGX_Windows_x64_PSW_2.x.xxx.xxx for Windows Server 2016 or 2019 
    


## Usage
 PCKIDRetrievalTool [OPTION]
Example: PCKIDRetrievalTool -f pckid_retrieval_result.csv

Options:
  -f filename       - output the retrieval result to the "filename"
  -?                - show command help
  -h                - show command help
  -help             - show command help

If -f option is not specified, default filename(pckid_retrieval.csv) will be used

## Output file
   the outputed file is CSV format and the values are CSV delimited Base16(HEX):

 EncryptedPPID(384 byte array),PCE_ID (16 bit integer),CPUSVN (16 byte array),PCE ISVSVN (16 bit integer),QE_ID (16 byte array)
   Big Endian                    Little Endian        Big Endian                Little Endian               Big Endian

#Notes:
This tool is used to retrieve the raw PCK data, so  please make sure the quote provider library(dcap_quoteprov.dll for Windows,libdcap_quoteprov.so for Linux) is not in this tool's library search path, otherwise this tool will report error message.
