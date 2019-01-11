Intel(R) Software Guard Extensions Data Center Attestation Primitives 
software package
=======================================================

These are the libraries and header files required to build Intel(R) 
Software Guard Extensions (Intel(R) SGX) Data Center Attestation 
Primitives (Intel(R) SGX DCAP) which needs to provide ECDSA quote generaton.

Header Files:
-------------
sgx_ql_lib_common.h - Defines the QL library error codes and the data 
     structures needed by the Quote Provider Library for retrieving TCBm 
     and the PCK Cert Chain

sgx_dcap_ql_wrapper.h -  Defines the API prototypes used by Intel(R) SGX 
     DCAP to request quotes from the sgx_dcap_ql.dll for Windows* OS and 
     libsgx_dcap_ql.so for Linux* OS 

sgx_report.h - Defines the REPORT data structures used by the sgx_dcap_ql.dll
     for Windows* OS and libsgx_dcap_ql.so from Linux* OS. Consumers of 
     the sgx_dcap_ql.dll for Windows* OS and libsgx_dcap_ql.so for Linux* OS 
     will need to include this file.

sgx_key.h - Defines the SVN structures used by the REPORT data structure. 
     Included by sgx_report.h

sgx_attributes.h - Defines the REPORT attributes.  Included by sgx_report.h

sgx_pce.h - Defines the APIs and data structures for the PCE libary. This 
     is not needed by the Intel(R) SGX DCAP but is currenlty required by 
     the sgx_dcap_ql_wrapper.h file.

sgx_defs.h - Defines basic macros used in SGX. Included by sgx_pce.h

sgx_error.h - Defines the error code in SGX. Included by sgx_pce.h	 

Libraries:
----------
sgx_dcap_ql.dll for Windows* OS, libsgx_dcap_ql.so for Linux* OS: 
     This provides the ECDSA quoting API's to the Intel(R) SGX DCAP.  
     It will dynamically link with uRTS and will look for PCE and QE files 
     in the current directory.

pce.signed.dll for Windows* OS, libsgx_pce.signed.so for Linux* OS:
     The Provisioning Certification Enclave (PCE) used by the quoting library. 
     The quoting library currenlty expects this file to be located in the 
     current directory.

qe3.signed.dll for Windows* OS, libsgx_qe3.signed.so for Linux* OS:
     The ECDSA Quoting Enclave (QE) used by the quoting library. The quoting 
     library currenlty expects this file to be located in the current directory.

sgx_dcap_ql.lib for Windows* OS:
     This contains a list of the exported functions and data information 
     for sgx_dcap_ql.dll.
