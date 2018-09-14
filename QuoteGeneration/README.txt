Intel(R) Software Guard Extensions Data Center Attestation Primitives 
software package
=======================================================

These are the libraries and header files required to build Intel(R) 
Software Guard Extensions (Intel(R) SGX) Data Center Attestation 
Primitives (Intel(R) SGX DCAP) which needs to provide ECDSA quote generaton.

Files:
   
sgx_ql_lib_common.h - Defines the QL library error codes and the data 
     structures needed by the Quote Provider Library for retrieving TCBm 
     and the PCK Cert Chain

sgx_dcap_ql_wrapper.h -  Defines the API prototypes used by Intel(R) SGX DCAP 
     to request quotes from the libsgx_dcap_ql.so library.

libsgx_dcap_ql.so - This provides the ECDSA quoting API's to the Intel(R) SGX 
     DCAP.  It will dynamically link with the libsgx_urts.so and will look
     for PCE and QE files in the current directory.

libsgx_pce.signed.so - The Provisioning Certification Enclave (PCE) used 
     by the quoting library.  The quoting library currenlty expects this 
     file to be located in the current directory.

libsgx_qe3.signed.so - The ECDSA Quoting Enclave (QE) used by the quoting 
     library. The quoting library currenlty expects this file to be 
     located in the current directory.

sgx_report.h - Defines the REPORT data structures used by the libsgx_dcap_ql.so 
     library.  Consumers of the libsgx_dcap_ql.so library will need to include 
     this file.

sgx_key.h - Defines the SVN structures used by the REPORT data structure. 
     Included by sgx_report.h

sgx_attributes.h - Defines the REPORT attributes.  Included by sgx_report.h

sgx_pce.h - Defines the APIs and data structures for the PCE libary. This 
     is not needed by the Intel(R) SGX DCAP but is currenlty required by 
     the sgx_dcap_ql_wrapper.h file.

sgx_defs.h - Defines basic macros used in SGX. Included by sgx_pce.h

sgx_error.h - Defines the error code in SGX. Included by sgx_pce.h

