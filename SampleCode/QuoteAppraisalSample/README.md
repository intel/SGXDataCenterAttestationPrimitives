Intel(R) Software Guard Extensions Data Center Attestation Primitives (Intel(R) SGX DCAP) Quote Appraisal SampleCode
================================================

Requirements:
* make
* gcc
* g++
* bash shell

Prerequisite:
* Intel(R) SGX DCAP Driver
* Intel(R) SGX SDK
* Intel(R) SGX DCAP Packages
* Intel(R) SGX DCAP PCCS (Provisioning Certificate Caching Service)

*Please refer to SGX DCAP Linux installation guide "https://download.01.org/intel-sgx/sgx-dcap/#version#/linux/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf" to install above dependencies*<br/>
*Note that you need to change **\#version\#** to actual version number in URL, such as 1.15.*


1. Generate an ECDSA quote with certification data of type 5 using QuoteGenerationSample
```
   $ cd SampleCode/QuoteGenerationSample/
   $ make
   $ ./app
```

2. Customize the appraisal policy
  * Sample appraisal policies are provided in Policies/ folder. Please customize the policy in the sample policies before running the sample.

  * Update the sample policies to add your own application enclave's MRSIGNER, MRENCLAVE, ISV SVN etc.
   - To get your enclave's detailed info, you can use `sgx_sign` tool to dump the enclave info.

   e.g.
   ```
      $ sgx_sign dump -enclave enclave.signed.so -dumpfile out.txt
   ```
   Then get your own enclave infomation from out.txt

  * ***In production environment, you should use your own policy and policy signing key [Not required for runing this sample]***
    - Prepare the enclave policy and platform policy. You can refer to the policy samples/templates in folder Policies/ to generate your own appraisal policies. The policy templates provides a default ECDSA signing key pair with below format:   
    - 384 bits   
    - private key - PEM format
    - public key - JWK format            

   * If you want to generate your own ECDSA signing key pair, run below command to utilize the OpenSSL with the tool https://github.com/danedmunds/pem-to-jwk:    
```bash
    $ openssl ecparam -name secp384r1 -genkey --noout > ec_priv.pem
    $ cat ec_priv.pem | docker run -i danedmunds/pem-to-jwk:latest --public  --pretty
```

    * Sign the policies with the tool `tee_appraisal_tool`:
     - Go to qal/tee_appraisal_tool folder and  run `tee_appraisal_tool` to sign the policies:
    ```bash
      $ tee_appraisal_tool {your_policy_manifest.json}
    ```

3. Build and run QuoteAppraisalSample in Debug build
   * Prepare the enclave test key(two options):
     - Install openssl first, then the project will generate a test key<Enclave_private_sample.pem> automatically when you build the project.
     - Rename your test key(3072-bit RSA private key) to <Enclave_private_sample.pem> and put it under the <Enclave> folder.
   
   * Build and run the sample
   ```
   $ make SGX_DEBUG=1
   $ ./app
   ```

4. Build and run QuoteAppraisalSample in Release build
   * Build the sample code
   ```
   $ make
   ```
   * Sign the enclave with the signing key
     - The command to sign the key is printed during the enclave build process. You can also follow the Developer Reference for more details about the signing tool.

   * Run the sample code
   ```
   $ ./app
   ```

**Policy definiton**
   
   * Please refer to Appraisal engine SAS section 4.2 and 4.3

**Note**: Our libdcap_quoteprov.so is not built with Intel(R) Control Flow Enforcement Technology(CET) feature. If the sample is built with CET feature(it can be enabled by the compiler's default setting) and it is running on a CET enabled platform, you may encounter such an error message(or something similar): "Couldn't find the platform library. rebuild shared object with SHSTK support enabled". It means the system glibc enforces that a CET-enabled application can't load a non-CET shared library. You need to rebuild the sample by adding  -fcf-protection=none option explicitly to disable CET.
