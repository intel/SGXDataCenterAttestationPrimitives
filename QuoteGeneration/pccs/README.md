## Provisioning Certificate Caching Service (PCCS)
This is a lightweight Provisioning Certificate Caching Service implemented in nodejs for reference. It retrieves PCK Certificates and other collaterals on-demand using the internet at runtime, and then caches them in local database. The PCCS exposes similar HTTPS interfaces as Intel's Provisioning Certificate Service.

## How to install
- **Prerequisites**

    Install node.js (Version 10.13.0 LTS or later)
    + For Debian and Ubuntu based distributions, you can use the following command:<br/>
         curl -sL https://deb.nodesource.com/setup_14.x | sudo -E bash - sudo apt-get install -y nodejs
    + To download and install, goto https://nodejs.org/en/download/

- **Install via Linux Debian package installer**

    dpkg -i sgx-dcap-pccs_${version}-${os}_${arch}.deb

    All configurations can be done during the installation process.

    *NOTE : If you have installed old libsgx-dcap-pccs releases with root privilege before, some folders may remain even after you uninstall it. 
    You can delete them manually with root privilege, for example, ~/.pm2/, ~/.npm/, etc.*

- **Install via RPM package installer**

    rpm -ivh sgx-dcap-pccs_${version}_${arch}.rpm

    After the RPM package was installed, you can run install.sh from the root directory of the PCCS to configure it.

- **Linux manual installation**

    1) Put all the files and sub folders in this directory to your preferred place with right permissions set to launch a 
       web service.
    2) Install python if it's not already installed
    3) Goto ../../tools/PCKCertSelection/ and build libPCKCertSelection.so, copy it to ./lib/ 
    4) From the root directory of the PCCS, run ./install.sh

- **Windows manual installation**

    1) Put all the files and sub folders in this directory to your preferred place with right permissions set to launch a 
       web service.
    2) (Optional) If the target machine connects to internet through a proxy server, configure proxy server first 
        before continuing.
            npm config set http-proxy http://your-proxy-server:port
            npm config set https-proxy http://your-proxy-server:port
            npm config set proxy http://your-proxy-server:port

    3) Update config file based on your environment, see section Configuration file

    4) Private key and public certificate
        The PCCS requires a private key and certificate pair to run as HTTPS server. For production environment
        you should use formally issued key and certificate. Please put the key files in ssl_key sub directory.
        You can also genarate an insecure key and certificate pair with following commands: (only for debug purpose)
            openssl genrsa 1024 > private.pem 
            openssl req -new -key private.pem -out csr.pem
            openssl x509 -req -days 365 -in csr.pem -signkey private.pem -out file.crt

    5) Install python if it's not already installed

    6) From the root directory of the PCCS, run install.bat 
        This will install the required npm packages in that directory. It will also install pm2 package in the 
        global npm packages' directory and add the PCCS service to services list. 

    7) PCKCertSelection Library
        You need to compile the PCKCertSelection library in ../../tools/PCKCertSelection, then put the binary files
        (PCKCertSelectionLib.dll and libcrypto-1_1-x64.dll from openSSL) in a folder that is in OS's search path, 
        for example, %SYSTEMROOT%\system32. 

    **NOTE** : If self-signed insecure key and certificate are used, you need to set USE_SECURE_CERT=FALSE when 
    configuring the default QPL library (see ../qpl/README.md)

## Configuration file (config/production-0.json)
- **HTTPS_PORT** - The port you want the PCCS to listen on. The default listening port is 8081.
- **hosts** - The hosts that will be accepted for connections. Default is localhost only. To accept all connections use 0.0.0.0
- **uri** - The URL of Intel Provisioning Certificate Service. The default URL is https://api.trustedservices.intel.com/sgx/certification/v2/
- **ApiKey** - The PCCS use this API key to request collaterals from Intel's Provisioning Certificate Service. User needs to subscribe first to obtain an API key. For how to subscribe to Intel Provisioning Certificate Service and receive an API key, goto https://api.portal.trustedservices.intel.com/provisioning-certification and click on 'Subscribe'.
- **proxy** - Specify the proxy server for internet connection, for example, "http://192.168.1.1:80". Leave blank for no proxy or system proxy.
- **RefreshSchedule** - cron-style refresh schedule for the PCCS to refresh cached artifacts including CRL/TCB Info/QE Identity/QVE Identity.
  The default setting is "0 0 1 * * *", which means refresh at 1:00 am every day.
- **UserToken** - Sha512 hashed token for the PCCS client user to register a platform. For example, PCK Cert ID retrieval tool will use this token to send platform information to pccs.
- **AdminToken** - Sha512 hashed token for the PCCS administrator to perform a manual refresh of cached artifacts. 

	*NOTE* : For Windows you need to set the UserToken and AdminToken manually. You can calculate SHA512 hash with the help of openssl:

		<nul: set /p password="mytoken" | openssl dgst -sha512
- **CachingFillMode** - The method used to fill the cache DB. Can be one of the following: REQ/LAZY/OFFLINE. For more details see section "Caching Fill Mode".
- **LogLevel** - Log level. Use the same levels as npm: error, warn, info, http, verbose, debug, silly. Default is info.
- **DB_CONFIG** - You can choose sqlite or mysql and many other DBMSes. For sqlite, you don't need to change anything. For other DBMSes, you need to set database connection options correctly. Normally you need to change database, username, password, host and dialect to connect to your DBMS.
<br/>**NOTE: It's recommended to delete old database first if you have installed a different version of PCCS before because the database may be not compatible.**

## Caching Fill Mode
When a new server platform is introduced to the data center or the cloud service provider that will require SGX remote attestation, the caching service will need to import the platform’s SGX attestation collateral retrieved from Intel.  This collateral will be used for both generating and verifying ECDSA quotes. Currently PCCS supports three caching fill methods.

- LAZY mode
In this mode, when the caching service gets a retrieval request(PCK Cert, TCB, etc.) at runtime, it will look for the collaterals in its database to see if they are already in the cache.  If they don't exist, it will contact the Intel PCS to retrieve the collaterals. This mode only works when internet connection is available.  

- REQ mode
In this method of filling the cache, the caching service will create a platform database entry when the caching service receives the registration requests. It will not return any data to the caller, but will contact the Intel PCS to retrieve the platform's collaterals if they are not in the cache. It will save the retrived collaterals in cache database for later use. This mode requires internet connection at deployment time. During runtime the caching service will use cache data only and will not contact Intel PCS. 

- OFFLINE mode
In this method of filling the cache, the caching service will not have access to the Intel hosted PCS service on the internet. It will create a platform database entry to save platform registration information sent by PCK Cert ID retrieval tool. It will provide an interface to allow an administration tool to retrieve the contents of the registration queue. The administrator tool will run on a platform that does have access to the internet. It can fetch platform collaterals from Intel PCS and send them to the caching service. The tool can be found at [SGXDataCenterAttestationPrimitives/tools/PccsAdminTool](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/tools/PccsAdminTool) 

## Local service vs Remote service
You can run PCCS on localhost for product development or setup it as a public remote service in datacenter.
Typical setup flow for Local Service mode (Ubuntu 18.04 as example):

    1) Install Node.js via package manager (version 10.13 or later from official Node.js site)
    2) Request an API key from Intel's Provisioning Certificate Service
    3) Install PCCS through Debian package

You can test PCCS by running QuoteGeneration sample:

    1) Set USE_SECURE_CERT=FALSE in /etc/sgx_default_qcnl.conf 
    2) Build and run QuoteGeneration sample and verify CertType=5 quote is generated

For Remote service mode, you must use a formal key and certificate pair. You should also change 'hosts' to 0.0.0.0 to accept remote connections. Also make sure the firewall is not blocking your listening port.
In /etc/sgx_default_qcnl.conf, Set USE_SECURE_CERT=TRUE (For Windows see ../qpl/README.md)

## Manage the service
    1) Check status:
        $ pm2 status
    2) Stop PCCS 
        $ pm2 stop pccs
    3) Start PCCS 
        $ pm2 start pccs

## Uninstall
    If the PCCS service was installed through Debian package, you can use Debian package manager to uninstall it.
    If the PCCS service was installed manually, you can run below script to uninstall it:
        ./uninstall.sh (or uninstall.bat on Windows)
