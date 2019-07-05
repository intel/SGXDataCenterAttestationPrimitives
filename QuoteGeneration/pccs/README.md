
## Provisioning Certificate Caching Service (PCCS)
This is a lightweight Provisioning Certificate Caching Service implemented in nodejs for reference. It retrieves PCK Certificates and other collaterals on-demand using the internet at runtime, and then cache them in local database. The PCCS exposes similar HTTPS interfaces as Intel's Provisioning Certificate Service.

## How to setup
    1) install node.js
        Version 10.13.0 LTS or later
           Download page: https://nodejs.org/en/download/
           NOTE : If you install PCCS through Debian package on Linux, please follow the link "Installing Node.js 
           via package manager" in the above page to install Node.js, because the PCCS Debian package has 
           dependency on it.

    2) If you installed PCCS by Debian package, then goto step 3), otherwise put all the files and sub folders 
       in this directory to your preferred place with right permissions set to launch a web service.

    3) (Optional) If you are connecting to internet through a proxy server, config proxy first before continue.
             sudo npm config set http-proxy http://your-proxy-server:port
             sudo npm config set https-proxy http://your-proxy-server:port

    4) Configure your environment, see section Configuration file

    5) Private key and public certificate
       The PCCS requires a private key and certificate pair to run as HTTPS server. For production environment 
       you should use formally issued key and certificate.
       You can also genarate an insecure key and certificate pair with following commands: (only for debug purpose)
           openssl genrsa 1024 > private.pem 
           openssl req -new -key private.pem -out csr.pem
           openssl x509 -req -days 365 -in csr.pem -signkey private.pem -out file.crt
       NOTE : If self-signed insecure key and certificate are used, you need to set USE_SECURE_KEY=FALSE when 
              configuring default QPL library (see ../qpl/README.md)

    6) From the root directory of the PCCS, run sudo ./install.sh (Linux) or install.bat (Windows)
       This will install the required npm packages in the current directory. It will also install pm2 package in the 
       global npm packages' directory and add the PCCS service to services list. You can change administrator
       token if prompted during installation. 

## Configuration file (./config.json)
You can modify config.json to change configurations for the PCCS.
- HTTPS_PORT - The port you want the PCCS to listen on. The default listening port is 8081.
- hosts - The hosts that will be accepted for connections. Default is localhost only. To accept all connections use 0.0.0.0
- uri - The URL of Intel Provisioning Certificate Service. The default URL is https://api.trustedservices.intel.com/sgx/certification/v1/
- ApiKey - The PCCS use this API key to require collaterals from Intel's Provisioning Certificate Service. User needs to subscribe first to obtain an API key. For how to subscribe to Intel Provisioning Certificate Service and receive an API key, goto https://api.portal.trustedservices.intel.com/provisioning-certification and click on 'Subscribe'.
- RefreshSchedule - cron-style refresh schedule for the PCCS to refresh cached artifacts including CRL/TCBInfo/QEIdentity.
  The default setting is "0 0 1 * * *", which means refresh at 1:00 am every day.
- CacheDB - File name of the cache database. Default value is pckcache.db.
- AdminToken - Sha512 hashed token for the PCCS administrator to perform a manual refresh of cached artifacts. 

## Local service vs Remote service
You can run PCCS on localhost for product development or setup it as a public remote service in datacenter.
Typical setup flow for Local Service mode (Ubuntu as example):
    1) Install Node.js via package manager (version 10.13 or later from official Node.js site)
    2) Setup npm proxy if necessary
    3) Install PCCS through Debian package or just copy it to your preferred directory manually
    4) Generate self-signed key and certificate pair in the PCCS installation directory
    5) Request an API key from Intel's Provisioning Certificate Service and update the configuration file
    6) Run ./install.sh from the PCCS installation directory
    7) Run 'sudo pm2 status' to confirm pccs_server is running
You can test PCCS by running QuoteGeneration sample:
    1) Set USE_SECURE_KEY=FALSE in /etc/sgx_default_qcnl.conf 
    2) Build and run QuoteGeneration sample and verify CertType=5 quote is generated
The default local service mode will only accept connections from localhost.
For Remote service mode, in step 4), you must use a formal key and certificate pair. In step 5), you should also change
'hosts' to 0.0.0.0 to accept remote connections. Also make sure the firewall is not blocking your listening port.
In step 8), Set USE_SECURE_KEY=TRUE

## Manage the server
    1) Check status:
        $ sudo pm2 status
    2) Stop PCCS 
        $ sudo pm2 stop pccs_server
    3) Start PCCS 
        $ sudo pm2 start pccs_server

## Uninstall
    sudo ./uninstall.sh


