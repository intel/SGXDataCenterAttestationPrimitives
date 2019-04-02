
## PCK caching service
This is a lightweight PCK caching service implemented in nodejs for reference. It retrieves PCK Certs and other collaterals on-demand using the internet at runtime, and then cache them in local database. The PCS caching service exposes similar HTTPS interfaces as Intel's PCS Service.

## How to setup
    1) install node.js
        10.13.0 LTS
           For Linux you can build from source
           For Windows use pre-built installer

    2) Put all the files and sub folders in this directory to your preferred place with right permissions set to launch a web service

    3) Modify the configuration file to fit with your environment, see Section 2.configuration

    4) Private key and public certificate
       The pcs server requires a private key and certificate pair to run as HTTPS server. Vendors should use your formally issued key and certificate for this purpose.
       You can also genarate an insecure key and certificate pair with following commands: (only for debug purpose)
           openssl genrsa 1024 > private.pem 
           openssl req -new -key private.pem -out csr.pem
           openssl x509 -req -days 365 -in csr.pem -signkey private.pem -out file.crt

    5) From the root directory of the pcs server, run ./install.sh 
        This will install the required npm packages in the current directory. It will also install pm2 package in the global npm packages' directory and add the PCS to service list. 
        You can change administrator token during installation. If you don't change it, you can still generate the sha512 hash of your token manually and modify config.json directly.

## Configuration
You can modify config.json to change configurations.
- HTTPS_PORT - The port you want PCS to listen on.
- uri - The URL of Intel's PCS Service.
- ApiKey - The PCK caching service use this API key to require collaterals from Intel's PCS Service. User needs to subscribe first to obtain an API key. For how to subscribe to Intel PCS service and receive an API key, goto https://api.portal.trustedservices.intel.com/
- RefreshSchedule - cron-style refresh schedule for the PCS caching service to refresh cached artifacts including CRL/TCBInfo/QEIdentity. 
- CacheDB - File name of the cache database.
- AdminToken - Sha512 hashed token for the PCS caching service administrator to perform a manual refresh of cached artifacts.

## Manage the server
    1) Check status:
        $ sudo pm2 status
    2) Stop PCS 
        $ sudo pm2 stop pcs_server
    3) Start PCS 
        $ sudo pm2 start pcs_server

## Uninstall
    sudo ./uninstall.sh


