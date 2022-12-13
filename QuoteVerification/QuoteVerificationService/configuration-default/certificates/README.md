# Quote Verification Service certificates configuration
This guide describes how to create certificates required  by the service.

## Prerequisite

 - Install [OpenSSL](https://www.openssl.org/ "OpenSSL") (tested with version 1.1.0g)
 - SSS MTLS client certificate has been [created](../../samples/simple-signing-service/README.md#configure-key-pairs).

## Configure Key Pairs
Let’s create a key and self-signed cert for HTTPS enabling:

```
openssl genrsa -out qvs-key.pem
openssl req -new -key qvs-key.pem -out csr.pem
openssl x509 -req -days 9999 -in csr.pem -signkey qvs-key.pem -out qvs-cert.pem
rm csr.pem
```

Copy or mount created files to Docker container and provide paths in the following environment variables:

* QVS_SERVICE_CERT_FILE
* QVS_SERVICE_KEY_FILE

Then set QVS_SERVICE_TLS_SERVER_TYPE environment variable to TLS to enable HTTPS.

### Configure MTLS with SSS

Generate a second pair for MTLS connection between components:

```
openssl genrsa -out qvs-to-sss-client-key.pem
openssl req -new -key qvs-to-sss-client-key.pem -out csr.pem
openssl x509 -req -days 9999 -in csr.pem -signkey qvs-to-sss-client-key.pem -out qvs-to-sss-client-cert.pem
rm csr.pem
```


Make sure SSS(VCS) certificate is trusted for QVS:
```
cp ../../samples/simple-signing-service/cert.pem ./internal-ca/
```
Make sure QVS certificate is trusted for SSS:
```
cp qvs-to-sss-client-cert.pem ../../samples/simple-signing-service/
```

Make sure [../config.yml](../config.yml) contains certificate paths and client server name:
```
certFile:          '${QVS_SERVICE_CERT_FILE:certificates/qvs-cert.pem}'
keyFile:           '${QVS_SERVICE_KEY_FILE:certificates/qvs-key.pem}'
tlsServerType:     '${QVS_SERVICE_TLS_SERVER_TYPE:TLS}'
...
host:              '${QVS_VCS_CLIENT_HOST:localhost}'
port:              '${QVS_VCS_CLIENT_PORT:8797}'
certFile:          '${QVS_VCS_CLIENT_CERT_FILE:certificates/qvs-to-sss-client-cert.pem}'
keyFile:           '${QVS_VCS_CLIENT_KEY_FILE:certificates/qvs-to-sss-client-key.pem}'
servername:        '${QVS_VCS_CLIENT_SERVERNAME:<CN of the qvs-to-sss-client-cert.pem>}'
```

Copy or mount created files to Docker container and provide paths in the following environment variables:

* QVS_VCS_CLIENT_CERT_FILE
* QVS_VCS_CLIENT_KEY_FILE

Provide host and port of VCS (e.g. simple-signing-service) in the following environment variables:

* QVS_VCS_CLIENT_HOST
* QVS_VCS_CLIENT_PORT
