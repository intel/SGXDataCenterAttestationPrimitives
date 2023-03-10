# Simple Signing Service Example

DO NOT USE THIS IN PRODUCTION.

## Prerequisite

Non-SGX platform is sufficient, tested with Ubuntu 18.04 and Ubuntu 20.04

Install: 
 - [Node.js](https://nodejs.org/en/) (tested with version 16.13.1)
 - [OpenSSL](https://www.openssl.org/ "OpenSSL") (tested with version 1.1.0g)

## Configure Key Pairs
In order to use the service, we need to generate 2 key pairs and corresponding self-signed certificates: one for HTTPS, second for signing Attestation Report. 

First, let’s create a key and self-signed cert for HTTPS enabling:

```
openssl genrsa -out key.pem
openssl req -new -key key.pem -out csr.pem
openssl x509 -req -days 9999 -in csr.pem -signkey key.pem -out cert.pem
rm csr.pem
```

Finally, let’s create a key and self-signed cert for signing Attestation Report:

```
openssl genrsa -out sign-key.pem 3072
openssl req -new -key sign-key.pem -out csr.pem
openssl x509 -req -days 9999 -in csr.pem -signkey sign-key.pem -out sign-cert.pem
rm csr.pem
```

## Communication with Quote Verification Service

Sample simple-signing-service is configured by default to support MTLS.

To allow requests from Quote Verification Service, QVS client certificate has to be added to SSS's trusted CA. It's configured by [QVS_VCS_CLIENT_CERT_FILE](../../README.md#service-configuration) configuration variable.

To do so, please [create QVS Client certificate](../../configuration-default/certificates/README.md#configure-mtls-with-sss). Expected result is that qvs-to-sss-client-cert.pem copy is located in SSS's directory.

## Building and Starting Service

Build simple-signing-service:

```npm install```

and start:

```npm start``` or ```node simple-signing-service.js```

This service will run with two ports enabled:

```
Server Started: https://localhost:8797
Server Started: http://localhost:8796 
```
## Healtcheck
In order to use HTTPS (default port: 8797) please create qvs-to-sss-client key and cert first, 
following: [../../configuration-default/certificates/README.md](../../configuration-default/certificates/README.md)

```
curl http://localhost:8796/health
curl --cacert ./cert.pem --key ../../configuration-default/certificates/qvs-to-sss-client-key.pem --cert ../../configuration-default/certificates/qvs-to-sss-client-cert.pem  https://localhost:8797/health
```

## Configuration for Quote Verification Service 

Read the log and get information from the line below:

```
Signing Certificate in URL encoded:<SIGNING_KEY_CERTIFCATE_URL_ENCODED>
```

That will be required to start Quote Verification Service. 
