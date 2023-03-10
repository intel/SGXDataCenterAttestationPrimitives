# Intel® Software Guard Extensions and Intel® Trust Domain Extensions Data Center Attestation Primitives (Intel® SGX and Intel® TDX DCAP) Quote Verification Service

## Introduction

Quote Verification Service is a stateless server endpoint implementation that verifies attestation evidence (quote) of ISV (Independent Software Vendor) enclaves.
It can be used as a part of [SGX attestation](https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/attestation-services.html) process.

Service checks, that provided evidence comes from a genuine, non-revoked SGX/TDX capable platform on given TCB level and generates appriopriate JSON report. Based on that report and by verifying additional evidences (like: MRSIGNER, MRENCLAVE) client can decide whether to trust this enclave or not. 


## Service architecture overview

![QVS Diagram](diagram.png?raw=true "QVS Diagram")

ISV Quote Verification Backend potential structure is presented on the diagram above. 

Quote Verification Service utilizes [QVL](../QVL) to perform it's business logic. It also communicates with Verification Collateral Distribution Services (PCS and CRL Distribution List) to obtain latest collaterals. When verification is done, report is generated and sent to a crypto provider - Verification Crypto Service (VCS) in order to be signed. 

VCS is a service capable of storing (Secure Key Storage) and using cryptographic keys in a secure manner (for example, by utilizing Hardware Secure Module). It has to be provided and protected by ISV, as a part of it's Quote Verification Backend.
Sample VCS implementation called [Simple Signing Service (SSS)](samples/simple-signing-service/README.md) has been created for demo purposes only - please do NOT use it in production environment.

## System requirements
QVS is purely software component, and it doesn't require SGX capable platform to work. Although it can be additionally protected by running inside an enclave (for example by using [Gramine](https://gramineproject.io/)).
Following instructions were tested using Linux (Ubuntu) distribution.

## Prerequisites for Linux

 - [Node.js](https://nodejs.org/en/) (tested with version 16.13.1) with `npm` and `cmake-js` addon
 - [Docker](https://www.docker.com/) (tested with version 20.10.11)
 - install prerequisites from [QVL](../QVL)

#### Install software dependencies
For Ubuntu 18.04, the following command can be used to install all necessary software dependencies:
- Node.js
  - ```$ wget https://nodejs.org/dist/v16.13.1/node-v16.13.1-linux-x64.tar.gz```
  - ```$ sudo tar -C /usr/local --strip-components 1 -xzf node-v16.13.1-linux-x64.tar.gz```
- cmake-js
  - ```$ sudo npm install -g cmake-js``` (assuming Node.js is already installed)
- Docker
  - ```$ curl -fsSL https://get.docker.com -o get-docker.sh```
  - ```$ sudo sh ./get-docker.sh```

## Building on Linux
The build was tested on Ubuntu 18.04 and 20.04.
Here, we assume that the [build prerequisites](#prerequisites-for-linux) are fulfilled. 

Execute ```./build.sh```. This script will build QVL, QVS Service and finally will create Docker Image with service installed in it. 

Script will build:
- QVL
- download and install node modules
- copy native libs into service structure
- produce docker image ```qvs:latest```


## Setting up local environment

QVS service can be either [run locally](#running-locally) or [inside a docker container](#running-docker-image).
To set up local environment, a working instance of Verification Crypto Service (VCS) is required.

For non-production/development purpose use mock VCS located in [samples/simple-signing-service](./samples/simple-signing-service/README.md). 
It is recommended to write your own Verification Crypto Service that will be able to securely protect Signing Key for attestation evidence.

By default QVS is using MTLS to communicate with VCS, it is recommended to keep  [QVS_VCS_CLIENT_TLS_CLIENT_TYPE](#service-configuration) set to MTLS.

In order to set up local environment one must generate required key pairs for MTLS. Commands in README files linked in next sections will show how to generate self-signed certificates for non-production environment. It is highly recommended not to use such self-signed certificates in production and replace them with certificates signed by widely trusted certification authority.

### Set-up Simple-Signing-Service:
Go to [samples/simple-signing-service/README.md](samples/simple-signing-service/README.md). Simple-signing-service will provide output with correctly formatted certifcate (see mock-service log and search for: SIGNING_KEY_CERTIFCATE_URL_ENCODED) from Signing Key that needs to be included as env variable QVS_ATTESTATION_REPORT_SIGNING_CERTIFICATE to your Quote Verification Service.

### Configure QVS (MTLS)
Go to [configuration-default/certificates/README.md](configuration-default/certificates/README.md) - (Some of the steps should be already done as a part of SSS instruction)
## Running locally

```bash
QVS_VCS_CLIENT_HOST=localhost QVS_VCS_CLIENT_PORT=8797 QVS_ATTESTATION_REPORT_SIGNING_CERTIFICATE=SIGNING_KEY_CERTIFCATE_URL_ENCODED NODE_ENV=production node src/bootstrap.js
```
## Running docker image

```bash
docker run --network host --env QVS_VCS_CLIENT_HOST=localhost --env QVS_VCS_CLIENT_PORT=8797 --env QVS_ATTESTATION_REPORT_SIGNING_CERTIFICATE=SIGNING_KEY_CERTIFCATE_URL_ENCODED -it qvs:latest
```

## Healtcheck
```bash
curl --cacert ./configuration-default/certificates/qvs-cert.pem https://localhost:8799/health
```

## Service configuration

### General Service Configuration
|  ENV | Default Value  | Additional Description |
| ------------ | ------------ | ------------ |
|  QVS_SERVICE_COMPONENT_NAME | QuoteVerificationService  |   |
|  QVS_SERVICE_COMPONENT_SHORT |  QVS |   |
|  QVS_SERVICE_PORT | 8799  |   |
|  QVS_SERVICE_CERT_FILE |   |   |
|  QVS_SERVICE_KEY_FILE |   |   |
|  QVS_SERVICE_TLS_SERVER_TYPE |  TLS |  None/TLS |
|  QVS_CA_CERT_DIRECTORIES | 'certificates/internal_ca/'  | Used in case QVS_SERVICE_TLS_SERVER_TYPE is MTLS. Should point to directories (seperated by `,` `;` or ` `) containing CA certificates (or subdirectories with certificates). Overrides the default trusted CA certificates.  |
|  QVS_SERVICE_BODY_SIZE_LIMITS | '{"json":"256kb"}'  |   |

### Logger
|  ENV | Default Value  | Additional Description |
| ------------ | ------------ | ------------ |
|  QVS_LOGGER_CATEGORY | QuoteVerificationService  | Name of the service that will be displayed in log before file name  |
|  QVS_LOGGER_LEVEL_FILE | off  | options: off/on, configure also QVS_LOGGER_FILE_NAME |
|  QVS_LOGGER_FILE_NAME |   |  value: specify filepath, then you have to mount a directory with r/w rights |
|  QVS_LOGGER_LEVEL_CONSOLE | info  | info/debug/trace |
|  QVS_LOGGER_MULTILINE_ERROR_LOG |  true | options: true/false  |

### Service healthcheck
|  ENV | Default Value  | Additional Description |
| ------------ | ------------ | ------------ |
|  QVS_HEALTH_CHECK_INTERVAL_MS |  60000 | Time period between checking health of component dependencies (positive status is cached for QVS_HEALTH_CHECK_FRESHNESS_MS) |
|  QVS_HEALTH_CHECK_FRESHNESS_MS |  60000 | Health cache expiration time (in milliseconds) |

### Verification Crypto Service Client
|  ENV | Default Value  | Additional Description |
| ------------ | ------------ | ------------ |
|  QVS_VCS_CLIENT_HOST |   | VCS address |
|  QVS_VCS_CLIENT_PORT | 0  |  |
|  QVS_VCS_CLIENT_RETRIES |   |   |
|  QVS_VCS_CLIENT_INITIAL_INTERVAL | 100  |   |
|  QVS_VCS_CLIENT_INTERVAL_FACTOR |  1 | multiplier of wait period between retries |
|  QVS_VCS_CLIENT_CERT_FILE |   |  Configure if QVS_VCS_CLIENT_TLS_CLIENT_TYPE=MTLS  |
|  QVS_VCS_CLIENT_KEY_FILE |   | Configure if QVS_VCS_CLIENT_TLS_CLIENT_TYPE=MTLS  |
|  QVS_VCS_CLIENT_CA_CERT_DIRECTORIES |   | Should point to directories (seperated by `,` `;` or ` `) containing CA certificates (or subdirectories with certificates). Overrides the default trusted CA certificates.  |
|  QVS_VCS_CLIENT_TLS_CLIENT_TYPE | MTLS  | options: None/TLS/MTLS, recommendation is to use MTLS |
|  QVS_VCS_CLIENT_PROXY |   |  Configure proxy for VCS client |
|  QVS_VCS_CLIENT_SERVERNAME |   | CN of the certificate expected in MTLS mode |


### Intel® Provisioning Certification Service Client (PCS)
|  ENV | Default Value  | Additional Description |
| ------------ | ------------ | ------------ |
|  QVS_PCS_CLIENT_HOST | api.trustedservices.intel.com  |  |
|  QVS_PCS_CLIENT_PORT | 443  |   |
|  QVS_PCS_CLIENT_RETRIES | 1  |   |
|  QVS_PCS_CLIENT_INITIAL_INTERVAL | 100 |   |
|  QVS_PCS_CLIENT_INTERVAL_FACTOR | 1  |   |
|  QVS_PCS_CLIENT_CA_CERT_DIRECTORIES | 'certificates/internal_ca/'  |  Should point to directories (seperated by `,` `;` or ` `) containing CA certificates (or subdirectories with certificates). Overrides the default trusted CA certificates. |
|  QVS_PCS_CLIENT_TLS_CLIENT_TYPE | TLS  | options: None/TLS/MTLS, notice: Intel® Provisioning Certification Service will work only with TLS  |
|  QVS_PCS_CLIENT_PROXY |   | Configure proxy for PCS client  |
|  QVS_PCS_CLIENT_SERVERNAME |   | CN of the certificate expected in MTLS mode |

### CRL Client
|  ENV | Default Value  | Additional Description |
| ------------ | ------------ | ------------ |
|  QVS_CRL_CLIENT_RETRIES | 2  |   |
|  QVS_CRL_CLIENT_INITIAL_INTERVAL | 100  |   |
|  QVS_CRL_CLIENT_INTERVAL_FACTOR | 3  |   |
|  QVS_CRL_CLIENT_PROXY |   | Configure proxy for PCS client  |

### Cache for CRL and PCS clients
|  ENV | Default Value  | Additional Description |
| ------------ | ------------ | ------------ |
|  QVS_CACHE_CRL_TTL | 0  | 0 is unlimited / until next restart  |
|  QVS_CACHE_CRL_CHECK_PERIOD | 600  |   |
|  QVS_CACHE_CRL_MAX_KEYS | 100  |  -1 is unlimited, 0 turns off caching |
|  QVS_CACHE_PCS_TTL | 0  | 0 is unlimited / until next restart  |
|  QVS_CACHE_PCS_CHECK_PERIOD | 600  |   |
|  QVS_CACHE_PCS_MAX_KEYS | 100  |  -1 is unlimited, 0 turns off caching |

### Attestation Report and quote verifying
|  ENV | Default Value  | Additional Description |
| ------------ | ------------ | ------------ |
|  QVS_ATTESTATION_REPORT_SIGNING_CA_CERTIFICATE |   | URL encoded CA certificate (in PEM format) of QVS_ATTESTATION_REPORT_SIGNING_CERTIFICATE. As part of chain it will be returned in `X-IASReport-Signing-Certificate` header to enable verifying report. |
|  QVS_ATTESTATION_REPORT_SIGNING_CERTIFICATE |   |  URL encoded certificate (in PEM format) that Verification Crypto Service uses to sign reports. Also returned as part of chain in `X-IASReport-Signing-Certificate` header. |
|  QVS_TRUSTED_ROOT_PUBLIC_KEY | 3059301306072a8648ce3d020106082a8648ce3d030107034200040ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f567918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394  | Public key of CA certificate that is root for PCK certificate chain  |
