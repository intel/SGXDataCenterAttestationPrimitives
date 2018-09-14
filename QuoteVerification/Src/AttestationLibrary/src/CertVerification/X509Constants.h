/*
* Copyright (c) 2017, Intel Corporation
*
* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:

* 1. Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
* 3. Neither the name of the copyright holder nor the names of its contributors
*    may be used to endorse or promote products derived from this software
*    without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
* THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
* BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
* OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
* OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
* OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
* WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
* OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
* EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef SGX_ECDSA_X509_CONSTANTS_H_
#define SGX_ECDSA_X509_CONSTANTS_H_

#include <PckParser/PckParser.h>

#include <openssl/x509v3.h>

#include <string>

namespace intel { namespace sgx { namespace qvl { namespace constants {

const pckparser::Subject ROOT_CA_SUBJECT
{
    "CN=Intel SGX Root CA, O=Intel Corporation, L=Santa Clara, ST=CA, C=US",

    "Intel SGX Root CA",    // commonName
    "US",                   // countryName
    "Intel Corporation",    // organizationName
    "Santa Clara",          // locationName
    "CA"                    // stateName
};

const std::vector<int> ROOT_CA_REQUIRED_EXTENSIONS
{
    NID_authority_key_identifier,
    NID_crl_distribution_points,
    NID_subject_key_identifier,
    NID_key_usage,
    NID_basic_constraints
};

const pckparser::Subject PLATFORM_CA_SUBJECT
{
    "CN=Intel SGX PCK Platform CA, O=Intel Corporation, L=Santa Clara, ST=CA, C=US",

    "Intel SGX PCK Platform CA",    // commonName
    "US",                           // countryName
    "Intel Corporation",            // organizationName
    "Santa Clara",                  // locationName
    "CA"                            // stateName
};

const std::vector<int> PLATFORM_CA_REQUIRED_EXTENSIONS
{
    NID_authority_key_identifier,
    NID_crl_distribution_points,
    NID_subject_key_identifier,
    NID_key_usage,
    NID_basic_constraints
};

const pckparser::Subject PROCESSOR_CA_SUBJECT
{
    "CN=Intel SGX PCK Processor CA, O=Intel Corporation, L=Santa Clara, ST=CA, C=US",

    "Intel SGX PCK Processor CA",   // commonName
    "US",                           // countryName
    "Intel Corporation",            // organizationName
    "Santa Clara",                  // locationName
    "CA"                            // stateName
};

const std::vector<int> PROCESSOR_CA_REQUIRED_EXTENSIONS
{
    NID_authority_key_identifier,
    NID_crl_distribution_points,
    NID_subject_key_identifier,
    NID_key_usage,
    NID_basic_constraints
};

const pckparser::Subject PCK_SUBJECT
{
    "CN=Intel SGX PCK Certificate, O=Intel Corporation, L=Santa Clara, ST=CA, C=US",

    "Intel SGX PCK Certificate",    // commonName
    "US",                           // countryName
    "Intel Corporation",            // organizationName
    "Santa Clara",                  // locationName
    "CA"                            // stateName
};

const std::vector<int> PCK_REQUIRED_EXTENSIONS
{
    NID_authority_key_identifier,
    NID_crl_distribution_points,
    NID_subject_key_identifier,
    NID_key_usage,
    NID_basic_constraints
};

const std::vector<pckparser::SgxExtension::Type> PCK_REQUIRED_SGX_EXTENSIONS
{
    pckparser::SgxExtension::Type::PPID,
    pckparser::SgxExtension::Type::TCB,
    pckparser::SgxExtension::Type::PCEID,
    pckparser::SgxExtension::Type::FMSPC,
    pckparser::SgxExtension::Type::SGX_TYPE
};

const std::vector<pckparser::SgxExtension::Type> TCB_REQUIRED_SGX_EXTENSIONS
{
    pckparser::SgxExtension::Type::CPUSVN,
    pckparser::SgxExtension::Type::PCESVN,
    pckparser::SgxExtension::Type::SGX_TCB_COMP01_SVN,
    pckparser::SgxExtension::Type::SGX_TCB_COMP02_SVN,
    pckparser::SgxExtension::Type::SGX_TCB_COMP03_SVN,
    pckparser::SgxExtension::Type::SGX_TCB_COMP04_SVN,
    pckparser::SgxExtension::Type::SGX_TCB_COMP05_SVN,
    pckparser::SgxExtension::Type::SGX_TCB_COMP06_SVN,
    pckparser::SgxExtension::Type::SGX_TCB_COMP07_SVN,
    pckparser::SgxExtension::Type::SGX_TCB_COMP08_SVN,
    pckparser::SgxExtension::Type::SGX_TCB_COMP09_SVN,
    pckparser::SgxExtension::Type::SGX_TCB_COMP10_SVN,
    pckparser::SgxExtension::Type::SGX_TCB_COMP11_SVN,
    pckparser::SgxExtension::Type::SGX_TCB_COMP12_SVN,
    pckparser::SgxExtension::Type::SGX_TCB_COMP13_SVN,
    pckparser::SgxExtension::Type::SGX_TCB_COMP14_SVN,
    pckparser::SgxExtension::Type::SGX_TCB_COMP15_SVN,
    pckparser::SgxExtension::Type::SGX_TCB_COMP16_SVN
};

const pckparser::Subject TCB_SUBJECT
{
    "CN=Intel SGX TCB Signing, O=Intel Corporation, L=Santa Clara, ST=CA, C=US",

    "Intel SGX TCB Signing",        // commonName
    "US",                           // countryName
    "Intel Corporation",            // organizationName
    "Santa Clara",                  // locationName
    "CA"                            // stateName
};

const std::vector<int> TCB_REQUIRED_EXTENSIONS
{
    NID_authority_key_identifier,
    NID_crl_distribution_points,
    NID_subject_key_identifier,
    NID_key_usage,
    NID_basic_constraints
};

const pckparser::Issuer ROOT_CA_CRL_ISSUER =
{
    "CN=Intel SGX Root CA, O=Intel Corporation, L=Santa Clara, ST=CA, C=US",

    "Intel SGX Root CA",            // commonName
    "US",                           // countryName
    "Intel Corporation",            // organizationName
    "Santa Clara",                  // locationName
    "CA"                            // stateName
};

const pckparser::Issuer PCK_PLATFORM_CRL_ISSUER =
{
    "CN=Intel SGX PCK Platform CA, O=Intel Corporation, L=Santa Clara, ST=CA, C=US",

    "Intel SGX PCK Platform CA",   // commonName
    "US",                           // countryName
    "Intel Corporation",            // organizationName
    "Santa Clara",                  // locationName
    "CA"                            // stateName
};

const pckparser::Issuer PCK_PROCESSOR_CRL_ISSUER =
{
    "CN=Intel SGX PCK Processor CA, O=Intel Corporation, L=Santa Clara, ST=CA, C=US",

    "Intel SGX PCK Processor CA",  // commonName
    "US",                           // countryName
    "Intel Corporation",            // organizationName
    "Santa Clara",                  // locationName
    "CA"                            // stateName
};

const std::vector<pckparser::Issuer> CRL_VALID_ISSUERS = {ROOT_CA_CRL_ISSUER, PCK_PLATFORM_CRL_ISSUER, PCK_PROCESSOR_CRL_ISSUER};

const std::vector<int> CRL_REQUIRED_EXTENSIONS
{
    NID_crl_number,
    NID_authority_key_identifier
};

const size_t PPID_BYTE_LEN = 16;
const size_t CPUSVN_BYTE_LEN = 16;
const size_t SGX_TCB_SVN_COMP_BYTE_LEN = 1;
const size_t PCEID_BYTE_LEN = 2;
const size_t FMSPC_BYTE_LEN = 6;
const size_t DYNAMIC_PLATFORM_BYTE_LEN = 1;
const size_t CACHED_KEYS_BYTE_LEN = 1;
const size_t SGX_TYPE_BYTE_LEN = 1;
const size_t TCB_SEQUENCE_LEN = 18;

}}}} // namespace intel { namespace sgx { namespace qvl { namespace constants {

#endif
