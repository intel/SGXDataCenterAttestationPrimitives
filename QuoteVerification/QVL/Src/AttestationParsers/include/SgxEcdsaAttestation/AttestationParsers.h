/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef SGX_DCAP_PARSERS_H_
#define SGX_DCAP_PARSERS_H_

#include <vector>
#include <set>
#include <string>
#include <ctime>
#include <stdexcept>
#include <rapidjson/fwd.h>
#include "OpensslHelpers/OpensslTypes.h"

namespace intel { namespace sgx { namespace dcap { namespace parser
{

    namespace json
    {
        class JsonParser;

        class TcbInfo;

        class TcbLevel
        {
        public:
            TcbLevel(const std::vector<uint8_t>& cpuSvnComponents,
                     unsigned int pceSvn,
                     const std::string& status);

            TcbLevel(const std::vector<uint8_t>& cpuSvnComponents,
                     unsigned int pceSvn,
                     const std::string& status,
                     std::time_t tcbDate,
                     std::vector<std::string> advisoryIDs);

            virtual ~TcbLevel() = default;

            virtual bool operator>(const TcbLevel& other) const;

            /**
             * Get SVN component value at given position
             * @param componentNumber
             * @return the value for given component
             *
             * @throws intel::sgx::dcap::parser::FormatException when out of range
             */
            virtual unsigned int getSgxTcbComponentSvn(unsigned int componentNumber) const;
            virtual const std::vector<uint8_t>& getCpuSvn() const;
            virtual unsigned int getPceSvn() const;
            virtual const std::string& getStatus() const;
            virtual const std::time_t& getTcbDate() const;
            virtual const std::vector<std::string>& getAdvisoryIDs() const;

        private:
            std::vector<uint8_t> _cpuSvnComponents;
            unsigned int _pceSvn;
            std::string _status;
            std::time_t _tcbDate;
            std::vector<std::string> _advisoryIDs{};

            void setCpuSvn(const ::rapidjson::Value& tcb, JsonParser& jsonParser);
            void parseSvns(const ::rapidjson::Value& tcbLevel, JsonParser& jsonParser);
            void parseStatus(const ::rapidjson::Value &tcbLevel,
                             const std::vector<std::string> &validStatuses,
                             const std::string &filedName);
            void parseTcbLevelV1(const ::rapidjson::Value& tcbLevel, JsonParser& jsonParser);
            void parseTcbLevelV2(const ::rapidjson::Value& tcbLevel, JsonParser& jsonParser);

            explicit TcbLevel(const ::rapidjson::Value& tcbLevel, unsigned int version);

            friend class TcbInfo;
        };

        class TcbInfo
        {
        public:
            enum class Version : unsigned int
            {
                V1 = 1,
                V2 = 2
            };

            TcbInfo() = default;
            virtual ~TcbInfo() = default;

            virtual unsigned int getVersion() const;
            virtual std::time_t getIssueDate() const;
            virtual std::time_t getNextUpdate() const;
            virtual const std::vector<uint8_t>& getFmspc() const;
            virtual const std::vector<uint8_t>& getPceId() const;
            virtual const std::set<TcbLevel, std::greater<TcbLevel>>& getTcbLevels() const;
            virtual const std::vector<uint8_t>& getSignature() const;
            virtual const std::vector<uint8_t>& getInfoBody() const;

            /**
             * @return TCB Type
             *
             * @throws intel::sgx::dcap::parser::FormatException in case of TCBInfo version equal 1
             */
            virtual int getTcbType() const;

            /**
             * @return TCB Evaluation Data Number
             *
             * @throws intel::sgx::dcap::parser::FormatException in case of TCBInfo version equal 1
             */
            virtual unsigned int getTcbEvaluationDataNumber() const;

            /**
             * Parse JSON text from a string
             * @param json JSON text
             * @return TCB info instance
             *
             * @throws intel::sgx::dcap::parser::FormatException in case of parsing error
             */
            static TcbInfo parse(const std::string& json);

        private:
            Version _version;
            std::time_t _issueDate;
            std::time_t _nextUpdate;
            std::vector<uint8_t> _fmspc;
            std::vector<uint8_t> _pceId;
            std::set<TcbLevel, std::greater<TcbLevel>> _tcbLevels;
            std::vector<uint8_t> _signature;
            std::vector<uint8_t> _infoBody;
            int _tcbType;
            unsigned int _tcbEvaluationDataNumber;

            void parsePartV2(const ::rapidjson::Value &tcbInfo, JsonParser& jsonParser);


            explicit TcbInfo(const std::string& jsonString);
        };
    }

    namespace x509
    {
        class Certificate;

        class DistinguishedName
        {
        public:
            DistinguishedName() = default;
            DistinguishedName(const std::string& raw,
                              const std::string& commonName,
                              const std::string& countryName,
                              const std::string& organizationName,
                              const std::string& locationName,
                              const std::string& stateName);
            virtual ~DistinguishedName() = default;

            virtual bool operator==(const DistinguishedName& other) const;
            virtual bool operator!=(const DistinguishedName& other) const;

            virtual const std::string& getRaw() const;
            virtual const std::string& getCommonName() const;
            virtual const std::string& getCountryName() const;
            virtual const std::string& getOrganizationName() const;
            virtual const std::string& getLocationName() const;
            virtual const std::string& getStateName() const;

        private:
            std::string _raw;
            std::string _commonName;
            std::string _countryName;
            std::string _organizationName;
            std::string _locationName;
            std::string _stateName;

            explicit DistinguishedName(X509_name_st *x509Name);

            friend class Certificate;
        };

        class Validity
        {
        public:
            Validity() = default;
            Validity(std::time_t notBeforeTime, std::time_t notAfterTime);
            virtual ~Validity() = default;

            virtual bool operator==(const Validity& other) const;

            virtual std::time_t getNotBeforeTime() const;
            virtual std::time_t getNotAfterTime() const;

        private:
            std::time_t _notBeforeTime;
            std::time_t _notAfterTime;
        };

        class Extension
        {
        public:
            enum class Type : int
            {
                NONE = -1,
                PPID = 0,
                CPUSVN,
                PCESVN,
                PCEID,
                FMSPC,
                SGX_TYPE,
                DYNAMIC_PLATFORM,
                CACHED_KEYS,
                TCB,
                SGX_TCB_COMP01_SVN,
                SGX_TCB_COMP02_SVN,
                SGX_TCB_COMP03_SVN,
                SGX_TCB_COMP04_SVN,
                SGX_TCB_COMP05_SVN,
                SGX_TCB_COMP06_SVN,
                SGX_TCB_COMP07_SVN,
                SGX_TCB_COMP08_SVN,
                SGX_TCB_COMP09_SVN,
                SGX_TCB_COMP10_SVN,
                SGX_TCB_COMP11_SVN,
                SGX_TCB_COMP12_SVN,
                SGX_TCB_COMP13_SVN,
                SGX_TCB_COMP14_SVN,
                SGX_TCB_COMP15_SVN,
                SGX_TCB_COMP16_SVN
            };

            Extension();
            Extension(int nid,
                      const std::string& name,
                      const std::vector<uint8_t>& value) noexcept;
            virtual ~Extension() = default;

            virtual bool operator==(const Extension&) const;
            virtual bool operator!=(const Extension&) const;

            virtual int getNid() const;
            virtual const std::string& getName() const;
            virtual const std::vector<uint8_t>& getValue() const;

        private:
            int _nid;
            std::string _name;
            std::vector<uint8_t> _value;

            explicit Extension(X509_EXTENSION *ext);

            friend class Certificate;
            friend class UnitTests;
        };

        class Signature
        {
        public:
            Signature();
            Signature(const std::vector<uint8_t>& rawDer,
                      const std::vector<uint8_t>& r,
                      const std::vector<uint8_t>& s);
            virtual ~Signature() = default;

            virtual bool operator==(const Signature& other) const;

            virtual const std::vector<uint8_t>& getRawDer() const;
            virtual const std::vector<uint8_t>& getR() const;
            virtual const std::vector<uint8_t>& getS() const;

        private:
            std::vector<uint8_t> _rawDer;
            std::vector<uint8_t> _r;
            std::vector<uint8_t> _s;

            explicit Signature(const ASN1_BIT_STRING* pSig);

            friend class Certificate;
        };

        class Certificate
        {
        public:
            Certificate();
            Certificate(const Certificate &) = default;
            Certificate(Certificate &&) = default;
            virtual ~Certificate() = default;

            Certificate& operator=(const Certificate &) = delete;
            Certificate& operator=(Certificate &&) = default;
            virtual bool operator==(const Certificate& other) const;

            virtual unsigned int getVersion() const;
            virtual const std::vector<uint8_t>& getSerialNumber() const;
            virtual const DistinguishedName& getSubject() const;
            virtual const DistinguishedName& getIssuer() const;
            virtual const Validity& getValidity() const;
            virtual const std::vector<Extension>& getExtensions() const;
            virtual const std::string getPem() const;

            /**
             * Get Certificate info (TBS) binary value that should be verifiable
             * using signature and public key with SHA256 algorithm
             * @return Vector of bytes representing certificate info
             */
            virtual const std::vector<uint8_t>& getInfo() const;
            virtual const Signature& getSignature() const;

            /**
             * Get public key bytes <header[1B]><x[32B]><y[32B]>
             * @return Vector of bytes
             */
            virtual const std::vector<uint8_t>& getPubKey() const;

            /**
             * Parse PEM encoded X.509 certificate
             * @param pem PEM encoded X.509 certificate
             * @return Certificate instance
             *
             * @throws intel::sgx::dcap::parser::FormatException in case of parsing error
             */
            static Certificate parse(const std::string& pem);

        protected:
            unsigned int _version;
            DistinguishedName _subject;
            DistinguishedName _issuer;
            Validity _validity;
            std::vector<Extension> _extensions;
            Signature _signature;
            std::vector<uint8_t> _serialNumber;
            std::vector<uint8_t> _pubKey;
            std::vector<uint8_t> _info;
            std::string _pem;

            explicit Certificate(const std::string& pem);

        private:
            void setInfo(X509* x509);
            void setVersion(const X509* x509);
            void setSerialNumber(const X509* x509);
            void setSubject(const X509* x509);
            void setIssuer(const X509* x509);
            void setValidity(const X509* x509);
            void setExtensions(const X509* x509);
            void setSignature(const X509* x509);
            void setPublicKey(const X509* x509);
        };

        enum SgxType
        {
            Standard
        };

        class PckCertificate;

        class Tcb
        {
        public:
            Tcb() = default;
            Tcb(const std::vector<uint8_t>& cpusvn,
                const std::vector<uint8_t>& cpusvnComponents,
                unsigned int pcesvn);
            virtual ~Tcb() = default;

            virtual bool operator==(const Tcb& other) const;

            /**
             * Get SVN component value at given position
             * @param componentNumber
             * @return the value for given component
             *
             * @throws intel::sgx::dcap::parser::FormatException when out of range
             */
            virtual unsigned int getSgxTcbComponentSvn(unsigned int componentNumber) const;
            virtual const std::vector<uint8_t>& getSgxTcbComponents () const;
            virtual unsigned int getPceSvn() const;
            virtual const std::vector<uint8_t>& getCpuSvn() const;

        private:
            std::vector<uint8_t> _cpuSvn;
            std::vector<uint8_t> _cpuSvnComponents;
            unsigned int _pceSvn;

            explicit Tcb(const ASN1_TYPE *);

            friend class PckCertificate;
        };

        class PckCertificate : public Certificate
        {
        public:
            PckCertificate() = default;
            PckCertificate(const PckCertificate &) = delete;
            PckCertificate(PckCertificate &&) = default;
            virtual ~PckCertificate() = default;

            /**
             * Upcast Certificate to PCK certificate
             * @param certificate
             *
             * @throws intel::sgx::dcap::parser::FormatException in case of upcasting error
             */
            explicit PckCertificate(const Certificate& certificate);

            PckCertificate& operator=(const PckCertificate &) = delete;
            PckCertificate& operator=(PckCertificate &&) = default;
            virtual bool operator==(const PckCertificate& other) const;

            virtual const std::vector<uint8_t>& getPpid() const;
            virtual const std::vector<uint8_t>& getPceId() const;
            virtual const std::vector<uint8_t>& getFmspc() const;
            virtual SgxType getSgxType() const;
            virtual const Tcb& getTcb() const;

            /**
             * Parse PEM encoded X.509 PCK certificate
             * @param pem PEM encoded X.509 certificate
             * @return PCK certificate instance
             *
             * @throws intel::sgx::dcap::parser::FormatException in case of parsing error
             */
            static PckCertificate parse(const std::string& pem);

        private:
            std::vector<uint8_t> _ppid;
            std::vector<uint8_t> _pceId;
            std::vector<uint8_t> _fmspc;
            Tcb _tcb;
            SgxType _sgxType;

            void setMembers();

            explicit PckCertificate(const std::string& pem);
        };
    }

    class FormatException : public std::logic_error
    {
    public:
        using std::logic_error::logic_error;
    };

    class InvalidExtensionException : public std::logic_error
    {
    public:
        using std::logic_error::logic_error;
    };

}}}}

#endif // SGX_DCAP_PARSERS_H_