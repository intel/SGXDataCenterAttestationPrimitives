/*
* Copyright (c) 2018, Intel Corporation
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
*    * Redistributions of source code must retain the above copyright notice,
*      this list of conditions and the following disclaimer.
*    * Redistributions in binary form must reproduce the above copyright
*      notice, this list of conditions and the following disclaimer in the
*      documentation and/or other materials provided with the distribution.
*    * Neither the name of Intel Corporation nor the names of its contributors
*      may be used to endorse or promote products derived from this software
*      without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef SGXECDSAATTESTATION_QEIDENTITYJSONGENERATOR_H
#define SGXECDSAATTESTATION_QEIDENTITYJSONGENERATOR_H

#include <string>
#include <array>
#include <vector>
#include <QuoteVerification/ByteOperands.h>
#include <QuoteGenerator.h>
#include <random>

namespace
{
    uint8_t getRandomNumber() {
        return (rand() % 9) + 1;
    }

    std::vector<uint8_t> generateRandomUint8Vector(std::size_t SIZE) {
        std::vector<uint8_t> vector;
        std::default_random_engine generator;
        std::uniform_int_distribution<uint8_t > distribution(0, UINT8_MAX);
        for(auto i = 0; i < SIZE; i++)
        {
            vector.push_back(distribution(generator));
        }
        return vector;
    }
};

std::string toHexString(const std::vector<uint8_t> &vector);

class QEIdentityVectorModel {
public:
    int version;
    std::string issueDate;
    std::string nextUpdate;
    std::vector<uint8_t> miscselect;
    std::vector<uint8_t> miscselectMask;
    std::vector<uint8_t> attributes;
    std::vector<uint8_t> attributesMask;

    std::vector<uint8_t> mrenclave;
    std::vector<uint8_t> mrsigner;
    uint8_t isvprodid;
    uint8_t isvsvn;

    QEIdentityVectorModel() {
        version = 1;
        issueDate = "2018-08-22T12:00:00Z";
        nextUpdate = "2029-08-22T12:00:00Z";

        isvprodid = getRandomNumber();
        isvsvn = getRandomNumber();
        attributes = generateRandomUint8Vector(16);
        mrsigner = generateRandomUint8Vector(32);
        mrenclave = generateRandomUint8Vector(32);
        miscselect = generateRandomUint8Vector(4);

        miscselectMask = miscselect;
        attributesMask = attributes;
    }

    std::string toJSON();
    void applyTo(intel::sgx::qvl::test::QuoteGenerator::EnclaveReport& enclaveReport);
};

class QEIdentityStringModel
{
public:
    std::string version;
    std::string issueDate;
    std::string nextUpdate;
    std::string miscselect;
    std::string miscselectMask;
    std::string attributes;
    std::string attributesMask;

    std::string mrenclave;
    std::string mrsigner;
    std::string isvprodid;
    std::string isvsvn;

    QEIdentityStringModel() : QEIdentityStringModel(QEIdentityVectorModel())
    {}

    explicit QEIdentityStringModel(QEIdentityVectorModel vectorModel) {
        version = std::to_string(vectorModel.version);
        issueDate = vectorModel.issueDate;
        nextUpdate = vectorModel.nextUpdate;
        miscselect = toHexString(vectorModel.miscselect);
        miscselectMask = toHexString(vectorModel.miscselectMask);
        attributes = toHexString(vectorModel.attributes);
        mrenclave = toHexString(vectorModel.mrenclave);
        mrsigner = toHexString(vectorModel.mrsigner);
        isvprodid = std::to_string(vectorModel.isvprodid);
        isvsvn = std::to_string(vectorModel.isvsvn);
    }

    std::string toJSON();
};

uint32_t vectorToUint32(const std::vector<uint8_t> input);

std::string qeIdentityJsonWithSignatureGenerator(const std::string &qeIdentityBody, const std::string &signature);

void removeWordFromString(std::string word, std::string &input);

#endif // SGXECDSAATTESTATION_QEIDENTITYJSONGENERATOR_H