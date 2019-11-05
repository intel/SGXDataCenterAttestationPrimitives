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

#ifndef SGXECDSAATTESTATION_TCBINFOGENERATOR_H
#define SGXECDSAATTESTATION_TCBINFOGENERATOR_H

#include <string>

extern const std::string validTcb;
extern const std::string validUpToDateStatus;
extern const std::string validOutOfDateStatus;
extern const std::string validRevokedStatus;
extern const std::string validConfigurationNeededStatus;
extern const std::string validTcbLevelTemplate;
extern const std::string validTcbInfoTemplate;
extern const std::string validSignatureTemplate;

/**
 * Generates tcbInfo json based on given template and tcb json
 * @param tcbLevelTemplate template which contains two %s which will be replaced with tcb and status
 * @param tcb json of tcb content
 * @param status tcb status json
 * @return TcbInfo as jsons string
 */
std::string generateTcbLevel(const std::string& tcbLevelTemplate = validTcbLevelTemplate,
                             const std::string& tcb = validTcb,
                             const std::string& status = validUpToDateStatus);

/**
 * Generates tcbInfo json based on given template and tcb json
 * @param tcbInfoTemplate template which contains two %s which will be replaced with tcbJson and signature
 * @param tcbLevelsJson json of TcbLevels array content
 * @param signature signature over tcbInfo body
 * @return TcbInfo as json string
 */
std::string generateTcbInfo(const std::string& tcbInfoTemplate = validTcbInfoTemplate,
                            const std::string& tcbLevelsJson = generateTcbLevel(),
                            const std::string& signature = validSignatureTemplate);

#endif //SGXECDSAATTESTATION_TCBINFOGENERATOR_H
