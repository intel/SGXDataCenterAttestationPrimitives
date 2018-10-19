/******************************************************************************
 *                           INTEL CONFIDENTIAL                               *
 *                    Copyright 2018 Intel Corporation.                       *
 *                                                                            *
 *  This software and the related documents are Intel copyrighted materials,  *
 *  and  your  use  of  them  is governed by the express license under which  *
 *  they  were  provided  to  you  (License). Unless  the  License  provides  *
 *  otherwise,  you may not use, modify, copy, publish, distribute, disclose  *
 *  or  transmit  this  software  or  the  related documents without Intel's  *
 *  prior  written  permission.  This  software  and  the  related documents  *
 *  are  provided  as  is, with no express or implied warranties, other than  *
 *  those that are expressly stated in the License.                           *
 *****************************************************************************/

#ifndef SGXECDSAATTESTATION_QEIDENTITYGENERATOR_H
#define SGXECDSAATTESTATION_QEIDENTITYGENERATOR_H

#include <string>

namespace testutils{

extern const std::string validQEIdentityTemplate;
extern const std::string validSignatureTemplate;

/**
 * Generates QEIdentity json based on given templates
 * @param signature signature over qeIdentity body
 * @return QEIdentity as json string
 */
std::string generateQEIdentity(const std::string& tcbLevelTemplate = validQEIdentityTemplate,
                               const std::string& signature = validSignatureTemplate);

}

#endif //SGXECDSAATTESTATION_QEIDENTITYGENERATOR_H
