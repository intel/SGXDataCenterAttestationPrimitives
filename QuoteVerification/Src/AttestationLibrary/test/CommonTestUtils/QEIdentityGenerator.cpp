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

#include "QEIdentityGenerator.h"

namespace testutils{

const std::string validQEIdentityTemplate = R"json({
        "qeIdentity": {
            "version": 1,
            "issueDate": "2018-10-04T11:10:45Z",
            "nextUpdate": "2019-06-21T12:36:02Z",
            "miscselect": "8fa64472",
            "miscselectMask": "0000fffa",
            "attributes": "1254863548af4a6b2fcc2d3244784452",
            "attributesMask": "ffffffffffffffffffffffffffffffff",
            "mrsigner": "aaff34ffa51981951a61d616b16c16f1651c6516e51f651d26a6166ed5679c79",
            "isvprodid": 3,
            "isvsvn": 22
        },
        %s})json";

const std::string validSignatureTemplate = R"json("signature": "fb1530326344ee4baded1120a7a07b1c7c46941cf5f8abff36a63492610e17f5b9d0f8f8b4b9bf06932e1220a74b72e2ab27d14d8bbfe69334046b38363bb568")json";

std::string generateQEIdentity(const std::string& qeIdentityTemplate, const std::string& signature)
{
    auto jsonSize = qeIdentityTemplate.length() + signature.length() + 1;
    char qeIdentity[jsonSize];
    sprintf(qeIdentity, qeIdentityTemplate.c_str(), signature.c_str());
    return std::string(qeIdentity);
}

}
