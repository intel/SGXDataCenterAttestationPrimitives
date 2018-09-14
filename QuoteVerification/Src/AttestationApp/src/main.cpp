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

#include <iostream>
#include <sstream>
#include <memory>
#include "AppCore.h"
#include "AppOptions.h"
#include "AppOptionsParser.h"
#include "AttestationLibraryAdapter.h"
#include "FileReader.h"
#include "ColorUtils.h"

int main(int argc, char* argv[])
{
    auto libAdapter = std::make_shared<intel::sgx::qvl::AttestationLibraryAdapter>();
    auto fileReader = std::make_shared<intel::sgx::qvl::FileReader>();
    intel::sgx::qvl::AppCore app(libAdapter, fileReader);

    std::stringstream logger;


    intel::sgx::qvl::AppOptionsParser optionsParser;
    auto options = optionsParser.parse(argc, argv, logger);
    if(nullptr == options)
    {
        std::cout << logger.str();
        return 0;
    }

    std::cout << "Running QVL version: " << app.version() << "\n";
    bool result = app.runVerification(*options, logger);
    auto color = result ? term::color::fg::green : term::color::fg::red;
    std::cout << color << "Verification results: " << std::boolalpha << result << std::noboolalpha << term::color::fg::reset << "\n\n";
    std::cout << "AppLogs:\n" << logger.str() << std::endl;
    return 0;
}
