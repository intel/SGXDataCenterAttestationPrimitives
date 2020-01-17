/**
 *
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

const { platformsRegService, platformsService }= require('../services');
const PccsError = require('../utils/PccsError.js');
const PCCS_STATUS = require('../constants/pccs_status_code.js');
const Constants = require('../constants');

exports.postPlatforms = async function(req,res,next) {
    try {
        // call registration service
        let platf = await platformsRegService.registerPlatforms(req.body);

        // send response
        res.status(PCCS_STATUS.PCCS_STATUS_SUCCESS[0]).send(PCCS_STATUS.PCCS_STATUS_SUCCESS[1]);
    }
    catch(err) {
        next(err);
    }
};

exports.getPlatforms = async function(req,res,next) {
    try {
        let platformsJson;
        if (!req.query.fmspc) {
            // call registration service
            platformsJson = await platformsRegService.getRegisteredPlatforms();
        }
        else {
            let fmspc = req.query.fmspc;
            if (fmspc.length < 2 || fmspc[0] != '[' || fmspc[fmspc.length-1] != ']') 
                throw new PccsError(PCCS_STATUS.PCCS_STATUS_INVALID_REQ);
            fmspc = fmspc.substring(1, fmspc.length-1).trim().toUpperCase();
            let fmspc_arr;
            if (fmspc.length > 0)
                fmspc_arr = fmspc.split(',');
            else fmspc_arr = [];
            platformsJson = await platformsService.getCachedPlatforms(fmspc_arr);
        }

        // send response
        res.header(Constants.HTTP_HEADER_PLATFORM_COUNT, platformsJson.length)
           .status(PCCS_STATUS.PCCS_STATUS_SUCCESS[0])
           .send(platformsJson);
        
        if (!req.query.fmspc) {
            await platformsRegService.deleteRegisteredPlatforms();
        }
    }
    catch(err) {
        next(err);
    }
};

