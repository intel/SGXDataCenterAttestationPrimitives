/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
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


const config = require('config');
const request = require('request');
const rp = require('request-promise');
const logger = require('../utils/Logger.js');
const PccsError = require('../utils/PccsError.js');
const PCCS_STATUS = require('../constants/pccs_status_code.js');

const HTTP_TIMEOUT = 60000;  // 60 seconds 

do_request = async function(options, src) {
    try {
        let response =  await rp(options);
        logger.info('Request-ID is : ' + response.headers['request-id'] + ' ' + src);
        return response;
    }
    catch(err) {
        if (err.response && err.response.headers) {
            logger.info('Request-ID is : ' + err.response.headers['request-id'] + ' ' + src);
        }
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_PCS_ACCESS_FAILURE);
    }
}

exports.getCert=async function(enc_ppid,cpusvn,pcesvn,pceid){
    const options = {
        uri: config.get('uri')+ 'pckcert',
        proxy: config.get('proxy'),
        qs: {
            encrypted_ppid:enc_ppid,
            cpusvn:cpusvn,
            pcesvn:pcesvn,
            pceid:pceid
        },
        method: 'GET',
        timeout: HTTP_TIMEOUT,
        resolveWithFullResponse: true, 
        headers: {'Ocp-Apim-Subscription-Key':config.get('ApiKey')}
    };

    logger.debug('getCert......');
    logger.debug('enc_ppid : ' + enc_ppid);
    logger.debug('cpusvn : ' + cpusvn);
    logger.debug('pcesvn : ' + pcesvn);
    logger.debug('pceid : ' + pceid);

    return do_request(options, 'pckcert');
};

exports.getCerts=async function(enc_ppid,pceid){
    const options = {
        uri: config.get('uri')+ 'pckcerts',
        proxy: config.get('proxy'),
        qs: {
            encrypted_ppid:enc_ppid,
            pceid:pceid
        },
        method: 'GET',
        timeout: HTTP_TIMEOUT,
        resolveWithFullResponse: true, 
        headers: {'Ocp-Apim-Subscription-Key':config.get('ApiKey')}
    };

    logger.debug('getCerts......');
    logger.debug('enc_ppid : ' + enc_ppid);
    logger.debug('pceid : ' + pceid);

    return do_request(options, 'pckcerts');
};

exports.getPckCrl=async function(ca){
    const options = {
        uri: config.get('uri')+ 'pckcrl',
        proxy: config.get('proxy'),
        qs: {
            ca:ca
        },
        method: 'GET',
        timeout: HTTP_TIMEOUT,
        resolveWithFullResponse: true 
    };

    logger.debug('getPckCrl......');
    logger.debug('ca : ' + ca);

    return do_request(options, 'pckcrl');
};

exports.getTcb=async function(fmspc){
    const options = {
        uri: config.get('uri')+ 'tcb',
        proxy: config.get('proxy'),
        qs: {
            fmspc:fmspc
        },
        method: 'GET',
        timeout: HTTP_TIMEOUT,
        resolveWithFullResponse: true 
    };

    logger.debug('getTcb......');
    logger.debug('fmspc : ' + fmspc);

    return do_request(options, 'tcb');
};

exports.getQEIdentity=async function(){
    const options = {
        uri: config.get('uri')+ 'qe/identity',
        proxy: config.get('proxy'),
        qs: {
        },
        method: 'GET',
        timeout: HTTP_TIMEOUT,
        resolveWithFullResponse: true 
    };

    logger.debug('getQEIdentity......');

    return do_request(options, 'qe/identity');
};

exports.getQvEIdentity=async function(){
    const options = {
        uri: config.get('uri')+ 'qve/identity',
        proxy: config.get('proxy'),
        qs: {
        },
        method: 'GET',
        timeout: HTTP_TIMEOUT,
        resolveWithFullResponse: true 
    };

    logger.debug('getQvEIdentity......');

    return do_request(options, 'qve/identity');
};

exports.getFileFromUrl=async function(uri){
    const options = {
        uri: uri,
        proxy: config.get('proxy'),
        method: 'GET',
        timeout: HTTP_TIMEOUT,
        encoding: null 
    };

    logger.debug('getFileFromUrl......' + uri);

    try {
        let response = await rp(options);
        return Buffer.from(response, 'utf8');
    }
    catch(err) {
        throw err;
    }
};
