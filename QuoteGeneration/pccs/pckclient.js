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


const config = require('config');
const rp = require('request-promise');
const winston = require('./winston');
const request = require('request');

const HTTP_TIMEOUT = 60000;  // 60 seconds 

exports.getCert=function(enc_ppid,cpusvn,pcesvn,pceid){
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

    winston.debug('getCert......');
    winston.debug('enc_ppid : ' + enc_ppid);
    winston.debug('cpusvn : ' + cpusvn);
    winston.debug('pcesvn : ' + pcesvn);
    winston.debug('pceid : ' + pceid);

    return new Promise((resolve,reject)=>{
        rp(options)
        .then(function (response) {
            // GET succeeded...
            winston.info('Request-ID is : ' + response.headers['request-id']);
            resolve(response);
        })
        .catch(function (err) {
            // GET failed...
            if (err.response && err.response.headers) {
                winston.info('Request-ID is : ' + err.response.headers['request-id']);
            }
            reject(err);
        });
    })
};

exports.getPckCrl=function(ca){
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

    winston.debug('getPckCrl......');
    winston.debug('ca : ' + ca);

    return new Promise((resolve,reject)=>{
        rp(options)
        .then(function (response) {
            // GET succeeded...
            winston.info('Request-ID is : ' + response.headers['request-id']);
            resolve(response);
        })
        .catch(function (err) {
            // GET failed...
            if (err.response && err.response.headers) {
                winston.info('Request-ID is : ' + err.response.headers['request-id']);
            }
            reject(err);
        });
    })
};

exports.getTcb=function(fmspc){
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

    winston.debug('getTcb......');
    winston.debug('fmspc : ' + fmspc);

    return new Promise((resolve,reject)=>{
        rp(options)
        .then(function (response) {
            // GET succeeded...
            winston.info('Request-ID is : ' + response.headers['request-id']);
            resolve(response);
        })
        .catch(function (err) {
            // GET failed...
            if (err.response && err.response.headers) {
                winston.info('Request-ID is : ' + err.response.headers['request-id']);
            }
            reject(err);
        });
    })
};

exports.getQEIdentity=function(){
    const options = {
        uri: config.get('uri')+ 'qe/identity',
        proxy: config.get('proxy'),
        qs: {
        },
        method: 'GET',
        timeout: HTTP_TIMEOUT,
        resolveWithFullResponse: true 
    };

    winston.debug('getQEIdentity......');

    return new Promise((resolve,reject)=>{
        rp(options)
        .then(function (response) {
            // GET succeeded...
            winston.info('Request-ID is : ' + response.headers['request-id']);
            resolve(response);
        })
        .catch(function (err) {
            // GET failed...
            if (err.response && err.response.headers) {
                winston.info('Request-ID is : ' + err.response.headers['request-id']);
            }
            reject(err);
        });
    })
};

exports.getQvEIdentity=function(){
    const options = {
        uri: config.get('uri')+ 'qve/identity',
        proxy: config.get('proxy'),
        qs: {
        },
        method: 'GET',
        timeout: HTTP_TIMEOUT,
        resolveWithFullResponse: true 
    };

    winston.debug('getQvEIdentity......');

    return new Promise((resolve,reject)=>{
        rp(options)
        .then(function (response) {
            // GET succeeded...
            winston.info('Request-ID is : ' + response.headers['request-id']);
            resolve(response);
        })
        .catch(function (err) {
            // GET failed...
            if (err.response && err.response.headers) {
                winston.info('Request-ID is : ' + err.response.headers['request-id']);
            }
            reject(err);
        });
    })
};

exports.getFileFromUrl=function(uri){
    const options = {
        uri: uri,
        proxy: config.get('proxy'),
        method: 'GET',
        timeout: HTTP_TIMEOUT,
        encoding: null 
    };

    winston.debug('getFileFromUrl......' + uri);

    return new Promise((resolve,reject)=>{
        rp(options)
        .then(function(res){
            resolve(Buffer.from(res, 'utf8'));
        })
        .catch(function(err){
            reject(err);
        });
    });
};
