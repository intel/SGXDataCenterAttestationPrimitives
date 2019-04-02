const config = require('./config.json');
var rp = require('request-promise');

exports.getCert=function(enc_ppid,cpusvn,pcesvn,pceid){
    var options = {
        uri: config.uri + 'pckcert',
        qs: {
            encrypted_ppid:enc_ppid,
            cpusvn:cpusvn,
            pcesvn:pcesvn,
            pceid:pceid
        },
        method: 'GET',
        resolveWithFullResponse: true, 
        headers: {'Ocp-Apim-Subscription-Key':config.ApiKey}
    };

    return new Promise((resolve,reject)=>{
        rp(options)
        .then(function (response) {
            // GET succeeded...
            resolve(response);
        })
        .catch(function (err) {
            // GET failed...
            reject(err);
        });
    })
};

exports.getPckCrl=function(ca){
    var options = {
        uri: config.uri + 'pckcrl',
        qs: {
            ca:ca
        },
        method: 'GET',
        resolveWithFullResponse: true 
    };

    return new Promise((resolve,reject)=>{
        rp(options)
        .then(function (response) {
            // GET succeeded...
            resolve(response);
        })
        .catch(function (err) {
            // GET failed...
            reject(err);
        });
    })
};

exports.getTcb=function(fmspc){
    var options = {
        uri: config.uri + 'tcb',
        qs: {
            fmspc:fmspc
        },
        method: 'GET',
        resolveWithFullResponse: true 
    };

    return new Promise((resolve,reject)=>{
        rp(options)
        .then(function (response) {
            // GET succeeded...
            resolve(response);
        })
        .catch(function (err) {
            // GET failed...
            reject(err);
        });
    })
};

exports.getQEIdentity=function(){
    var options = {
        uri: config.uri + 'qe/identity',
        qs: {
        },
        method: 'GET',
        resolveWithFullResponse: true 
    };

    return new Promise((resolve,reject)=>{
        rp(options)
        .then(function (response) {
            // GET succeeded...
            resolve(response);
        })
        .catch(function (err) {
            // GET failed...
            reject(err);
        });
    })
};

