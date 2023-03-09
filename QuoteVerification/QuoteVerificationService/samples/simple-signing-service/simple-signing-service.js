/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
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
'use strict';

// DO NOT USE IN PRODUCTION

const https = require('https');
const http = require('http');
const fs = require('fs');
const Koa = require('koa');
const Router = require('koa-router');
const koaBody = require('koa-body');
const crypto = require('crypto');

const app = new Koa();
const router = new Router();
//Sample Configuration
//Load Signing key, to generate the signature over attestation report
const signingKey = fs.readFileSync('sign-key.pem', 'utf-8');
const signingCert = fs.readFileSync('sign-cert.pem', 'utf-8');
const algorithm = 'sha384WithRSAEncryption';

//Load HTTPS keys for this service
const httpsKey = fs.readFileSync('key.pem');
const httpsCert = fs.readFileSync('cert.pem');
const caCertPath = 'qvs-to-sss-client-cert.pem';
const HTTPS_PORT = 8797;
const HTTP_PORT = 8796;
const isMtls = true;

const options = {
    key:                httpsKey,
    cert:               httpsCert,
    ca:                 isMtls ? [fs.readFileSync(caCertPath)] : undefined,
    requestCert:        isMtls,
    rejectUnauthorized: isMtls,
};

router.get('/health', (ctx) => {
    ctx.body = { status: 'OK', version: '0.0.1', lastChecked: new Date(Date.now()).toISOString() };
});

router.post('/sign/attestation-verification-report', (ctx) => {
    console.log('[Request]' + JSON.stringify(ctx.request.body));

    const bodyJsonToString = JSON.stringify(ctx.request.body);
    const signer = crypto.createSign(algorithm);
    signer.update(bodyJsonToString);
    signer.end();
    const signature = signer.sign(signingKey);
    const buff = Buffer.from(signature);
    //Adding extra check to verify if pair sign-key sign-cert is working well just for DEBUG purpose
    crypto.verify(algorithm, Buffer.from(bodyJsonToString), signingCert, signature);
    //returning signature
    ctx.body = { signature: buff.toString('base64') };

    console.log('[Response]' + JSON.stringify(ctx.body));
});

app.use(koaBody())
    .use(router.routes())
    .use(router.allowedMethods());

https.createServer(options, app.callback()).listen(HTTPS_PORT);
http.createServer(app.callback()).listen(HTTP_PORT);

console.log('Server Started: https://localhost:' + HTTPS_PORT);
console.log('Server Started: http://localhost:' + HTTP_PORT);
/**
 * To run Quote Verification Service Docker image you need to override
 * QVS_ATTESTATION_REPORT_SIGNING_CERTIFICATE
 * with value from below log, as it consumes certificate in PEM, UrlEncoded
 */

console.log('Signing Certificate in URL encoded:' + encodeURI(signingCert.toString()));
