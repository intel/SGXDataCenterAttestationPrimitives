#!/usr/bin/env node
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
const morgan = require('morgan');
const express = require('express');
const fs = require('fs');
const logger = require('./utils/Logger.js');
const https = require('https');
const schedule = require('node-schedule');
const bodyParser = require('body-parser');
const routes = require('./routes');
const Auth = require('./middleware/auth.js');
const ErrorHandling = require('./middleware/error.js');
const RefreshService = require('./services/refreshService.js');

// Create ./logs if it doesn't exist
fs.mkdir('./logs', (err)=> {/* do nothing*/});

const app = express();

// logger
app.use(morgan('combined', {stream: logger.stream}));

// body parser middleware, this will let us get the data from a POST
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json({limit:"200000kb"}));

// authentication middleware
app.get('/sgx/certification/v2/platforms', Auth.validateAdmin);
app.post('/sgx/certification/v2/platforms', Auth.validateUser);
app.use('/sgx/certification/v2/platformcollateral', Auth.validateAdmin);
app.use('/sgx/certification/v2/refresh', Auth.validateAdmin);

// router
app.use('/sgx/certification/v2', routes);

// error handling middleware
app.use(ErrorHandling.errorHandling);

// Start HTTPS server 
try {
    var privateKey = fs.readFileSync('./ssl_key/private.pem', 'utf8');
    var certificate = fs.readFileSync('./ssl_key/file.crt', 'utf8');
} catch (err){
    logger.error("The private key or certificate for HTTPS server is missing.");
}
const credentials = {key: privateKey, cert: certificate};
const httpsServer = https.createServer(credentials, app);
httpsServer.listen(config.get('HTTPS_PORT'), config.get('hosts'), function() {
    logger.info('HTTPS Server is running on: https://localhost:' + config.get('HTTPS_PORT'));
});

// Schedule the refresh job in cron-style
// # ┌───────────── minute (0 - 59)
// # │ ┌───────────── hour (0 - 23)
// # │ │ ┌───────────── day of the month (1 - 31)
// # │ │ │ ┌───────────── month (1 - 12)
// # │ │ │ │ ┌───────────── day of the week (0 - 6) (Sunday to Saturday;
// # │ │ │ │ │                                   7 is also Sunday on some systems)
// # │ │ │ │ │
// # │ │ │ │ │
// # * * * * * command to execute
//
schedule.scheduleJob(config.get('RefreshSchedule'), RefreshService.scheduledRefresh);

module.exports = app;

