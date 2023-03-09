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

const random = require('./../util/random');
const {
    STATUS_SERVICE_UNAVAILABLE
} = require('./response').STATUSES;

global.currentClients = 0;

function decreaseCurrentClients(log, serviceName, taskType, taskID) {
    global.currentClients--;
    log.info('Decreasing number of clients. Current number: %s', global.currentClients);
    log.trace('STOP task_type: %s.%s task_id: %s', serviceName, taskType, taskID);
}

function handleServiceBusy(ctx) {
    ctx.status = STATUS_SERVICE_UNAVAILABLE.httpCode;
    ctx.body =  { code: 'KO.', message: 'Server too busy.' };
}

module.exports.createRequestManager = (serviceName, maxClients) => {
    return {
        manageRequest(taskType, action) {
            return async(ctx, next) => {
                const taskID = random.uuid();
                if (global.currentClients + 1 <= maxClients) {
                    global.currentClients++;
                    ctx.log.info('Increasing number of clients. Current number: %s', global.currentClients);
                    ctx.log.trace('START task_type: %s.%s task_id: %s', serviceName, taskType, taskID);

                    const log = ctx.log; //ctx is cleared after finish/close
                    ctx.res.on('finish', () => {
                        decreaseCurrentClients(log, serviceName, taskType, taskID);
                    });
                    ctx.res.on('close', () => {
                        if (!ctx.res.writableFinished) {
                            log.error('res.end() was not called. Something bad has happened.');
                            // ctx.res.finished = true;
                            decreaseCurrentClients(log, serviceName, taskType, taskID);
                        }
                    });
                    return action(ctx, next);
                }
                else {
                    ctx.log.info('Too many requests');
                    ctx.log.trace('Discarding task_type: %s task_id: %s', taskType, taskID);
                    handleServiceBusy(ctx);
                }
            };
        }
    };
};
