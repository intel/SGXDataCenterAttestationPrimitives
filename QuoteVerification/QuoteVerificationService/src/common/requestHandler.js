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

const _ = require('lodash');
const retry = require('retry');
const url = require('fast-url-parser');

const nodeRequest = require('./nodeRequestHandler');
const responseUtils = require('../util/responseUtils');
const httpStatusCodes = require('./httpStatusCodes');
const detailedErrorString = require('./detailedErrorString');
const { HttpError, HttpNoRetryError, RuntimeError } = require('./restClientErrors');

class RequestHandler {

    constructor(config) {
        this.config = config;
    }

    /* Request prepare */

    removeHeaderContentLength(headers) {
        const CONTENT_LENGTH_FIELD = 'Content-Length';
        const explicitHeaders = _.clone(headers || {});

        for (const headerName in explicitHeaders) {
            if (headerName.toLowerCase() === CONTENT_LENGTH_FIELD.toLowerCase()) {
                // Json flag sets content length automatically
                delete explicitHeaders[headerName];
            }
        }

        return explicitHeaders;
    }

    async prepareRequestOptions(method, requestUrl, headers) {
        const options = _.clone(this.config.options);
        options.protocol = requestUrl.protocol;
        options.method = method;
        options.host = this.config.host;
        options.port = this.config.port;
        options.path = requestUrl.path;
        options.headers = this.removeHeaderContentLength(headers);
        return options;
    }

    /* Response status */

    isSuccessStatusCode(statusCode) {
        return statusCode === httpStatusCodes.SUCCESS || statusCode === httpStatusCodes.CREATED;
    }

    isNotFatalError(error) {
        const statusCodeError = error.status >= httpStatusCodes.INTERNAL_SERVER_ERROR;
        const notHttpError = !(error instanceof HttpError);
        const httpNoRetryError = error instanceof HttpNoRetryError;
        return !httpNoRetryError && (statusCodeError || notHttpError);
    }

    /* Request retry utils */

    createRetryOperation() {
        const maxTimeout = (this.config.retryDelay * (1 + this.config.factor + Math.pow(this.config.factor, 2)));

        return retry.operation({
            maxTimeout,
            minTimeout: this.config.retryDelay,
            retries:    this.config.retryCount, // Previous version counter was lower
            factor:     this.config.factor
        });
    }

    async sendRequest(logger, method, path, body, headers, queryParams, isResponseBinary = false) {
        const requestUrl = url.parse(url.format({
            protocol: this.config.protocol,
            hostname: this.config.host,
            port:     this.config.port,
            pathname: path,
            query:    queryParams
        }));
        const self = this;
        const options = await this.prepareRequestOptions(method, requestUrl, headers);
        logger.info(`Sending request to: ${requestUrl.href}`);

        return nodeRequest(options, body, isResponseBinary)
            .then(async res => {

                if (responseUtils.statusCodeNotExists(res)) {
                    throw new RuntimeError('Empty status code received');
                }

                if (!self.isSuccessStatusCode(res.statusCode)) {
                    throw new HttpError(`Response status unrecognized ${res.statusCode}`, res.statusCode, res.body, res.headers);
                }
                const result = {
                    status:  responseUtils.getStatusCodeSafely(res),
                    body:    res.body,
                    headers: res.headers
                };

                if (result.headers !== undefined && 'request-id' in result.headers && logger.context.reqId !== `[reqId=${result.headers['request-id']}]`) {
                    logger.info(`Related request ID: ${result.headers['request-id']}`);
                }
                /* istanbul ignore else */
                if (logger.isTraceEnabled()) {
                    logger.trace('Returned response:', result.status, JSON.stringify(result.body));
                }

                return result;
            })
            .catch(async error => {
                logger.error(`Error while trying to ${method} ${requestUrl.href}: ${detailedErrorString(error)}`);
                if (error instanceof HttpError || error instanceof HttpNoRetryError) {
                    throw error;
                }

                throw new RuntimeError(error.message, { code: error.code, stack: error.stack });
            });
    }

    async sendRequestWithRetries(logger, method, path, jsonBody, headers, queryParams, isResponseBinary = false) {
        const retryConditionFn = this.isNotFatalError;
        return this.sendRequestWithRetriesBase(logger, method, path, jsonBody, headers, queryParams, isResponseBinary, retryConditionFn);
    }

    isECONNRESET(err) {
        // return err.message === 'socket hang up';
        return err.details && err.details.code === 'ECONNRESET'; // more general than above
    }

    async sendRequestWithRetriesOnConnectionReset(logger, method, path, jsonBody, headers, queryParams, isResponseBinary = false) {
        const retryConditionFn = this.isECONNRESET;
        return this.sendRequestWithRetriesBase(logger, method, path, jsonBody, headers, queryParams, isResponseBinary, retryConditionFn);
    }

    async sendRequestWithRetriesBase(logger, method, path, jsonBody, headers, queryParams, isResponseBinary, retryConditionFn) {
        const self = this;
        const operation = self.createRetryOperation(this.config);

        let handlers = null;
        const promise = new Promise((resolve, reject) => {
            handlers = {
                resolve,
                reject
            };
        });

        operation.attempt(currentAttempt => {
            const sendRequest = self.sendRequest(logger, method, path, jsonBody, headers, queryParams, isResponseBinary);

            sendRequest
                .then(async result => {
                    return handlers.resolve(result);
                })
                .catch(async error => {
                    if (operation.retry(retryConditionFn(error))) {
                        const retryInfo = `Retrying call host with address: ${self.config.host}:${self.config.port} ` +
                            `... Attempt number: ${currentAttempt} out of ${self.config.retryCount}`;
                        logger.warn(error, `Request ended with an error. ${retryInfo}`);

                        return;
                    }

                    if (error instanceof HttpError || error instanceof HttpNoRetryError || error instanceof RuntimeError) {
                        return handlers.reject(error);
                    }

                    return handlers.reject(new RuntimeError(error.message));
                });
        });

        return promise;
    }
}

module.exports = RequestHandler;
