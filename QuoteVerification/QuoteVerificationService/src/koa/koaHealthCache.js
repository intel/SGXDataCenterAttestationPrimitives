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

const detailedErrorString = require('../common/detailedErrorString');
const random = require('../util/random');
const clone = require('../util/clone');
const util = require('util');
const {
    STATUS_OK,
    STATUS_NOT_FOUND,
    STATUS_SERVICE_UNAVAILABLE
} = require('./response').STATUSES;

/**
 * IntelliJ IDEA has long lasting bugs: 
 * https://youtrack.jetbrains.com/issue/WEB-31971
 * https://youtrack.jetbrains.com/issue/WEB-52385
 * JSDoc import works for example in Visual Studio Code.
 * 
 * @typedef {import('../jsDoc/types').KoaContext} KoaContext 
 * @typedef {import('../jsDoc/types').Logger} Logger 
 */

/**
 * @typedef {Object} KoaHealthCacheOptions 
 * @property {number}  frequencyMS - how often to run health check methods [milliseconds], default : 5000
 * @property {number}  validityMS - duration after which cached component health status is outdated [milliseconds], default : 20000
 * @property {string}  version - version of the main component that uses health cache functionality
 * @property {Logger}  logger - OBLIGATORY - logger object so that you know what is happening around
 * @property {boolean} details - OPTIONAL - allows adding additional fields to output (.details)
 */

/**
 * Creates health cache object that will contain all data about components and it's children health
 * 
 # @constructor
 * @param {KoaHealthCacheOptions} options
 */
function KoaHealthCache(options) {

    const status = {
        OK:       'OK', // The component responded that it is healthy
        FAILED:   'FAILED', // The component responded that it is not healthy at all
        UNKNOWN:  'UNKNOWN', // There are still no cached reports for this component
        OUTDATED: 'OUTDATED' // Component didn't respond for the very long time
    };

    /**
     * HealthCache handler
     * 
     * @param {KoaContext} ctx
     */
    async function handleRequest(ctx) {
        const logHeader = 'healthCache.handleRequest ';
        ctx.log.trace(`${logHeader}started...`);

        // Resolve components statuses for current moment
        const componentReports = clone(getComponentReports(ctx.log));

        if (componentReports.AttestationService && componentReports.AttestationService['X-IASReport-Signing-Certificate']) {
            ctx.set('X-IASReport-Signing-Certificate', componentReports.AttestationService['X-IASReport-Signing-Certificate']);
            delete componentReports.AttestationService['X-IASReport-Signing-Certificate'];
        }

        if (ctx.params && ctx.params.component) {
            return handleComponentRequest(ctx.params.component, componentReports, options.version, ctx);
        }
        // Respond
        const [httpStatus, response] = buildResponse(componentReports);
        ctx.status = httpStatus;
        ctx.body = response;

        if (response.status !== status.OK || ctx.log.isTraceEnabled()) {
            const logMsg = `${logHeader}done. HTTP status : ${httpStatus}. response : ${JSON.stringify(response)}`;
            const logLvl = response.status === status.OK ? 'trace' : 'warn';
            ctx.log[logLvl](logMsg);
        }
    }

    async function handleComponentRequest(component, componentReports, mainComponentVersion, ctx) {
        ctx.assert(componentReports[component], STATUS_NOT_FOUND.httpCode);
        const retJson = {
            status:      componentReports[component].status,
            version:     mainComponentVersion,
            lastChecked: new Date()
        };
        retJson[component] = componentReports[component];
        ctx.assert(componentReports[component].status === status.OK, STATUS_SERVICE_UNAVAILABLE.httpCode, retJson);
        // Respond
        ctx.status = STATUS_OK.httpCode;
        ctx.body = retJson;
    }

    function isPositiveNumber(value) {
        return _.isNumber(value) && value >= 0;
    }

    // Needed since _.extend does only shallow extend
    function extendRHCResponse(target, source) {
        let extendedComponentStatus = null;

        if (source &&
            target &&
            source.componentStatus &&
            target.componentStatus) {
            extendedComponentStatus = _.extend(target.componentStatus, source.componentStatus);
        }

        const extended = _.extend(target, source);

        if (extendedComponentStatus !== null) {
            extended.componentStatus = extendedComponentStatus;
        }

        return extended;
    }

    // Conditions to check health for components
    const conditions = [];
    // Health results for each component
    const reports = [];

    // Helper array to prevent multiple checks of the same component
    const pending = [];

    // Params to say that health caching is stopped or not
    let stopped = true;

    // Logger is obligatory
    if (!options.logger) {
        const errorMsg = 'healthCache initialization failed - options.logger is obligatory!';
        throw new Error(errorMsg);
    }

    const log = options.logger;

    log.info('healthCache initialization started...');

    // Validate input
    options.frequencyMS = positiveNumberOrDefault(options.frequencyMS, 'options.frequencyMS', 5000);

    options.validityMS = positiveNumberOrDefault(options.validityMS, 'options.validityMS', 20000);

    if (!_.isString(options.version)) {
        options.version = 'UNDEFINED';
        log.warn('options.componentVersion not defined so should be defined by this component health condition');
    }

    log.info('healthCache initialization done.');

    const version = {
        NA: 'NA' // The componentVersion is unknown
    };

    function positiveNumberOrDefault(field, fieldName, defaultValue) {
        if (!isPositiveNumber(field)) {
            log.warn(`${fieldName} not defined - will use default value :${defaultValue}`);
            return defaultValue;
        }
        else {
            log.debug(`${fieldName} = ${field}`);
            return field;
        }
    }

    function stripResult(logger, result) {
        const strippedResult = {};

        if (!result) {
            logger.warn('Healthcheck result is undefined. Setting status to UNKNOWN.');
            strippedResult.status = status.UNKNOWN;
        }
        else {
            if (result.status) {
                strippedResult.status = result.status;
            }
            else {
                logger.warn(`Field 'status' is missing in healthcheck result. Setting it's status to UNKNOWN. Full object: ${JSON.stringify(result)}`);
                strippedResult.status = status.UNKNOWN;
            }
            if (result.version) {
                strippedResult.version = result.version;
            }
            else {
                logger.warn(`Field 'version' is missing in healthcheck result. Setting it's version to NA. Full object: ${JSON.stringify(result)}`);
                strippedResult.version = version.NA;
            }
            if (result.componentStatus) {
                strippedResult.componentStatus = result.componentStatus;
            }
            if (options.details && result.details) {
                strippedResult.details = result.details;
            }
            if (result['X-IASReport-Signing-Certificate']) {
                strippedResult['X-IASReport-Signing-Certificate'] = result['X-IASReport-Signing-Certificate'];
            }
            if (result['X-IASReport-Signing-Certificate-Status']) {
                strippedResult['X-IASReport-Signing-Certificate-Status'] = result['X-IASReport-Signing-Certificate-Status'];
            }
        }
        return strippedResult;
    }

    async function runComponentHealthCheck(logger, reqId, componentHealthCheck) {
        const result = await componentHealthCheck(logger, reqId);
        return stripResult(logger, result);
    }

    function validateResult(logger, logHeader, result) {
        let errorMsg = null;
        if (!_.isString(result.status)) {
            errorMsg = '- result.status [string] field is obligatory!';
        }

        if (!_.isString(result.version)) {
            errorMsg = '- result.componentVersion [string] field is obligatory!';
        }

        if (errorMsg !== null) {
            errorMsg = logHeader + errorMsg;
            throw new Error(errorMsg);
        }
    }

    function createResultHandler(logger, logHeader, componentName, result) {
        logger.trace(`${logHeader}- polling done for component ${componentName}`);
        validateResult(logger, logHeader, result);

        // Remember when the check was made
        result.lastChecked = new Date();

        if (result.status !== status.OK || logger.isTraceEnabled()) {
            const logMsg = `[${componentName}] result = ${JSON.stringify(result)}`;
            const logLvl = result.status === status.OK ? 'trace' : 'warn';
            logger[logLvl](logMsg);
        }

        reports[componentName] = result;
    }

    function validateAddComponentHealthConditionParams(componentName, componentHealthCheck) {
        const logHeader = 'healthCache.validateAddComponentHealthConditionParams ';
        let errorMsg = null;
        if (!_.isString(componentName)) {
            errorMsg = '- componentName should be a string value';
        }
        else if (componentName in conditions) {
            errorMsg = '- componentName should be unique';
        }
        else if (!_.isFunction(componentHealthCheck)) {
            errorMsg = '- componentHealthCheck should be a function';
        }

        if (errorMsg !== null) {
            errorMsg = logHeader + errorMsg;
            throw new Error(errorMsg);
        }
    }

    function pollingAction(logHeader, componentName, componentHealthCheck, frequencyMS) {
        // Ensure that only one check is made at a time for given component
        if (!pending[componentName] && !stopped) {
            const cachedRequestId = random.uuid();
            const logger = log.scoped(cachedRequestId);
            logger.trace(`${logHeader}- component health check started for component ${componentName}`);
            pending[componentName] = true;
            runComponentHealthCheck(logger, cachedRequestId, componentHealthCheck)
                .then(result => {
                    result.cachedRequestId = cachedRequestId;
                    createResultHandler(logger, logHeader, componentName, result);
                })
                .catch(err => {
                    logger.error(`${logHeader}- error while polling component ${componentName}: ${err.errorMessage || err.message || detailedErrorString(err)}`);
                })
                .then(() => {
                    pending[componentName] = false;
                    logger.trace(`${logHeader}- component health check done for component ${componentName}`);
                    setTimeout(() => {
                        pollingAction(logHeader, componentName, componentHealthCheck, frequencyMS);
                    }, frequencyMS);
                });
        }
    }

    function addComponentHealthCondition(componentName, componentHealthCheck) {
        const logHeader = 'healthCache.addComponentHealthCondition ';
        log.info(`${logHeader} for component ${componentName} started...`);
        validateAddComponentHealthConditionParams(componentName, componentHealthCheck);

        // Initialize arrays for this component
        reports[componentName] = null;
        pending[componentName] = false;

        log.debug(`${logHeader}- creating polling object for component ${componentName} started...`);
        conditions[componentName] = () => { pollingAction(logHeader, componentName, util.promisify(componentHealthCheck), options.frequencyMS); };
        log.debug(`${logHeader}- creating polling object for component ${componentName} done.`);

        log.info(`${logHeader} for component ${componentName} done`);
    }

    function run() {
        log.info('healthCache starting...');
        stopped = false;
        for (const componentName in conditions) {
            conditions[componentName]();
        }
        log.info('healthCache started.');
    }

    function stop() {
        log.info('healthCache stopping...');
        stopped = true;
        log.info('healthCache stopped.');
    }

    function getReportForComponent(logger, logHeader, componentName) {
        logger.trace(`${logHeader}- checking component ${componentName}...`);

        // If there is no result reported yet
        // Then report it also as an error
        let result = {};
        let cachedRequestId = version.NA;
        if (reports[componentName] === null) {
            logger.info(`${logHeader}- there is no health report stored for component ${componentName} yet. Setting UNKNOWN status`);
            result = { status: status.UNKNOWN, version: version.NA };
        }
        else {
            const componentResult = Object.assign({}, reports[componentName]);
            cachedRequestId = componentResult.cachedRequestId === undefined ? cachedRequestId : componentResult.cachedRequestId;
            delete componentResult.cachedRequestId;

            // Check if the report wasn't stored earlier than it is acceptable
            if (new Date().getTime() - componentResult.lastChecked.getTime() > options.validityMS) {
                logger.warn(`${logHeader}- health report for component ${componentName} is outdated (${options.validityMS}ms validity time exceeded)`);

                // Remember the original status
                result.lastStatus = componentResult;
                result.status = status.OUTDATED;
            }
            else {
                result = componentResult;
            }
        }

        logger.trace(`${logHeader}- checking component ${componentName} done.`);
        return { result, cachedRequestId };
    }

    function getComponentReports(logger) {
        const logHeader = 'getComponentReports ';
        logger.trace(`${logHeader}started...`);
        const output = {};

        // Gather all last reports from components health checks
        for (const componentName in reports) {
            const { result, cachedRequestId } = getReportForComponent(logger, logHeader, componentName);
            output[componentName] = result;

            if (result.status !== status.OK || logger.isTraceEnabled()) {
                const logMsg = `[${componentName}] result = ${JSON.stringify(output[componentName])}, cachedRequestId = ${cachedRequestId}`;
                const logLvl = result.status === status.OK ? 'trace' : 'warn';
                logger[logLvl](logMsg);
            }
        }

        logger.trace(`${logHeader}done.`);
        return output;
    }

    function buildResponse(componentReports) {
        let thisComponent = null;
        let mainStatus = status.OK;
        const mainVersion = options.version;
        let httpStatus = STATUS_OK.httpCode;

        // If any of component healths is not OK
        // Then the overall health is also not so good
        for (const componentName in componentReports) {
            if (componentReports[componentName].status !== status.OK) {
                mainStatus = status.FAILED;
                httpStatus = STATUS_SERVICE_UNAVAILABLE.httpCode;
                break;
            }
        }

        // If there is a special this component then it will be formatted separately
        if (_.has(componentReports, 'this')) {
            thisComponent = _.clone(componentReports.this);
            delete componentReports.this;
            delete thisComponent.status;
        }

        let response = {
            status:      mainStatus,
            version:     mainVersion,
            lastChecked: new Date(),
        };

        if (!_.isEmpty(componentReports)) {
            response.componentStatus = componentReports;
        }

        if (thisComponent !== null) {
            response = extendRHCResponse(response, thisComponent);
        }
        return [httpStatus, response];
    }

    return {

        /**
         * Component statuses
         */
        status,

        /**
         * Version field constants
         */
        version,

        /**
         * Adds component's health check condition that will be checked with some defined (in constructor) frequency
         * 
         * @param {string} componentName - unique component name. If componentName === 'this' then it will be treated as root component and it's health report will be glued with response JSON root
         * @param {function} componentHealthCheck - callback that will check component's health and return a healthcheck result object (or error in case of any)
         *        Valid healthcheck result object SHALL contain following fields:
         *          {string} status - "OK" is success, any other status is fault, in particular you should use value defined by healthCache.status
         *          {string} componentVersion - componentVersion of given component
         * Valid healthcheck result MAY contain following field:
         *          {object} componentStatus - map of children components where component name is key and value is healthcheck result object
         *        If this method throws exception it will be caught and handled.
         *
         */
        addComponentHealthCondition,

        /**
         * Start gathering and caching component statuses
         */
        run,

        /**
         * Stop gathering and caching component statuses
         */
        stop,

        /**
         * REST request handler
         */
        handleRequest
    };
}

module.exports = KoaHealthCache;
