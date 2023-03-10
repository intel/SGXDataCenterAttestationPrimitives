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

const Promise = require('bluebird');
const _ = require('lodash');
const Buffer = require('../util/buffer');
const env = require('process').env;
const path = require('path');
const jsYaml = require('js-yaml');
const ZSchema = require('z-schema');

const logger = require('./logger').genericLogger;
const readFileSafely = require('./readFileSafely');

let configPath = '../configuration-default/';

const SPLIT_REGEXP = /[,; ]+/;

const HIDDEN_CONFIG_FIELDS = ['PASSWORD', 'SECRET', 'VAULT', 'validationKey', 'restKey'];

function readApplicationJsonFromEnv() {
    if (env.APPLICATION_JSON) {
        try {
            return JSON.parse(env.APPLICATION_JSON);
        }
        catch (e) {
            throw new Error('Error parsing APPLICATION_JSON env variable. Make sure it is in JSON format: ' + e);
        }
    }
    else if (env.APPLICATION_JSON_BASE64) {
        try {
            return JSON.parse(Buffer.from(env.APPLICATION_JSON_BASE64, 'base64').toString('ascii'));
        }
        catch (e) {
            throw new Error('Error parsing APPLICATION_JSON_BASE64 env variable. Make sure its content is proper base64 of a JSON: ' + e);
        }
    }
    return {};
}

const applicationJson = readApplicationJsonFromEnv();

function appendPath(p) {
    if (p.startsWith('/')) {
        return p;
    }

    return path.join(configPath || '.', p);
}

function appendConfigPath(configObject, fieldList) {
    for (const field of fieldList) {
        if (_.isString(configObject[field])) {
            configObject[field] = appendPath(configObject[field]);
        }
        else if (_.isArray(configObject[field])) {
            configObject[field] = configObject[field].map(appendPath);
        }
    }
}

function getSchemaErrors(name, errors) {
    for (const error of errors) {
        const schemaPath = error.path.replace(/^#\//, ''); // Replace '#/' from the beginning of the error.path
        if (schemaPath) { // Extend error message with path info (if exists)
            error.message += ` in ${schemaPath}`;
        }
    }
    // Create and return single-line message with all errors (used ' :: ' as a separator)
    return `Configuration parsing error(s) in "${configPath}" <${name}>: ${errors.map(e => e.message).join(' :: ')}`;
}

class Base {
    validate(config, schema) {
        const validator = new ZSchema({
            breakOnFirstError: false
        });
        const valid = validator.validate(config, Object.assign(schema, { type: 'object' }));
        if (!valid) {
            const msg = getSchemaErrors(this.constructor.name, validator.getLastErrors());
            logger.fatal(msg);
            throw new Error(msg);
        }
    }
}

class Logger extends Base {
    constructor(config) {
        super();
        this.validate(config, {
            required:   ['levelFile', 'levelConsole', 'fileName', 'category'],
            properties: {
                levelFile: {
                    'type': 'string', 'enum': ['trace', 'debug', 'info', 'warn', 'error', 'fatal', 'off']
                },
                levelConsole: {
                    'type': 'string', 'enum': ['trace', 'debug', 'info', 'warn', 'error', 'fatal', 'off']
                },
                fileName: {
                    type: 'string'
                },
                fileCPP: {
                    type: 'string'
                },
                category: {
                    type: 'string'
                },
                maxDisplayingMessageLength: {
                    type: 'integer'
                },
                multilineEnabled: {
                    type: 'boolean'
                }
            }
        });
        this.levelFile = config.levelFile;
        this.levelConsole = config.levelConsole;
        this.fileName = config.fileName;
        this.fileCPP = config.fileCPP;
        this.multilineEnabled = config.multilineEnabled;
        this.category = config.category;
        this.maxDisplayingMessageLength = config.maxDisplayingMessageLength;
    }
}

class HealthCheck extends Base {
    constructor(config) {
        super();
        this.validate(config, {
            required:   ['intervalMs', 'freshnessMs'],
            properties: {
                intervalMs: {
                    type: 'number'
                },
                freshnessMs: {
                    type: 'number'
                }
            }
        });
        this.intervalMs = config.intervalMs;
        this.freshnessMs = config.freshnessMs;
    }
}

class Service extends Base {
    constructor(config) {
        super();
        this.validate(config, {
            required: (function checkMTLSType() {
                switch (config.tlsServerType) {
                    case 'MTLS':
                        return ['componentName', 'componentShort', 'certFile', 'keyFile', 'tlsServerType', 'caCertDirectories'];
                    case 'TLS':
                        return ['componentName', 'componentShort', 'certFile', 'keyFile', 'tlsServerType'];
                    case 'None':
                        return ['componentName', 'componentShort', 'tlsServerType'];
                    default:
                        return ['componentName', 'componentShort', 'certFile', 'keyFile', 'tlsServerType'];
                }
            }()),
            properties: {
                componentName: {
                    type: 'string'
                },
                componentShort: {
                    type: 'string'
                },
                tlsServerType: {
                    'type': 'string', 'enum': ['MTLS', 'TLS', 'None']
                },
                port: {
                    type: 'number'
                },
                certFile: {
                    type: 'string'
                },
                keyFile: {
                    type: 'string'
                },
                caCertDirectories: {
                    type: 'string',
                },
                bodySizeLimits: {
                    type:       'object',
                    properties: {
                        text: {
                            type: 'string'
                        },
                        json: {
                            type: 'string'
                        },
                        form: {
                            type: 'string'
                        },
                        blob: {
                            type: 'string'
                        }
                    }
                },
                restClientTimeout: {
                    type: 'number'
                }
            }
        });

        if (config.caCertDirectories) {
            config.caCertDirectories = config.caCertDirectories.split(SPLIT_REGEXP);  // since caCertDirectories are CSV we need to split them before prepending default config path
        }
        appendConfigPath(config, ['certFile', 'keyFile', 'caCertDirectories']);

        this.componentName = config.componentName;
        this.componentShort = config.componentShort;
        this.tlsServerType = config.tlsServerType;
        this.port = config.port;
        this.certFile = config.certFile;
        this.keyFile = config.keyFile;
        this.caCertDirectories = config.caCertDirectories;
        this.bodySizeLimits = config.bodySizeLimits;
        this.restClientTimeout = config.restClientTimeout;
    }
}

class Cache extends Base {
    constructor(config) {
        super();

        this.validate(config, {
            required:   ['ttl', 'checkPeriod', 'maxKeys'],
            properties: {
                ttl: {
                    type: 'number'
                },
                checkPeriod: {
                    type: 'number'
                },
                maxKeys: {
                    type: 'number'
                }
            }
        });

        this.ttl = config.ttl;
        this.checkPeriod = config.checkPeriod;
        this.maxKeys = config.maxKeys;
    }
}

class RestClient extends Base {
    constructor(config) {
        super();
        this.validate(config, {
            required:   ['host', 'port', 'retries', 'initialInterval', 'factor', 'tlsClientType', 'caCertDirectories', 'servername'],
            properties: {
                tlsClientType: {
                    'type': 'string', 'enum': ['MTLS', 'TLS', 'None']
                },
                host: {
                    type: 'string'
                },
                port: {
                    type: 'number'
                },
                retries: {
                    type: 'number'
                },
                initialInterval: {
                    type: 'number'
                },
                factor: {
                    type: 'number'
                },
                certFile: {
                    type: 'string'
                },
                keyFile: {
                    type: 'string'
                },
                caCertDirectories: {
                    type: 'string',
                },
                proxy: {
                    type: 'string',
                },
                servername: {
                    type: 'string'
                }
            }
        });

        this.tlsClientType = config.tlsClientType;
        this.host = config.host;
        this.port = config.port;
        this.retries = config.retries;
        this.initialInterval = config.initialInterval;
        this.factor = config.factor;
        this.certFile = config.certFile;
        this.keyFile = config.keyFile;
        this.caCertDirectories = config.caCertDirectories.split(SPLIT_REGEXP);
        this.proxy = config.proxy;
        this.servername = config.servername;

        appendConfigPath(this, ['certFile', 'keyFile', 'caCertDirectories']);
    }
}

// This is skeleton for basic rest service with logger, healthcheck and service nodes possible.
// All nodes are optional.
class BaseRestService extends Base {
    constructor(config) {
        super();
        const svc = config.service;
        if (svc) {
            this.service = new Service(svc);
        }
        if (config.logger) {
            this.logger = new Logger(config.logger);
        }
        if (config.healthCheck) {
            this.healthCheck = new HealthCheck(config.healthCheck);
        }
    }
}

async function parseJsonObject(value) {
    let res = JSON.parse(value);

    res = _.mapValues(res, (item) => {
        return item;
    });
    res = await Promise.props(res);

    return res;
}

async function parseJsonArray(value) {
    let array = JSON.parse(value);

    const promisedArray = array.map((item) => {
        return item;
    });
    array = await Promise.all(promisedArray);
    return array;
}

async function parseTemplate(val) {
    if (_.isBoolean(val) || _.isNumber(val)) {
        return val;
    }

    if (!_.isString(val)) {
        throw new Error('Cannot parse template which is not string: ' + val);
    }

    const trimmed = val.trim();
    // Recognize a template ${<env_variable_name:<default_value>}
    if (trimmed.startsWith('${') && trimmed.endsWith('}')) {
        const inside = trimmed.substring(2, trimmed.length - 1);
        const colonIndex = inside.indexOf(':');
        // Key should be at least 1 character long, value can be empty string, but colon is mandatory
        if (colonIndex < 1) {
            throw new Error('Non-empty key and default value in config are mandatory in template: ' + trimmed);
        }
        const envKey = inside.substring(0, colonIndex);
        // Retrieve value from different sources
        let value;
        // APPLICATION_JSON or APPLICATION_JSON_BASE64 environment variable
        if (!_.isUndefined(applicationJson[envKey])) {
            value = applicationJson[envKey];
        }
        // Specific env variable with prefix SGX_[DEVOPS_]<component>_<section>_<variable>
        else if (!_.isUndefined(env[envKey])) {
            value = env[envKey];
        }
        // Default value from config.yml
        else {
            const defaultValue = inside.substring(colonIndex + 1);
            value = defaultValue;
        }
        // Additional transformations or conversions
        /* istanbul ignore else: value read from env or file is always string, check before trim left for safety reasons */
        if (_.isString(value)) {
            value = value.trim();
            // Boolean
            if (value === 'true') {
                return true;
            }
            if (value === 'false') {
                return false;
            }
            if (value === 'null') {
                return null;
            }
            // String convertible to number
            if (value.length > 0 && !isNaN(value)) {
                return Number(value);
            }
            else if (value.length >= 2) {
                // Remove optional '' around content
                if (value[0] === '\'' && value[value.length - 1] === '\'') {
                    value =  value.substring(1, value.length - 1);
                }
                // Remove optional "" around content
                if (value[0] === '"' && value[value.length - 1] === '"') {
                    value = value.substring(1, value.length - 1);
                }

                // JSON object
                if (value[0] === '{' && value[value.length - 1] === '}') {
                    try {
                        const resJson = await parseJsonObject(value);
                        return resJson;
                    }
                    catch (e) {
                        throw new Error(value + ' cannot be parsed as valid JSON');
                    }
                }
                // JSON array
                if (value[0] === '[' && value[value.length - 1] === ']') {
                    try {
                        const resArray = await parseJsonArray(value);
                        return resArray;
                    }
                    catch (e) {
                        throw new Error(value + ' cannot be parsed as valid array');
                    }
                }
            }
        }
        return value;
    }
    return trimmed;
}

async function fillConfigFromEnv(obj) {
    const mapper = (value) => {
        if (_.isObject(value)) { // array is also an object
            return fillConfigFromEnv(value);
        }
        else if (_.isString(value)) {
            return parseTemplate(value);
        }
        return value;
    };

    if (_.isArray(obj)) {
        obj = await Promise.map(obj, mapper);
    }
    /* istanbul ignore else */
    else if (_.isObject(obj)) {
        const promisedObj = _.mapValues(obj, mapper);
        obj = await Promise.props(promisedObj);
    }
    return obj;
}

function removePasswords(obj) {
    const configWithHiddenPasswords = JSON.parse(JSON.stringify(obj));
    /* istanbul ignore else */
    if (_.isObject(configWithHiddenPasswords)) {
        for (const [key, value] of Object.entries(configWithHiddenPasswords)) {
            if (_.isObject(value)) {
                configWithHiddenPasswords[key] = removePasswords(value);
            }
            else if (_.isString(key) && HIDDEN_CONFIG_FIELDS.some(part => key.toUpperCase().includes(part.toUpperCase()))
            ) {
                configWithHiddenPasswords[key] = '<HIDDEN>';
            }
        }
    }
    return configWithHiddenPasswords;
}

/**
 * Loads config from directory
 * @param {string} configDir path to directory not file
 * @returns {{config: Object, service: Object, target: Object, logger: Logger, healthcheck: Object}} jsYaml Object
 */
async function loadConfig(configDir) {
    configPath = configDir;
    const configFilePath = path.resolve(appendPath('config.yml'));

    try {
        let config =  jsYaml.load(readFileSafely(configFilePath, 'utf8'), { filename: configFilePath });
        config.configPath = configPath;

        config = await fillConfigFromEnv(config);
        const configWithHiddenPasswords = removePasswords(config);
        logger.info((config.service ? config.service.componentName : '') + ' CONFIG: ' + JSON.stringify(configWithHiddenPasswords));
        return config;
    }
    catch (err) {
        let msg = err.message;
        if (err instanceof jsYaml.YAMLException) {
            // Replace multiple white characters (spaces, tabs, eol-s) with the single one; mainly for having single-line error message
            // > without replacement:
            // [...] end of the stream or a document separator is expected in "/GAS/configuration/config.yml" at line 25, column 16:
            // ComponentName:  'GroupAssignmentStore'
            // > with replacement:
            // [...] Error: end of the stream or a document separator is expected in "/GAS/configuration/config.yml" at line 25, column 16:
            // ComponentName: 'GroupAssignmentStore'
            msg = `Error: ${msg.replace(/[ \t\r\n^]+/g, ' ')}`;
        }
        else {
            msg = `Initialization failure: ${msg}`;
        }
        if (!msg.includes(configFilePath)) {
            msg = `Error in ${configFilePath}: ${msg}`;
        }
        logger.fatal(msg);
        throw new Error(msg);
    }
}

class ConfigLoader {
    constructor(configClass) {
        this.configClass = configClass;
        this.instance = null;
    }

    async init(path) {
        const config = await loadConfig(path);
        this.instance = new this.configClass(config);
    }

    getConfig() {
        if (!this.instance) {
            throw Error('You need to call init(path) first and await initialization. Run server using `node ./bootstrap.js and set correct config profile`');
        }
        return this.instance;
    }
}

module.exports = {
    Service,
    HealthCheck,
    Logger,
    RestClient,
    Cache,
    BaseRestService,
    ConfigLoader,
    Base,
    appendConfigPath,
    load: loadConfig
};
