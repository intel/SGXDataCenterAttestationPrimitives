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

const log4js = require('log4js');
const _ = require('lodash');
const util = require('util');
const LEVELS = log4js.levels;
const onelinerFormat = require('../util/onelinerFormat');

// General format of log output line:
// "[<timestamp>] [<levelName>] [<logCategory> <filename>:<linenumber>] <message>"
// "[<timestamp>] [<levelName>] [<logCategory> <filename>:<linenumber>] [reqId=<reqId>] <message>"
const MESSAGE_TOKEN = 'messageBody';
const LOG_PATTERN = `[%dZ] [%p] [%X{logCategory} %f{1}:%l] [hostname:%h pid:%z] %X{reqId} %x{${MESSAGE_TOKEN}}`;

/**
 * exact way as log4j handles %m (log data)
 * https://github.com/log4js-node/log4js-node/blob/f8d46a939279c0ab4efc8bb5f0478c4b0949a4cf/lib/layouts.js#L165
 * @param {{data: string}} loggingEvent
 * @returns {string} formatted message
 */
function formatMessage(loggingEvent) {
    return util.format(...loggingEvent.data);
}

/**
 * Makes multiline log message a single line by replacing new lines with |
 * @param {LoggingEvent} loggingEvent
 * @returns {string}
 */
function oneliner(loggingEvent) {
    return onelinerFormat(formatMessage(loggingEvent));
}

//increase stack size to catch the caller function in log4js pattern matching
Error.stackTraceLimit = 12;

class Logger {
    constructor(logCategory, logFile, logLevelFile, logLevelConsole, isMultilineLogEnabled) {
        this.layout = {
            type:    'pattern',
            pattern: LOG_PATTERN,
            tokens:  {
                [MESSAGE_TOKEN]: isMultilineLogEnabled ? formatMessage : oneliner
            }
        };

        this.stdout = {
            type:   'stdout',
            layout: this.layout,
        };
        this.file = {
            type:     'file',
            layout:   this.layout,
            filename: logFile,
        };
        this.consoleLower = {
            type:     'logLevelFilter',
            layout:   this.layout,
            appender: 'file',
            level:    LEVELS.getLevel(logLevelFile)
        };
        this.fileLower = {
            type:     'logLevelFilter',
            layout:   this.layout,
            appender: 'stdout',
            level:    LEVELS.getLevel(logLevelConsole)
        };

        this.appenders = {
            stdout: this.stdout
        };

        this.categories = {
            'default': { appenders: ['stdout'], level: logLevelConsole, enableCallStack: true }
        };

        this.logFile = logFile;
        this.logCategory = logCategory;
        this.logLevelFile = LEVELS.getLevel(logLevelFile);
        this.logLevelConsole = LEVELS.getLevel(logLevelConsole);

        if (logFile) {
            this.appenders.file = this.file;
            this.appenders.consoleLower = this.consoleLower;
            this.appenders.fileLower = this.fileLower;
            this.categories.consoleLower = { appenders: ['consoleLower', 'stdout'], level: logLevelConsole, enableCallStack: true };
            this.categories.fileLower = { appenders: ['fileLower', 'file'], level: logLevelFile, enableCallStack: true };
            this.categories.default = { appenders: ['stdout', 'file'], level: logLevelFile, enableCallStack: true };
        }
    }

    getConfiguredLogger() {
        if (this.logLevelFile.isEqualTo(this.logLevelConsole) || !this.logFile) {
            return log4js.getLogger();
        }
        else if (this.logLevelFile.isGreaterThanOrEqualTo(this.logLevelConsole)) {
            return log4js.getLogger('consoleLower');
        }
        else  {
            return log4js.getLogger('fileLower');
        }
    }

    getLogger() {
        log4js.configure({
            appenders:  this.appenders,
            categories: this.categories
        });

        const logger = this.getConfiguredLogger();
        logger.addContext('logCategory', this.logCategory);
        logger.addContext('reqId', '');

        logger.scoped = (reqId) => {
            // This piece of code adds 'reqId' to log lines. logger.addContext('reqId', '') is NOT thread safe,
            // so multiple requests in the system will mingle and override value of request-id in global logger.
            // Deep cloning logger object so new instance is used with different request-id
            const scopedLogger = _.cloneDeep(logger);
            scopedLogger.addContext('reqId', `[reqId=${reqId}]`);
            return scopedLogger;
        };

        return logger;
    }
}

class Singleton {
    constructor() {
        this.instance = null;
    }

    createLogger(logCategory, logFile, logLevelFile, logLevelConsole, isMultilineLogEnabled) {
        if (!this.instance) {
            this.instance = new Logger(logCategory, logFile, logLevelFile, logLevelConsole, isMultilineLogEnabled).getLogger();
        }

        return this.instance;
    }
}

const logger = new Singleton();
const genericLogger = new Logger('genericLogger', undefined, LEVELS.OFF, LEVELS.INFO, true).getLogger();

module.exports = {
    genericLogger,
    createLogger: (logCategory, logFile, logLevelFile, logLevelConsole, isMultilineLogEnabled = false) => logger.createLogger(logCategory, logFile, logLevelFile, logLevelConsole, isMultilineLogEnabled),
};
