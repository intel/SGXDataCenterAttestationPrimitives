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

const proxyquire = require('proxyquire').noCallThru();
const sinon = require('sinon');
const assert = require('assert');

class TestContext {
    constructor() {
        this.config = {
            logger: {
                category:              'category',
                fileName:              'logfile.log',
                levelFile:             'trace',
                levelConsole:          'trace',
                isMultilineLogEnabled: true
            }
        };
        this.logger = { createLogger: sinon.stub() };
        this.qvl = { loggerSetup: sinon.stub() };
        this.qvlFileNameExpected = 'logfile-qvl.log';
        this.qvlPatternExpected = '[%Y-%m-%dT%H:%M:%S.%eZ] [%l] [%n %@] [pid:%P]%r %v';
    }

    getTarget() {
        return proxyquire('../src/logger', {
            './common/logger': this.logger,
            './qvl':           this.qvl
        });
    }
}

describe('loggerTest', () => {
    it('positive', () => {
        // GIVEN
        const c = new TestContext();
        const loggerInstance = { logger: 'logger' };

        c.logger.createLogger.returns(loggerInstance);

        // WHEN
        const target = c.getTarget()(c.config);

        // THEN
        assert.equal(c.qvl.loggerSetup.callCount, 1);
        assert.ok(c.qvl.loggerSetup.calledWithExactly(
            c.config.logger.category,
            c.config.logger.levelConsole.toUpperCase(),
            c.config.logger.levelFile.toUpperCase(),
            c.qvlFileNameExpected,
            c.qvlPatternExpected
        ));

        assert.equal(c.logger.createLogger.callCount, 1);
        assert.ok(c.logger.createLogger.calledWithExactly(
            c.config.logger.category,
            c.config.logger.fileName,
            c.config.logger.levelFile,
            c.config.logger.levelConsole,
            c.config.logger.isMultilineLogEnabled));

        assert.deepEqual(target, loggerInstance);
    });

    it('positive - proper QVL filename when complex filename', () => {
        // GIVEN
        const c = new TestContext();
        const loggerInstance = { logger: 'logger' };

        c.logger.createLogger.returns(loggerInstance);
        // WHEN
        const config = {
            logger: {
                category:              'category',
                fileName:              '/some/dir/for/logs/logfile.log',
                levelFile:             'trace',
                levelConsole:          'trace',
                isMultilineLogEnabled: true
            }
        };
        c.getTarget()(config);

        // THEN
        assert.equal(c.qvl.loggerSetup.callCount, 1);
        assert.ok(c.qvl.loggerSetup.calledWithExactly(
            config.logger.category,
            config.logger.levelConsole.toUpperCase(),
            config.logger.levelFile.toUpperCase(),
            '/some/dir/for/logs/logfile-qvl.log',
            c.qvlPatternExpected
        ));

    });

    it('positive - proper QVL filename when no file extension', () => {
        // GIVEN
        const c = new TestContext();
        const loggerInstance = { logger: 'logger' };

        c.logger.createLogger.returns(loggerInstance);
        // WHEN
        const config = {
            logger: {
                category:              'category',
                fileName:              'logfile',
                levelFile:             'trace',
                levelConsole:          'trace',
                isMultilineLogEnabled: true
            }
        };
        c.getTarget()(config);

        // THEN
        assert.equal(c.qvl.loggerSetup.callCount, 1);
        assert.ok(c.qvl.loggerSetup.calledWithExactly(
            config.logger.category,
            config.logger.levelConsole.toUpperCase(),
            config.logger.levelFile.toUpperCase(),
            'logfile-qvl',
            c.qvlPatternExpected
        ));

    });
});
