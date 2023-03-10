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

/* eslint max-len: off */

const assert = require('chai').assert;
const sinon = require('sinon');
const proxyquire = require('proxyquire').noCallThru();

const assertMockCalledOnceWithArgs = require('./mocks/helpers').assertMockCalledOnceWithArgs;

class ConfigLoaderMock {
    constructor(configClass) {
        this.configClass = configClass;
    }

    async init(json) {
        this.instance = new this.configClass(json);
    }

    getConfig() {
        return this.instance;
    }
}

class TestContext {
    constructor() {
        const self = this;

        this.baseValidator = sinon.spy();
        this.baseRestServiceValidator = sinon.spy();
        this.cacheValidator = sinon.spy();

        this.config = {
            logger: {
                category:     'category',
                fileName:     'logfile.log',
                levelFile:    'trace',
                levelConsole: 'trace'
            },
            Base: class BaseMock {
                constructor() {
                    this.validate = self.baseValidator;
                }
            },
            BaseRestService: class BaseRestServiceMock {
                constructor() {
                    this.validate = self.baseRestServiceValidator;
                }
            },
            Cache: class CacheMock {
                constructor() {
                    this.validate = self.cacheValidator;
                }
            },
            ConfigLoader:     ConfigLoaderMock,
            HealthCheck:      sinon.stub(),
            RestClient:       sinon.stub(),
            appendConfigPath: sinon.spy(),
            load:             sinon.stub(),
        };

        this.commonLogger = {
            genericLogger: {
                fatal: sinon.stub()
            }
        };
    }

    getTarget() {
        return proxyquire('../src/configLoader', {
            './common/config': this.config
        });
    }
}

const getCorrectConfig = () => {
    return {
        service: {
            caCertDirectories: 'someElement'
        },
        pcsClient: {
            retries:         3,
            initialInterval: 100,
            factor:          2
        }
    };
};

const getCorrectConfigWithVCS = () => {
    return {
        service: {
            caCertDirectories: 'someElement'
        },
        pcsClient: {
            retries:         3,
            initialInterval: 100,
            factor:          2
        },
        vcsClient: {
            retries:         3,
            initialInterval: 100,
            factor:          2
        }
    };
};

describe('ConfigTest', () => {

    const configuration = {
        // this list is a list of sections that are required in valid RB configuration
        required:   ['service', 'pcsClient', 'crlClient', 'healthCheck', 'logger', 'cache', 'target'],
        properties: {
            crlClient: {
                required:   ['retries', 'initialInterval', 'factor'],
                properties: {
                    retries: {
                        type: 'number'
                    },
                    initialInterval: {
                        type: 'number'
                    },
                    factor: {
                        type: 'number'
                    }
                }
            },
            target: {
                required:                              ['attestationReportSigningCaCertificate', 'attestationReportSigningCertificate', 'trustedRootPublicKey'],
                attestationReportSigningCaCertificate: {
                    type: 'string'
                },
                attestationReportSigningCertificate: {
                    type: 'string'
                },
                trustedRootPublicKey: {
                    type: 'string'
                }
            }
        }
    };

    it('Config_constructor_success', async() => {
        // GIVEN
        const c = new TestContext();
        const target = c.getTarget();
        const jsonConfig = getCorrectConfig();
        // WHEN
        await target.init(jsonConfig);
        target.getConfig();
        // THEN
        assertMockCalledOnceWithArgs(c.baseRestServiceValidator, jsonConfig, configuration);
        assert.strictEqual(c.config.RestClient.callCount, 1);
    });

    it('Config_constructor_with_vcs_success', async() => {
        // GIVEN
        const c = new TestContext();
        const target = c.getTarget();
        const jsonConfig = getCorrectConfigWithVCS();
        // WHEN
        await target.init(jsonConfig);
        target.getConfig();
        // THEN
        assertMockCalledOnceWithArgs(c.baseRestServiceValidator, jsonConfig, configuration);
        assert.strictEqual(c.config.RestClient.callCount, 2);
    });

});
