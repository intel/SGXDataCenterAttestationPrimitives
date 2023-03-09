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

/* eslint no-new: off */

const assert = require('assert');
const proxyquire = require('proxyquire').noCallThru();
const sinon = require('sinon');
const config = require('../../src/common/config');


// valid yaml: service config as an example
const validYaml = `
service:
  componentName:  'Service'
  componentShort: 'SRV'
  port:           8443
  certFile:       'certificates/internal/srv.crt'
  keyFile:        'certificates/internal/srv.key'
  caCertDirectories: '../../Tools/AnsibleScripts/group_files/ALL/internal_use_ca_certificates/, ../../Tools/AnsibleScripts/files/testPurposesCA/'
  bodySizeLimits:
    text: '16mb'
    json: '16mb'
`;

// valid yaml with templates
const validYamlWithTemplates = `
service:
  componentName:  \${QVS_SERVICE_COMPONENT_NAME:RegistrationDataService}
  componentShort: \${QVS_SERVICE_COMPONENT_SHORT:RDS}
  port:           \${QVS_SERVICE_PORT:9998}
  certFile:       \${QVS_SERVICE_CERT_FILE:certificates/internal/rds.crt}
  keyFile:        \${QVS_SERVICE_KEY_FILE:certificates/internal/rds.key}
  tlsServerType:  \${QVS_SERVICE_TLS_SERVER_TYPE:TLS}
  caCertDirectories: \${QVS_CA_CERT_DIRECTORIES:certificates/internal_ca/internal_use_ca_certificates/}
  bodySizeLimits: \${QVS_SERVICE_BODY_SIZE_LIMITS:{"json":"1mb"}}

cassandra:
  contactPoints   : \${QVS_CASSANDRA_CONTACT_POINTS:"127.0.0.1"}
  healthCheckTable: \${QVS_CASSANDRA_HEALTH_CHECK_TABLE:"processorregistrationkey"}
  keyspace        : \${QVS_CASSANDRA_KEYSPACE:"registration_db"}
  maxRetries      : \${QVS_CASSANDRA_MAX_RETRIES:3}
  password        : \${QVS_CASSANDRA_PASSWORD:registration_US}
  timeoutMs       : \${QVS_CASSANDRA_TIMEOUT_MS:100}
  user            : \${QVS_CASSANDRA_USER:registration_US}
  datacenter      : \${QVS_CASSANDRA_DATACENTER:DC1}
`;

// invalid yaml: lack of ':' in first line
const invalidYaml = `
service
  componentName:  'Service'
  componentShort: 'SRV'
  port:           8443
  certFile:       'certificates/internal/srv.crt'
  keyFile:        'certificates/internal/srv.key'
  caCertDirectories: '../../Tools/AnsibleScripts/group_files/ALL/internal_use_ca_certificates/,../../Tools/AnsibleScripts/files/testPurposesCA/'
  bodySizeLimits:
    text: '16mb'
    json: '16mb'
`;

function readFile(returnedContent, throws = false) {
    return function readFileSafely() {
        if (throws) {
            throw new Error('ENOENT: no such file or directory');
        }
        return returnedContent;
    };
}

describe('configTest', () => {

    const assertErrorReport = {
        missingProperty(error, property) {
            const regex = new RegExp(`Missing required property: ${property}`);
            assert(regex.test(error), `Missing of ${property} not reported`);
        }
    };

    describe('config_load', () => {

        it('positive', async() => {
            //GIVEN
            const localConfig = proxyquire('../../src/common/config', {
                '../common/readFileSafely': readFile(validYaml),
                'os':                       {
                    homedir: sinon.stub().returns('/home/user')
                }
            });
            //THEN
            await assert.doesNotReject(
                //WHEN
                localConfig.load
            );
        });

        describe('templates support', () => {

            it('positive with templates', async() => {
                //GIVEN
                const localConfig = proxyquire('../../src/common/config', {
                    '../common/readFileSafely': readFile(validYamlWithTemplates),
                    'os':                       {
                        homedir: sinon.stub().returns('/home/user')
                    }
                });
                //THEN
                await assert.doesNotReject(
                    //WHEN
                    localConfig.load
                );
            });

            it('optional \'\'', async() => {
                //GIVEN
                const yaml = 'key: ${KEY_ENV:\'default_value\'}';
                const localConfig = proxyquire('../../src/common/config', {
                    '../common/readFileSafely': readFile(yaml),
                    'os':                       {
                        homedir: sinon.stub().returns('/home/user')
                    }
                });
                //THEN
                await assert.doesNotReject(async() => {
                    //WHEN
                    const config = await localConfig.load();
                    assert.strictEqual(config.key, 'default_value');
                });
            });

            it('optional ""', async() => {
                //GIVEN
                const yaml = 'key: ${KEY_ENV:"default_value"}';
                const localConfig = proxyquire('../../src/common/config', {
                    '../common/readFileSafely': readFile(yaml),
                    'os':                       {
                        homedir: sinon.stub().returns('/home/user')
                    }
                });
                //THEN
                await assert.doesNotReject(async() => {
                    //WHEN
                    const config = await localConfig.load();
                    assert.strictEqual(config.key, 'default_value');
                });
            });

            it('boolean true', async() => {
                //GIVEN
                const yaml = 'key: ${KEY_ENV:true}';
                const localConfig = proxyquire('../../src/common/config', {
                    '../common/readFileSafely': readFile(yaml),
                    'os':                       {
                        homedir: sinon.stub().returns('/home/user')
                    }
                });
                //THEN
                await assert.doesNotReject(async() => {
                    //WHEN
                    const config = await localConfig.load();
                    assert.strictEqual(config.key, true);
                });
            });

            it('boolean false', async() => {
                //GIVEN
                const yaml = 'key: ${KEY_ENV:false}';
                const localConfig = proxyquire('../../src/common/config', {
                    '../common/readFileSafely': readFile(yaml),
                    'os':                       {
                        homedir: sinon.stub().returns('/home/user')
                    }
                });
                //THEN
                await assert.doesNotReject(async() => {
                    //WHEN
                    const config = await localConfig.load();
                    assert.strictEqual(config.key, false);
                });
            });

            it('number', async() => {
                //GIVEN
                const yaml = 'key: ${KEY_ENV:7}';
                const localConfig = proxyquire('../../src/common/config', {
                    '../common/readFileSafely': readFile(yaml),
                    'os':                       {
                        homedir: sinon.stub().returns('/home/user')
                    }
                });
                //THEN
                await assert.doesNotReject(async() => {
                    //WHEN
                    const config = await localConfig.load();
                    assert.strictEqual(config.key, 7);
                });
            });

            it('null', async() => {
                //GIVEN
                const yaml = 'key: ${KEY_ENV:null}';
                const localConfig = proxyquire('../../src/common/config', {
                    '../common/readFileSafely': readFile(yaml),
                    'os':                       {
                        homedir: sinon.stub().returns('/home/user')
                    }
                });
                //THEN
                await assert.doesNotReject(async() => {
                    //WHEN
                    const config = await localConfig.load();
                    assert.strictEqual(config.key, null);
                });
            });

            it('null as string', async() => {
                //GIVEN
                const yaml = 'key: ${KEY_ENV:"null"}';
                const localConfig = proxyquire('../../src/common/config', {
                    '../common/readFileSafely': readFile(yaml),
                    'os':                       {
                        homedir: sinon.stub().returns('/home/user')
                    }
                });
                //THEN
                await assert.doesNotReject(async() => {
                    //WHEN
                    const config = await localConfig.load();
                    assert.strictEqual(config.key, 'null');
                });
            });

            it('number as string', async() => {
                //GIVEN
                const yaml = 'key: ${KEY_ENV:"7"}';
                const localConfig = proxyquire('../../src/common/config', {
                    '../common/readFileSafely': readFile(yaml),
                    'os':                       {
                        homedir: sinon.stub().returns('/home/user')
                    }
                });
                //THEN
                await assert.doesNotReject(async() => {
                    //WHEN
                    const config = await localConfig.load();
                    assert.strictEqual(config.key, '7');
                });
            });

            it('array', async() => {
                //GIVEN
                const yaml = 'key: ${KEY_ENV:[7, 9, 12]}';
                const localConfig = proxyquire('../../src/common/config', {
                    '../common/readFileSafely': readFile(yaml),
                    'os':                       {
                        homedir: sinon.stub().returns('/home/user')
                    }
                });
                //THEN
                await assert.doesNotReject(async() => {
                    //WHEN
                    const config = await localConfig.load();
                    assert.deepEqual(config.key, [7, 9, 12]);
                });
            });

            it('invalid array', async() => {
                //GIVEN
                const yaml = 'key: ${KEY_ENV:[1,3]]}';
                const localConfig = proxyquire('../../src/common/config', {
                    '../common/readFileSafely': readFile(yaml),
                    'os':                       {
                        homedir: sinon.stub().returns('/home/user')
                    }
                });
                //THEN
                await assert.rejects(
                    //WHEN
                    localConfig.load,
                    /Initialization failure: \[1,3]] cannot be parsed as valid array/
                );
            });

            it('object', async() => {
                //GIVEN
                const yaml = 'key: ${KEY_ENV:{"a":"b"}}';
                const localConfig = proxyquire('../../src/common/config', {
                    '../common/readFileSafely': readFile(yaml),
                    'os':                       {
                        homedir: sinon.stub().returns('/home/user')
                    }
                });
                //THEN
                await assert.doesNotReject(async() => {
                    //WHEN
                    const config = await localConfig.load();
                    assert.deepEqual(config.key, { a: 'b' });
                });
            });

            it('object without "" on key', async() => {
                //GIVEN
                const yaml = 'key: ${KEY_ENV:{a:5}}';
                const localConfig = proxyquire('../../src/common/config', {
                    '../common/readFileSafely': readFile(yaml),
                    'os':                       {
                        homedir: sinon.stub().returns('/home/user')
                    }
                });
                //THEN
                await assert.rejects(
                    localConfig.load,
                    /Initialization failure: {a:5} cannot be parsed as valid JSON/
                );
            });

            it('object without "" on string value', async() => {
                //GIVEN
                const yaml = 'key: ${KEY_ENV:{"a":a}}';
                const localConfig = proxyquire('../../src/common/config', {
                    '../common/readFileSafely': readFile(yaml),
                    'os':                       {
                        homedir: sinon.stub().returns('/home/user')
                    }
                });
                //THEN
                await assert.rejects(
                    //WHEN
                    localConfig.load,
                    /Initialization failure: {"a":a} cannot be parsed as valid JSON/
                );
            });

            it('too short string to have "", no need to check first and last char', async() => {
                //GIVEN
                const yaml = 'key: ${KEY_ENV:a}';
                const localConfig = proxyquire('../../src/common/config', {
                    '../common/readFileSafely': readFile(yaml),
                    'os':                       {
                        homedir: sinon.stub().returns('/home/user')
                    }
                });
                //THEN
                await assert.doesNotReject(async() => {
                    //WHEN
                    const config = await localConfig.load();
                    assert.strictEqual(config.key, 'a');
                });
            });

            it('complex structure - test recurrency', async() => {
                //GIVEN
                const yaml = 'key: ${KEY_ENV:{"a":{"b":{"c":{"d":[1]}}}}}';
                const localConfig = proxyquire('../../src/common/config', {
                    '../common/readFileSafely': readFile(yaml),
                    'os':                       {
                        homedir: sinon.stub().returns('/home/user')
                    }
                });
                //THEN
                await assert.doesNotReject(async() => {
                    //WHEN
                    const config = await localConfig.load();
                    assert.deepEqual(config.key.a.b.c.d[0], 1);
                });
            });

            it('mandatory default', async() => {
                //GIVEN
                const yaml = 'key: ${KEY_ENV}';
                const localConfig = proxyquire('../../src/common/config', {
                    '../common/readFileSafely': readFile(yaml),
                    'os':                       {
                        homedir: sinon.stub().returns('/home/user')
                    }
                });
                //THEN
                await assert.rejects(
                    //WHEN
                    localConfig.load,
                    /Non-empty key and default value in config are mandatory in template/
                );
            });

            it('empty default', async() => {
                //GIVEN
                const yaml = 'key: ${KEY_ENV:}';
                const localConfig = proxyquire('../../src/common/config', {
                    '../common/readFileSafely': readFile(yaml),
                    'os':                       {
                        homedir: sinon.stub().returns('/home/user')
                    }
                });
                //THEN
                await assert.doesNotReject(async() => {
                    //WHEN
                    const config = await localConfig.load();
                    assert.strictEqual(config.key, '');
                });
            });

            it('default value with a colon', async() => {
                //GIVEN
                const yaml = 'key: ${KEY_ENV:host:port}';
                const localConfig = proxyquire('../../src/common/config', {
                    '../common/readFileSafely': readFile(yaml),
                    'os':                       {
                        homedir: sinon.stub().returns('/home/user')
                    }
                });
                //THEN
                await assert.doesNotReject(async() => {
                    //WHEN
                    const config = await localConfig.load();
                    assert.strictEqual(config.key, 'host:port');
                });
            });

            it('from env', async() => {
                //GIVEN
                const yaml = 'key: ${KEY_ENV:default}';
                const localConfig = proxyquire('../../src/common/config', {
                    '../common/readFileSafely': readFile(yaml),
                    'process':                  {
                        env: {
                            KEY_ENV: 'env_value'
                        }
                    },
                    'os': {
                        homedir: sinon.stub().returns('/home/user')
                    }
                });
                //THEN
                await assert.doesNotReject(async() => {
                    //WHEN
                    const config = await localConfig.load();
                    assert.strictEqual(config.key, 'env_value');
                });
            });

            it('APPLICATION_JSON overrides', async() => {
                //GIVEN
                const yaml = 'key: ${KEY_ENV:default}';
                const localConfig = proxyquire('../../src/common/config', {
                    '../common/readFileSafely': readFile(yaml),
                    'process':                  {
                        env: {
                            KEY_ENV:          'env_value',
                            APPLICATION_JSON: '{"KEY_ENV":"value_from_APPLICATION_JSON"}'
                        }
                    },
                    'os': {
                        homedir: sinon.stub().returns('/home/user')
                    }
                });
                //THEN
                await assert.doesNotReject(async() => {
                    //WHEN
                    const config = await localConfig.load();
                    assert.strictEqual(config.key, 'value_from_APPLICATION_JSON');
                });
            });

            it('both APPLICATION_JSON and APPLICATION_JSON_BASE64 defined, use APPLICATION_JSON', async() => {
                //GIVEN
                const yaml = 'key: ${KEY_ENV:default}';
                const localConfig = proxyquire('../../src/common/config', {
                    '../common/readFileSafely': readFile(yaml),
                    'process':                  {
                        env: {
                            KEY_ENV:                 'env_value',
                            APPLICATION_JSON:        '{"KEY_ENV":"value_from_APPLICATION_JSON"}',
                            // base64('{"KEY_ENV":"value_from_APPLICATION_JSON_BASE64"}')
                            APPLICATION_JSON_BASE64: 'eyJLRVlfRU5WIjoidmFsdWVfZnJvbV9BUFBMSUNBVElPTl9KU09OX0JBU0U2NCJ9Cg=='
                        }
                    },
                    'os': {
                        homedir: sinon.stub().returns('/home/user')
                    }
                });
                //THEN
                await assert.doesNotReject(async() => {
                    //WHEN
                    const config = await localConfig.load();
                    assert.strictEqual(config.key, 'value_from_APPLICATION_JSON');
                });
            });

            it('APPLICATION_JSON not as JSON', () => {
                //GIVEN
                const yaml = 'key: ${KEY_ENV:default}';
                //THEN
                assert.throws(
                    () => {
                        //WHEN
                        proxyquire('../../src/common/config', {
                            '../common/readFileSafely': readFile(yaml),
                            'process':                  {
                                env: {
                                    KEY_ENV:          'env_value',
                                    APPLICATION_JSON: 'notJSON'
                                }
                            },
                            'os': {
                                homedir: sinon.stub().returns('/home/user')
                            }
                        });
                    },
                    /Error parsing APPLICATION_JSON env variable. Make sure it is in JSON format/
                );
            });

            it('APPLICATION_JSON_BASE64 encoded string is not as JSON', () => {
                //GIVEN
                const yaml = 'key: ${KEY_ENV:default}';
                //THEN
                assert.throws(
                    () => {
                        //WHEN
                        proxyquire('../../src/common/config', {
                            '../common/readFileSafely': readFile(yaml),
                            'process':                  {
                                env: {
                                    KEY_ENV:                 'env_value',
                                    APPLICATION_JSON_BASE64: 'bm90SlNPTgo=' // base64(notJSON)
                                }
                            },
                            'os': {
                                homedir: sinon.stub().returns('/home/user')
                            }
                        });
                    },
                    /Error parsing APPLICATION_JSON_BASE64 env variable. Make sure its content is proper base64 of a JSON/
                );
            });

            it('APPLICATION_JSON_BASE64 not base64', () => {
                //GIVEN
                const yaml = 'key: ${KEY_ENV:default}';
                //THEN
                assert.throws(
                    () => {
                        //WHEN
                        proxyquire('../../src/common/config', {
                            '../common/readFileSafely': readFile(yaml),
                            'process':                  {
                                env: {
                                    KEY_ENV:                 'env_value',
                                    APPLICATION_JSON_BASE64: 'ZZZ'
                                }
                            },
                            'os': {
                                homedir: sinon.stub().returns('/home/user')
                            }
                        });
                    },
                    /Error parsing APPLICATION_JSON_BASE64 env variable. Make sure its content is proper base64 of a JSON/
                );
            });

        });

        it('no_such_file', async() => {
            //GIVEN
            const localConfig = proxyquire('../../src/common/config', {
                '../common/readFileSafely': readFile('', true),
                'os':                       {
                    homedir: sinon.stub().returns('/home/user')
                }
            });
            //THEN
            await assert.rejects(
                //WHEN
                localConfig.load,
                /no such file/
            );
        });

        it('invalid_yaml', async() => {
            //GIVEN
            const localConfig = proxyquire('../../src/common/config', {
                '../common/readFileSafely': readFile(invalidYaml),
                'os':                       {
                    homedir: sinon.stub().returns('/home/user')
                }
            });
            //THEN
            await assert.rejects(
                //WHEN
                localConfig.load,
                /end of the stream/
            );
        });

        describe('local', () => {

            it('positive', async() => {
                //GIVEN
                const localConfig = proxyquire('../../src/common/config', {
                    '../common/readFileSafely': readFile(validYamlWithTemplates),
                    'process':                  {
                        env: {
                            QVS_CONFIG_SOURCE: 'local'
                        }
                    },
                    'os': {
                        homedir: sinon.stub().returns('/home/user')
                    }
                });
                //THEN
                await assert.doesNotReject(
                    //WHEN
                    localConfig.load
                );
            });

        });

    });

    describe('base_validate', () => {
        it('success', () => {
            //GIVEN
            const base = new config.Base();
            //WHEN / THEN
            base.validate(
                {
                    test: 'test'
                },
                {
                    type:       'object',
                    properties: {
                        test: {
                            type: 'string'
                        }
                    }
                }
            );
        });

        it('fail', () => {
            //GIVEN
            const base = new config.Base();
            //WHEN / THEN
            assert.throws(() => {
                base.validate(
                    {
                        test2: 'test'
                    },
                    {
                        type:       'object',
                        required:   ['test'],
                        properties: {
                            test: {
                                type: 'string'
                            }
                        }
                    });
            }, /Missing required property: test/);
        });
    });

    describe('logger_constructor', () => {
        it('success', () => {
            //GIVEN / WHEN
            const logger = new config.Logger({
                levelFile:    'trace',
                levelConsole: 'off',
                fileName:     'fileName',
                category:     'category'
            });
            //THEN
            assert.equal('trace', logger.levelFile);
            assert.equal('off', logger.levelConsole);
            assert.equal('fileName', logger.fileName);
            assert.equal('category', logger.category);
        });

        it('missing_file_fail', () => {
            //THEN
            assert.throws(() => {
                //GIVEN / WHEN
                new config.Logger({
                    levelFile:    'off',
                    levelConsole: 'trace',
                    category:     'category'
                });
            }, /Missing required property: fileName/);
        });

        it('missing_levelFile_fail', () => {
            //THEN
            assert.throws(() => {
                //GIVEN / WHEN
                new config.Logger({
                    levelConsole: 'off',
                    fileName:     'fileName',
                    category:     'category'
                });
            }, /Missing required property: levelFile/);
        });

        it('missing_levelConsole_fail', () => {
            //THEN
            assert.throws(() => {
                //GIVEN / WHEN
                new config.Logger({
                    levelFile: 'off',
                    fileName:  'fileName',
                    category:  'category'
                });
            }, /Missing required property: levelConsole/);
        });

        it('missing_category_fail', () => {
            //THEN
            assert.throws(() => {
                //GIVEN / WHEN
                new config.Logger({
                    levelFile:    'off',
                    levelConsole: 'off',
                    fileName:     'fileName'
                });
            }, /Missing required property: category/);
        });
    });

    describe('healthCheck_constructor', () => {
        it('success', () => {
            //GIVEN / WHEN
            const healthCheck = new config.HealthCheck({
                intervalMs:  1000,
                freshnessMs: 5000
            });
            //THEN
            assert.equal(1000, healthCheck.intervalMs);
            assert.equal(5000, healthCheck.freshnessMs);
        });

        it('no_interavalMs_fail', () => {
            //THEN
            assert.throws(() => {
                //GIVEN / WHEN
                new config.HealthCheck({
                    freshnessMs: 1000
                });
            }, /Missing required property: intervalMs/);
        });

        it('no_freshnessMs_fail', () => {
            //THEN
            assert.throws(() => {
                //GIVEN / WHEN
                new config.HealthCheck({
                    intervalMs: 1000
                });
            }, /Missing required property: freshnessMs/);
        });

        it('no_freshnessMs_not_a_number_fail', () => {
            //THEN
            assert.throws(() => {
                //GIVEN / WHEN
                new config.HealthCheck({
                    intervalMs:  1000,
                    freshnessMs: 'not a number'
                });
            }, /Expected type number but found type string in freshnessMs/);
        });

        it('no_intervalMs_not_a_number_fail', () => {
            //THEN
            assert.throws(() => {
                //GIVEN / WHEN
                new config.HealthCheck({
                    freshnessMs: 1000,
                    intervalMs:  'not a number'
                });
            }, /Expected type number but found type string in intervalMs/);
        });
    });

    describe('service_constructor', () => {
        it('success', () => {
            //GIVEN / WHEN
            const service = new config.Service({
                componentName:     'ServiceName',
                componentShort:    'SRV',
                tlsServerType:     'MTLS',
                port:              80,
                certFile:          '/../configuration-default/certFile',
                keyFile:           'keyFile',
                caCertDirectories: 'certDirectory',
                bodySizeLimits:    {
                    text: '2mb',
                    json: '2mb',
                    form: '32kb'
                }
            });
            //THEN
            assert.equal(80, service.port);
            assert.equal('/../configuration-default/certFile', service.certFile);
            assert.equal('../configuration-default/keyFile', service.keyFile);
            assert.equal(1, service.caCertDirectories.length);
            assert.equal('../configuration-default/certDirectory', service.caCertDirectories[0]);
        });

        it('multiple_caCertDirectories_success', () => {
            //GIVEN / WHEN
            const service = new config.Service({
                componentName:     'ServiceName',
                componentShort:    'SRV',
                tlsServerType:     'MTLS',
                port:              80,
                certFile:          'certFile',
                keyFile:           'keyFile',
                caCertDirectories: 'certDirectory,certDirectory2,certDirectory3',
                bodySizeLimits:    {
                    text: '2mb',
                    json: '2mb',
                    form: '32kb'
                }
            });
            //THEN
            assert.equal(80, service.port);
            assert.equal('../configuration-default/certFile', service.certFile);
            assert.equal('../configuration-default/keyFile', service.keyFile);
            assert.equal(3, service.caCertDirectories.length);
            assert.equal('../configuration-default/certDirectory', service.caCertDirectories[0]);
            assert.equal('../configuration-default/certDirectory2', service.caCertDirectories[1]);
            assert.equal('../configuration-default/certDirectory3', service.caCertDirectories[2]);
        });

        it('required_success', () => {
            //GIVEN / WHEN
            const service = new config.Service({
                componentName:     'ServiceName',
                componentShort:    'SRV',
                tlsServerType:     'MTLS',
                certFile:          'certFile',
                keyFile:           'keyFile',
                caCertDirectories: 'certDirectory,certDirectory2,certDirectory3',
                bodySizeLimits:    {
                    text: '2mb',
                    json: '2mb',
                    form: '32kb'
                }
            });
            //THEN
            assert.equal(undefined, service.port);
            assert.equal('../configuration-default/certFile', service.certFile);
            assert.equal('../configuration-default/keyFile', service.keyFile);
            assert.equal(3, service.caCertDirectories.length);
            assert.equal('../configuration-default/certDirectory', service.caCertDirectories[0]);
            assert.equal('../configuration-default/certDirectory2', service.caCertDirectories[1]);
            assert.equal('../configuration-default/certDirectory3', service.caCertDirectories[2]);
        });

        it('tls_no_certFile_fail', () => {
            //THEN
            assert.throws(() => {
                //GIVEN / WHEN
                new config.Service({
                    componentName:     'ServiceName',
                    componentShort:    'SRV',
                    tlsServerType:     'TLS',
                    keyFile:           'keyFile',
                    caCertDirectories: 'certDirectory',
                    bodySizeLimits:    {
                        text: '2mb',
                        json: '2mb',
                        form: '32kb'
                    }
                });
            }, /Missing required property: certFile/);
        });

        it('tls_no_keyFile_fail', () => {
            //THEN
            assert.throws(() => {
                //GIVEN / WHEN
                new config.Service({
                    componentName:     'ServiceName',
                    componentShort:    'SRV',
                    tlsServerType:     'TLS',
                    certFile:          'test',
                    caCertDirectories: 'certDirectory',
                    bodySizeLimits:    {
                        text: '2mb',
                        json: '2mb',
                        form: '32kb'
                    }
                });
            }, /Missing required property: keyFile/);
        });

        it('no_tls_cert_and_key_not_required', () => {
            //GIVEN / WHEN
            const service = new config.Service({
                componentName:     'ServiceName',
                componentShort:    'SRV',
                tlsServerType:     'None',
                caCertDirectories: 'certDirectory',
                bodySizeLimits:    {
                    text: '2mb',
                    json: '2mb',
                    form: '32kb'
                }
            });
            //THEN
            assert.equal(undefined, service.port);
        });

        it('no_caCertDirectories_for_MTLS_fail', () => {
            //THEN
            assert.throws(() => {
                //GIVEN / WHEN
                new config.Service({
                    componentName:  'ServiceName',
                    componentShort: 'SRV',
                    tlsServerType:  'MTLS',
                    certFile:       'certFile',
                    keyFile:        'keyFile'
                });
            }, /Missing required property: caCertDirectories/);
        });

        it('no_caCertDirectories_is_not_string_fail', () => {
            //THEN
            assert.throws(() => {
                //GIVEN / WHEN
                new config.Service({
                    componentName:     'ServiceName',
                    componentShort:    'SRV',
                    certFile:          'test',
                    keyFile:           'keyFile',
                    caCertDirectories: ['not a string']
                });
            }, /Expected type string but found type array in caCertDirectories/);
        });

        it('multiple_fails', () => {
            /* Full error info:
                Error: Configuration parsing error(s) in "<path>/configuration/config.yml" <Service>:
                Missing required property: keyFile ::
                Missing required property: certFile ::
                Expected type string but found type integer in caCertDirectories ::
                Expected type string but found type undefined in keyFile ::
                Expected type number but found type string in port ::
                Expected type string but found type array in componentName
            */
            function checkException(e) {
                // all following cases should be true for proper exception validation
                return (
                    e instanceof Error &&
                    (/Missing required property: keyFile/).test(e) &&
                    (/Missing required property: certFile/).test(e) &&
                    (/Expected type string but found type integer in caCertDirectories/).test(e) &&
                    (/Expected type string but found type undefined in keyFile/).test(e) &&
                    (/Expected type number but found type string in port/).test(e) &&
                    (/Expected type string but found type array in componentName/).test(e)
                );
            }

            //THEN
            assert.throws(() => {
                //GIVEN / WHEN
                new config.Service({
                    componentName:     ['ServiceName'], // should be string, not an array
                    componentShort:    'SRV',
                    port:              'not-a-number',           // should be number, not a string
                    //certFile: 'certFile',         // should be present
                    keyFile:           undefined,             // should have a string value (also interpreted as non-existent value)
                    caCertDirectories: 1234                    // should be a string, not a number
                });
            }, checkException);
        });
    });

    describe('restclient_constructor', () => {
        it('success', () => {
            //GIVEN / WHEN
            const restclient = new config.RestClient({
                tlsClientType:     'MTLS',
                host:              'host',
                port:              80,
                retries:           3,
                initialInterval:   100,
                factor:            3,
                certFile:          'certFile',
                keyFile:           'keyFile',
                caCertDirectories: 'certificates/internal_ca/internal_use_ca_certificates/',
                servername:        ''
            });
            //THEN
            assert.equal('host', restclient.host);
            assert.equal(80, restclient.port);
            assert.equal(3, restclient.retries);
            assert.equal(100, restclient.initialInterval);
            assert.equal(3, restclient.factor);
            assert.equal('../configuration-default/certFile', restclient.certFile);
            assert.equal('../configuration-default/keyFile', restclient.keyFile);
            assert.deepEqual(['../configuration-default/certificates/internal_ca/internal_use_ca_certificates/'], restclient.caCertDirectories);
        });

        it('no_host_fail', () => {
            //THEN
            assert.throws(() => {
                //GIVEN / WHEN
                new config.RestClient({
                    port:            80,
                    retries:         3,
                    initialInterval: 100,
                    factor:          3,
                    certFile:        'certFile',
                    keyFile:         'keyFile'
                });
            }, /Missing required property: host/);
        });

        it('no_port_fail', () => {
            //THEN
            assert.throws(() => {
                //GIVEN / WHEN
                new config.RestClient({
                    host:            'host',
                    retries:         3,
                    initialInterval: 100,
                    factor:          3,
                    certFile:        'certFile',
                    keyFile:         'keyFile',
                    servername:      ''
                });
            }, /Missing required property: port/);
        });

        it('no_retries_fail', () => {
            //THEN
            assert.throws(() => {
                //GIVEN / WHEN
                new config.RestClient({
                    host:            'host',
                    port:            80,
                    initialInterval: 100,
                    factor:          3,
                    certFile:        'certFile',
                    keyFile:         'keyFile',
                    servername:      ''
                });
            }, /Missing required property: retries/);
        });

        it('no_initialInterval_fail', () => {
            //THEN
            assert.throws(() => {
                //GIVEN / WHEN
                new config.RestClient({
                    host:       'host',
                    port:       80,
                    retries:    3,
                    factor:     3,
                    certFile:   'certFile',
                    keyFile:    'keyFile',
                    servername: ''
                });
            }, /Missing required property: initialInterval/);
        });

        it('no_factor_fail', () => {
            //THEN
            assert.throws(() => {
                //GIVEN / WHEN
                new config.RestClient({
                    host:            'host',
                    port:            80,
                    retries:         3,
                    initialInterval: 100,
                    certFile:        'certFile',
                    keyFile:         'keyFile',
                    servername:      ''
                });
            }, /Missing required property: factor/);
        });

        it('port_not_a_number_fail', () => {
            //THEN
            assert.throws(() => {
                //GIVEN / WHEN
                new config.RestClient({
                    host:            'host',
                    port:            'not a number',
                    retries:         3,
                    initialInterval: 100,
                    factor:          3,
                    certFile:        'certFile',
                    keyFile:         'keyFile',
                    servername:      ''
                });
            }, /Expected type number but found type string in port/);
        });

        it('retries_not_a_number_fail', () => {
            //THEN
            assert.throws(() => {
                //GIVEN / WHEN
                new config.RestClient({
                    host:            'host',
                    port:            80,
                    retries:         'not a number',
                    initialInterval: 100,
                    factor:          3,
                    certFile:        'certFile',
                    keyFile:         'keyFile',
                    servername:      ''
                });
            }, /Expected type number but found type string in retries/);
        });

        it('initialInterval_not_a_number_fail', () => {
            //THEN
            assert.throws(() => {
                //GIVEN / WHEN
                new config.RestClient({
                    host:            'host',
                    port:            80,
                    retries:         3,
                    initialInterval: 'not a number',
                    factor:          3,
                    certFile:        'certFile',
                    keyFile:         'keyFile',
                    servername:      ''
                });
            }, /Expected type number but found type string in initialInterval/);
        });

        it('factor_not_a_number_fail', () => {
            //THEN
            assert.throws(() => {
                //GIVEN / WHEN
                new config.RestClient({
                    host:            'host',
                    port:            80,
                    retries:         3,
                    initialInterval: 100,
                    factor:          'not a number',
                    certFile:        'certFile',
                    keyFile:         'keyFile',
                    servername:      ''
                });
            }, /Expected type number but found type string in factor/);
        });
    });

    describe('cache  constructor', () => {
        it('should set properties as expected', () => {
            //GIVEN
            const configuration = {
                ttl:         900,
                checkPeriod: 60,
                maxKeys:     -1
            };
            //WHEN
            const cache = new config.Cache(configuration);
            //THEN
            assert.equal(configuration.ttl, cache.ttl);
            assert.equal(configuration.checkPeriod, cache.checkPeriod);
            assert.equal(configuration.maxKeys, cache.maxKeys);
        });

        it('should report missing required fields as expected', async() => {
            //GIVEN
            const configuration = {};
            try {
                //WHEN
                await new config.Cache(configuration);
                assert.fail('Should throw error');
            }
            catch (error) {
                //THEN
                assertErrorReport.missingProperty(error, 'ttl');
                assertErrorReport.missingProperty(error, 'checkPeriod');
                assertErrorReport.missingProperty(error, 'maxKeys');
            }
        });
    });

    describe('baseRestService_constructor', () => {
        it('all_success', () => {
            //GIVEN / WHEN
            const baseRestService = new config.BaseRestService({
                logger: {
                    levelFile:    'debug',
                    levelConsole: 'debug',
                    fileName:     'fileName',
                    category:     'category'
                },
                service: {
                    componentName:     'ServiceName',
                    componentShort:    'SRV',
                    tlsServerType:     'MTLS',
                    port:              80,
                    certFile:          'certFile',
                    keyFile:           'keyFile',
                    caCertDirectories: 'certDirectory',
                    bodySizeLimits:    {
                        text: '2mb',
                        json: '2mb',
                        form: '32kb'
                    }
                },
                healthCheck: {
                    intervalMs:    1000,
                    freshnessMs:   1000,
                    extraHttpPort: 80,
                    table:         'test'
                },
            });

            //THEN
            assert.notEqual(undefined, baseRestService.logger);
            assert.notEqual(undefined, baseRestService.service);
            assert.notEqual(undefined, baseRestService.healthCheck);
        });

        it('no_logger_success', () => {
            //GIVEN / WHEN
            const baseRestService = new config.BaseRestService({
                service: {
                    componentName:     'ServiceName',
                    componentShort:    'SRV',
                    tlsServerType:     'MTLS',
                    port:              80,
                    certFile:          'certFile',
                    keyFile:           'keyFile',
                    caCertDirectories: 'certDirectory',
                    bodySizeLimits:    {
                        text: '2mb',
                        json: '2mb',
                        form: '32kb'
                    }
                },
                healthCheck: {
                    intervalMs:    1000,
                    freshnessMs:   1000,
                    extraHttpPort: 80,
                    table:         'test'
                },
            });

            //THEN
            assert.equal(undefined, baseRestService.logger);
            assert.notEqual(undefined, baseRestService.service);
            assert.notEqual(undefined, baseRestService.healthCheck);
        });

        it('no_service_success', () => {
            //GIVEN / WHEN
            const baseRestService = new config.BaseRestService({
                logger: {
                    levelFile:    'trace',
                    levelConsole: 'off',
                    fileName:     'fileName',
                    category:     'category'
                },
                healthCheck: {
                    intervalMs:    1000,
                    freshnessMs:   1000,
                    extraHttpPort: 80,
                    table:         'test'
                },
            });

            //THEN
            assert.notEqual(undefined, baseRestService.logger);
            assert.equal(undefined, baseRestService.service);
            assert.notEqual(undefined, baseRestService.healthCheck);
        });

        it('maxClient_success', () => {
            //GIVEN / WHEN
            const baseRestService = new config.BaseRestService({
                logger: {
                    levelFile:    'trace',
                    levelConsole: 'off',
                    fileName:     'fileName',
                    category:     'category'
                },
                healthCheck: {
                    intervalMs:    1000,
                    freshnessMs:   1000,
                    extraHttpPort: 80,
                    table:         'test'
                },
                service: {
                    componentName:  'componentName',
                    componentShort: 'componentShort',
                    tlsServerType:  'None',
                    maxClients:     4,
                    bodySizeLimits: {
                        text: '2mb',
                        json: '2mb',
                        form: '32kb'
                    }
                }
            });

            //THEN
            assert.notStrictEqual(undefined, baseRestService.logger);
            assert.notStrictEqual(undefined, baseRestService.service);
            assert.notStrictEqual(undefined, baseRestService.healthCheck);
        });

        it('no_healthCheck_success', () => {
            //GIVEN / WHEN
            const baseRestService = new config.BaseRestService({
                logger: {
                    levelFile:    'trace',
                    levelConsole: 'trace',
                    fileName:     'fileName',
                    category:     'category'
                },
                service: {
                    componentName:     'ServiceName',
                    componentShort:    'SRV',
                    tlsServerType:     'MTLS',
                    port:              80,
                    certFile:          'certFile',
                    keyFile:           'keyFile',
                    caCertDirectories: 'certDirectory',
                    bodySizeLimits:    {
                        text: '2mb',
                        json: '2mb',
                        form: '32kb'
                    }
                },
            });

            //THEN
            assert.notEqual(undefined, baseRestService.logger);
            assert.notEqual(undefined, baseRestService.service);
            assert.equal(undefined, baseRestService.healthCheck);
        });

        it('broken_logger_fail', () => {
            //THEN
            assert.throws(() => {
                //GIVEN / WHEN
                new config.BaseRestService({
                    logger: {
                        levelFile:    'error',
                        levelConsole: 'error',
                        category:     'category'
                    },
                    service: {
                        componentName:     'ServiceName',
                        componentShort:    'SRV',
                        tlsServerType:     'MTLS',
                        port:              80,
                        certFile:          'certFile',
                        keyFile:           'keyFile',
                        caCertDirectories: 'certDirectory',
                        bodySizeLimits:    {
                            text: '2mb',
                            json: '2mb',
                            form: '32kb'
                        }
                    },
                    healthCheck: {
                        intervalMs:    1000,
                        freshnessMs:   1000,
                        extraHttpPort: 80,
                        table:         'test'
                    },
                });
            }, / Missing required property: fileName/);
        });

        it('broken_service_fail', () => {
            //THEN
            assert.throws(() => {
                //GIVEN / WHEN
                new config.BaseRestService({
                    logger: {
                        levelFile:    'error',
                        levelConsole: 'fatal',
                        fileName:     'fileName',
                        category:     'category'
                    },
                    service: {
                        componentName:     'ServiceName',
                        tlsServerType:     'MTLS',
                        keyFile:           'keyFile',
                        certFile:          'certFile',
                        caCertDirectories: 'certDirectory',
                        bodySizeLimits:    {
                            text: '2mb',
                            json: '2mb',
                            form: '32kb'
                        }
                    },
                    healthCheck: {
                        intervalMs:    1000,
                        freshnessMs:   1000,
                        extraHttpPort: 80,
                        tables:        { testTable: 'test' }
                    },
                });
            }, /Missing required property: componentShort/);
        });

        it('broken_healthCheck_fail', () => {
            //THEN
            assert.throws(() => {
                //GIVEN / WHEN
                new config.BaseRestService({
                    logger: {
                        levelFile:    'off',
                        levelConsole: 'debug',
                        fileName:     'fileName',
                        category:     'category'
                    },
                    service: {
                        componentName:     'ServiceName',
                        componentShort:    'SRV',
                        tlsServerType:     'MTLS',
                        port:              80,
                        certFile:          'certFile',
                        keyFile:           'keyFile',
                        caCertDirectories: 'certDirectory',
                        bodySizeLimits:    {
                            text: '2mb',
                            json: '2mb',
                            form: '32kb'
                        }
                    },
                    healthCheck: {
                        intervalMs:    1000,
                        extraHttpPort: 80,
                        table:         'test'
                    },
                });
            }, /Missing required property: freshnessMs/);
        });

    });

    describe('testService_constructor', () => {
        it('lack_of_whole_section_fail', () => {
            //GIVEN
            // all real configs (per service) are created that way:
            class SvcConfig extends config.BaseRestService {
                constructor(configJson) {
                    super(configJson);
                    this.validate(configJson, {
                        //this list is a list of sections that are required for our test service configuration
                        required: ['service', 'healthCheck', 'logger']
                    });
                }
            }

            //THEN
            assert.throws(() => {
                //WHEN
                new SvcConfig({
                    service: {
                        componentName:     'ServiceName',
                        componentShort:    'SRV',
                        tlsServerType:     'MTLS',
                        port:              80,
                        certFile:          'certFile',
                        keyFile:           'keyFile',
                        caCertDirectories: 'certDirectory',
                        bodySizeLimits:    {
                            text: '2mb',
                            json: '2mb',
                            form: '32kb'
                        }
                    },
                    //healthCheck: {                    // this is our missing section
                    //    intervalMs : 1000,
                    //    freshnessMs: 1000,
                    //    port       : 80,
                    //    table      : 'test'
                    //},
                    logger: {
                        levelFile:    'fatal',
                        levelConsole: 'fatal',
                        fileName:     'fileName',
                        category:     'category'
                    }
                });
            }, /Missing required property: healthCheck/);
        });
    });

    describe('appendConfigPath', () => {
        it('should not modify field when field format is number', () => {
            //GIVEN
            const object = {
                numberField: 1
            };

            //WHEN
            config.appendConfigPath(object, ['numberField']);

            //THEN
            assert.equal(1, object.numberField);
        });

        it('should modify only selected fields', () => {
            //GIVEN
            const object = {
                modifiedField: 'modifiedField',
                otherField:    'otherField'
            };

            //WHEN
            config.appendConfigPath(object, ['modifiedField']);

            //THEN
            assert.equal('../configuration-default/modifiedField', object.modifiedField);
            assert.equal('otherField', object.otherField);
        });

        it('should modify as expected when field is a string', () => {
            //GIVEN
            const object = {
                stringField: 'value'
            };

            //WHEN
            config.appendConfigPath(object, ['stringField']);

            //THEN
            assert.equal('../configuration-default/value', object.stringField);
        });

        it('should modify as expected when field is an array', () => {
            //GIVEN
            const object = {
                arrayField: ['value']
            };

            //WHEN
            config.appendConfigPath(object, ['arrayField']);

            //THEN
            assert.equal(object.arrayField, '../configuration-default/value');
        });
    });

    describe('configLoaderTest', () => {
        it('positive', async() => {
            //GIVEN
            class configClass {}
            const config = proxyquire('../../src/common/config', {
                '../common/readFileSafely': readFile(validYaml),
                'os':                       {
                    homedir: sinon.stub().returns('/home/user')
                }
            });

            const configLoader = new config.ConfigLoader(configClass);
            await configLoader.init('');

            //WHEN
            const resultFirstCall = configLoader.getConfig();
            const resultSecondCall = configLoader.getConfig();

            //THEN
            assert.ok(resultFirstCall instanceof configClass);
            assert.ok(resultSecondCall instanceof configClass);
            assert.strictEqual(resultFirstCall, resultSecondCall);
        });

        it('uninitialized', async() => {
            //GIVEN
            class configClass {}
            const config = proxyquire('../../src/common/config', {
                '../common/readFileSafely': readFile(validYaml),
                'os':                       {
                    homedir: sinon.stub().returns('/home/user')
                }
            });

            const configLoader = new config.ConfigLoader(configClass);

            //THEN
            assert.throws(() => {
                //WHEN
                configLoader.getConfig();
            },
            /You need to call init\(path\) first and await initialization. Run server using `node .\/bootstrap.js and set correct config profile/
            );
        });
    });
});
