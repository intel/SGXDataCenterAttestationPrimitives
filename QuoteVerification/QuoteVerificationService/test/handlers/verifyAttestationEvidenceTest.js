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

const proxyquire = require('proxyquire').noCallThru().noPreserveCache();
const sinon = require('sinon');
const assert = require('assert');
const qvlStatus = require('../../src/qvl/status');
const errorSource = require('../../src/qvl/verifyQuoteErrorSource');
const assertMockCalledOnceWithArgs = require('../mocks/helpers').assertMockCalledOnceWithArgs;

const iso8601Regex = (/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(([+-]\d\d:\d\d)|Z)?$/i);

class TestContext {
    constructor() {
        this.certificateChainParser = {
            parseCertificateChainWithSpecificRoot:    sinon.stub(),
            parseTcbInfoSigningChainWithSpecificRoot: sinon.stub()
        };
        this.pcsClient = {
            getSgxTcbInfo:    sinon.stub(),
            getTdxTcbInfo:    sinon.stub(),
            getSgxQeIdentity: sinon.stub(),
            getTdxQeIdentity: sinon.stub()
        };
        this.crlClient = {
            getCrlFromDistributionPoint: sinon.stub()
        };
        this.logger = {
            info:  sinon.stub(),
            error: sinon.stub()
        };
        this.reqId = 'requestId';
        this.nonce = 'abcdefabcdef01234567890123456789';
        this.qvl = {
            getCertificationData:    sinon.stub(),
            getPckCertificateData:   sinon.stub(),
            getCrlDistributionPoint: sinon.stub(),
            verifyQuote:             sinon.stub()
        };
        this.vcsClient = {
            signVerificationReport: sinon.stub(),
        };
        this.configLoader = {
            getConfig: () => ({
                target: {
                    attestationReportSigningCaCertificate: sinon.stub(),
                    attestationReportSigningCertificate:   sinon.stub()
                }
            })
        };

        this.sgxQuote = 'AwACAAAAAAAEAAkAk5pyM/ecTKmUCg2zlX8GB3cEhXlSheEulmeokact7P4AAAAADQ0DBf+AAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAA/NbIKlebNUxhlIX/ysdhdjxtT2O+JTpqaPcLeJTp9SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAyEBhE5TtWVUKTgl2yS/DCkZ8aq0eu1aesDBuOxNUj9wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALhAAAExARVhwI2Qn6dtUK6O0qXpk97fZreM6ZtKxZVT5qFn/ZAqhUiOaiGMMIpu9SxOZfKnaZ3zTwkCVf2sApkYogL94Ijy59eb/nU0Lj+srbesE7PmrZ5M54oX1drz7Xxc74J+kA8tTxBaAZLNR6Z4BC1nUDtqqhaglnM8WwRXwXvH9DQ0DBf+AAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFQAAAAAAAAAHAAAAAAAAAAoqYO/EltvIi0w5bLQ4hA9bfdxLGAaAdJiKy10HVPF7AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACMT1d115ZQPpYTf3fGioKaAFasje1wFAsIGwlEkMV7/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACKe7gLvTbu8WKg4PBEDSsru/MqCZWIrP03ttBj2bRkkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeEbJ4qdQbfFHhAGIjijcPWHDmKmD4EMd3ONCtaLkQNHXBB9+H84y46sChtz9w4aYlBGpPOFQYFPwFxdBZEFhBiAAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8FAMYNAAAtLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJRWdEQ0NCQ2FnQXdJQkFnSVVWdlV0aGxBQjJjM2xvNms1T1M5YllOUlF2aEl3Q2dZSUtvWkl6ajBFQXdJd2NURWpNQ0VHQTFVRQpBd3dhU1c1MFpXd2dVMGRZSUZCRFN5QlFjbTlqWlhOemIzSWdRMEV4R2pBWUJnTlZCQW9NRVVsdWRHVnNJRU52Y25CdmNtRjBhVzl1Ck1SUXdFZ1lEVlFRSERBdFRZVzUwWVNCRGJHRnlZVEVMTUFrR0ExVUVDQXdDUTBFeEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRFNU1UQXgKTlRBM01qQTFORm9YRFRJMk1UQXhOVEEzTWpBMU5Gb3djREVpTUNBR0ExVUVBd3daU1c1MFpXd2dVMGRZSUZCRFN5QkRaWEowYVdacApZMkYwWlRFYU1CZ0dBMVVFQ2d3UlNXNTBaV3dnUTI5eWNHOXlZWFJwYjI0eEZEQVNCZ05WQkFjTUMxTmhiblJoSUVOc1lYSmhNUXN3CkNRWURWUVFJREFKRFFURUxNQWtHQTFVRUJoTUNWVk13V1RBVEJnY3Foa2pPUFFJQkJnZ3Foa2pPUFFNQkJ3TkNBQVFFeklzY0lFa3QKQ1NsNmdMTkN2a3haSVhNYmxOcU9KWTg4cFdpUENMKy9VZkViUktpZ3VCUVQ2MU0xVlAySGgyaWk2enBrUEhrT3NTSW02Z25JMjE4UwpvNElDbXpDQ0FwY3dId1lEVlIwakJCZ3dGb0FVME9pcTJuWFgrUzVKRjVnOGV4UmwwTlh5V1Uwd1h3WURWUjBmQkZnd1ZqQlVvRktnClVJWk9hSFIwY0hNNkx5OWhjR2t1ZEhKMWMzUmxaSE5sY25acFkyVnpMbWx1ZEdWc0xtTnZiUzl6WjNndlkyVnlkR2xtYVdOaGRHbHYKYmk5Mk1pOXdZMnRqY213L1kyRTljSEp2WTJWemMyOXlNQjBHQTFVZERnUVdCQlIyMHBhUkRJUXN1RlJxNGtrMWpmSUVlV0lxZGpBTwpCZ05WSFE4QkFmOEVCQU1DQnNBd0RBWURWUjBUQVFIL0JBSXdBRENDQWRRR0NTcUdTSWI0VFFFTkFRU0NBY1V3Z2dIQk1CNEdDaXFHClNJYjRUUUVOQVFFRUVJYTduYkdWNnJpWkpIejZDSlFsK0k0d2dnRmtCZ29xaGtpRytFMEJEUUVDTUlJQlZEQVFCZ3NxaGtpRytFMEIKRFFFQ0FRSUJEVEFRQmdzcWhraUcrRTBCRFFFQ0FnSUJEVEFRQmdzcWhraUcrRTBCRFFFQ0F3SUJBakFRQmdzcWhraUcrRTBCRFFFQwpCQUlCQkRBUUJnc3Foa2lHK0UwQkRRRUNCUUlCQVRBUkJnc3Foa2lHK0UwQkRRRUNCZ0lDQUlBd0VBWUxLb1pJaHZoTkFRMEJBZ2NDCkFRTXdFQVlMS29aSWh2aE5BUTBCQWdnQ0FRQXdFQVlMS29aSWh2aE5BUTBCQWdrQ0FRQXdFQVlMS29aSWh2aE5BUTBCQWdvQ0FRQXcKRUFZTEtvWklodmhOQVEwQkFnc0NBUUF3RUFZTEtvWklodmhOQVEwQkFnd0NBUUF3RUFZTEtvWklodmhOQVEwQkFnMENBUUF3RUFZTApLb1pJaHZoTkFRMEJBZzRDQVFBd0VBWUxLb1pJaHZoTkFRMEJBZzhDQVFBd0VBWUxLb1pJaHZoTkFRMEJBaEFDQVFBd0VBWUxLb1pJCmh2aE5BUTBCQWhFQ0FRa3dId1lMS29aSWh2aE5BUTBCQWhJRUVBME5BZ1FCZ0FNQUFBQUFBQUFBQUFBd0VBWUtLb1pJaHZoTkFRMEIKQXdRQ0FBQXdGQVlLS29aSWh2aE5BUTBCQkFRR0FKQnVvUUFBTUE4R0NpcUdTSWI0VFFFTkFRVUtBUUF3Q2dZSUtvWkl6ajBFQXdJRApTQUF3UlFJZ2Y4QmJqLzl4VmJlamhxbnRocjFjSGNYNWZGNU1TdFM1dENnWm13Q0w5OElDSVFDVFgrTGk1ZHJPNzRnc2RYYmpyYXdoCnVaMFdzTlJFSTdXSUVQRWQ5ZnAvS2c9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNsekNDQWo2Z0F3SUJBZ0lWQU5Eb3F0cDExL2t1U1JlWVBIc1VaZERWOGxsTk1Bb0dDQ3FHU000OUJBTUMKTUdneEdqQVlCZ05WQkFNTUVVbHVkR1ZzSUZOSFdDQlNiMjkwSUVOQk1Sb3dHQVlEVlFRS0RCRkpiblJsYkNCRApiM0p3YjNKaGRHbHZiakVVTUJJR0ExVUVCd3dMVTJGdWRHRWdRMnhoY21FeEN6QUpCZ05WQkFnTUFrTkJNUXN3CkNRWURWUVFHRXdKVlV6QWVGdzB4T0RBMU1qRXhNRFExTURoYUZ3MHpNekExTWpFeE1EUTFNRGhhTUhFeEl6QWgKQmdOVkJBTU1Ha2x1ZEdWc0lGTkhXQ0JRUTBzZ1VISnZZMlZ6YzI5eUlFTkJNUm93R0FZRFZRUUtEQkZKYm5SbApiQ0JEYjNKd2IzSmhkR2x2YmpFVU1CSUdBMVVFQnd3TFUyRnVkR0VnUTJ4aGNtRXhDekFKQmdOVkJBZ01Ba05CCk1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTDlxK05NcDJJT2cKdGRsMWJrL3VXWjUrVEdRbThhQ2k4ejc4ZnMrZktDUTNkK3VEelhuVlRBVDJaaERDaWZ5SXVKd3ZOM3dOQnA5aQpIQlNTTUpNSnJCT2pnYnN3Z2Jnd0h3WURWUjBqQkJnd0ZvQVVJbVVNMWxxZE5JbnpnN1NWVXI5UUd6a25CcXd3ClVnWURWUjBmQkVzd1NUQkhvRVdnUTRaQmFIUjBjSE02THk5alpYSjBhV1pwWTJGMFpYTXVkSEoxYzNSbFpITmwKY25acFkyVnpMbWx1ZEdWc0xtTnZiUzlKYm5SbGJGTkhXRkp2YjNSRFFTNWpjbXd3SFFZRFZSME9CQllFRk5EbwpxdHAxMS9rdVNSZVlQSHNVWmREVjhsbE5NQTRHQTFVZER3RUIvd1FFQXdJQkJqQVNCZ05WSFJNQkFmOEVDREFHCkFRSC9BZ0VBTUFvR0NDcUdTTTQ5QkFNQ0EwY0FNRVFDSUMvOWorODRUK0h6dFZPL3NPUUJXSmJTZCsvMnVleEsKNCthQTBqY0ZCTGNwQWlBM2RoTXJGNWNENTJ0NkZxTXZBSXBqOFhkR215MmJlZWxqTEpLK3B6cGNSQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNqakNDQWpTZ0F3SUJBZ0lVSW1VTTFscWROSW56ZzdTVlVyOVFHemtuQnF3d0NnWUlLb1pJemowRUF3SXcKYURFYU1CZ0dBMVVFQXd3UlNXNTBaV3dnVTBkWUlGSnZiM1FnUTBFeEdqQVlCZ05WQkFvTUVVbHVkR1ZzSUVOdgpjbkJ2Y21GMGFXOXVNUlF3RWdZRFZRUUhEQXRUWVc1MFlTQkRiR0Z5WVRFTE1Ba0dBMVVFQ0F3Q1EwRXhDekFKCkJnTlZCQVlUQWxWVE1CNFhEVEU0TURVeU1URXdOREV4TVZvWERUTXpNRFV5TVRFd05ERXhNRm93YURFYU1CZ0cKQTFVRUF3d1JTVzUwWld3Z1UwZFlJRkp2YjNRZ1EwRXhHakFZQmdOVkJBb01FVWx1ZEdWc0lFTnZjbkJ2Y21GMAphVzl1TVJRd0VnWURWUVFIREF0VFlXNTBZU0JEYkdGeVlURUxNQWtHQTFVRUNBd0NRMEV4Q3pBSkJnTlZCQVlUCkFsVlRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVDNm5Fd01ESVlaT2ovaVBXc0N6YUVLaTcKMU9pT1NMUkZoV0dqYm5CVkpmVm5rWTR1M0lqa0RZWUwwTXhPNG1xc3lZamxCYWxUVll4RlAyc0pCSzV6bEtPQgp1ekNCdURBZkJnTlZIU01FR0RBV2dCUWlaUXpXV3AwMGlmT0R0SlZTdjFBYk9TY0dyREJTQmdOVkhSOEVTekJKCk1FZWdSYUJEaGtGb2RIUndjem92TDJObGNuUnBabWxqWVhSbGN5NTBjblZ6ZEdWa2MyVnlkbWxqWlhNdWFXNTAKWld3dVkyOXRMMGx1ZEdWc1UwZFlVbTl2ZEVOQkxtTnliREFkQmdOVkhRNEVGZ1FVSW1VTTFscWROSW56ZzdTVgpVcjlRR3prbkJxd3dEZ1lEVlIwUEFRSC9CQVFEQWdFR01CSUdBMVVkRXdFQi93UUlNQVlCQWY4Q0FRRXdDZ1lJCktvWkl6ajBFQXdJRFNBQXdSUUlnUVFzLzA4cnljZFBhdUNGazhVUFFYQ01BbHNsb0JlN053YVFHVGNkcGEwRUMKSVFDVXQ4U0d2eEttanBjTS96MFdQOUR2bzhoMms1ZHUxaVdEZEJrQW4rMGlpQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K';
        this.tdxQuote = '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';
        this.certificationData = `-----BEGIN CERTIFICATE-----
MIIEgDCCBCagAwIBAgIUVvUthlAB2c3lo6k5OS9bYNRQvhIwCgYIKoZIzj0EAwIwcTEjMCEGA1UE
AwwaSW50ZWwgU0dYIFBDSyBQcm9jZXNzb3IgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9u
MRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYTAlVTMB4XDTE5MTAx
NTA3MjA1NFoXDTI2MTAxNTA3MjA1NFowcDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBDZXJ0aWZp
Y2F0ZTEaMBgGA1UECgwRSW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQsw
CQYDVQQIDAJDQTELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQEzIscIEkt
CSl6gLNCvkxZIXMblNqOJY88pWiPCL+/UfEbRKiguBQT61M1VP2Hh2ii6zpkPHkOsSIm6gnI218S
o4ICmzCCApcwHwYDVR0jBBgwFoAU0Oiq2nXX+S5JF5g8exRl0NXyWU0wXwYDVR0fBFgwVjBUoFKg
UIZOaHR0cHM6Ly9hcGkudHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9zZ3gvY2VydGlmaWNhdGlv
bi92Mi9wY2tjcmw/Y2E9cHJvY2Vzc29yMB0GA1UdDgQWBBR20paRDIQsuFRq4kk1jfIEeWIqdjAO
BgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH/BAIwADCCAdQGCSqGSIb4TQENAQSCAcUwggHBMB4GCiqG
SIb4TQENAQEEEIa7nbGV6riZJHz6CJQl+I4wggFkBgoqhkiG+E0BDQECMIIBVDAQBgsqhkiG+E0B
DQECAQIBDTAQBgsqhkiG+E0BDQECAgIBDTAQBgsqhkiG+E0BDQECAwIBAjAQBgsqhkiG+E0BDQEC
BAIBBDAQBgsqhkiG+E0BDQECBQIBATARBgsqhkiG+E0BDQECBgICAIAwEAYLKoZIhvhNAQ0BAgcC
AQMwEAYLKoZIhvhNAQ0BAggCAQAwEAYLKoZIhvhNAQ0BAgkCAQAwEAYLKoZIhvhNAQ0BAgoCAQAw
EAYLKoZIhvhNAQ0BAgsCAQAwEAYLKoZIhvhNAQ0BAgwCAQAwEAYLKoZIhvhNAQ0BAg0CAQAwEAYL
KoZIhvhNAQ0BAg4CAQAwEAYLKoZIhvhNAQ0BAg8CAQAwEAYLKoZIhvhNAQ0BAhACAQAwEAYLKoZI
hvhNAQ0BAhECAQkwHwYLKoZIhvhNAQ0BAhIEEA0NAgQBgAMAAAAAAAAAAAAwEAYKKoZIhvhNAQ0B
AwQCAAAwFAYKKoZIhvhNAQ0BBAQGAJBuoQAAMA8GCiqGSIb4TQENAQUKAQAwCgYIKoZIzj0EAwID
SAAwRQIgf8Bbj/9xVbejhqnthr1cHcX5fF5MStS5tCgZmwCL98ICIQCTX+Li5drO74gsdXbjrawh
uZ0WsNREI7WIEPEd9fp/Kg==
-----END CERTIFICATE----------BEGIN CERTIFICATE-----
MIIClzCCAj6gAwIBAgIVANDoqtp11/kuSReYPHsUZdDV8llNMAoGCCqGSM49BAMC
MGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBD
b3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQsw
CQYDVQQGEwJVUzAeFw0xODA1MjExMDQ1MDhaFw0zMzA1MjExMDQ1MDhaMHExIzAh
BgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQKDBFJbnRl
bCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNB
MQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABL9q+NMp2IOg
tdl1bk/uWZ5+TGQm8aCi8z78fs+fKCQ3d+uDzXnVTAT2ZhDCifyIuJwvN3wNBp9i
HBSSMJMJrBOjgbswgbgwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqww
UgYDVR0fBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNl
cnZpY2VzLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5jcmwwHQYDVR0OBBYEFNDo
qtp11/kuSReYPHsUZdDV8llNMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
AQH/AgEAMAoGCCqGSM49BAMCA0cAMEQCIC/9j+84T+HztVO/sOQBWJbSd+/2uexK
4+aA0jcFBLcpAiA3dhMrF5cD52t6FqMvAIpj8XdGmy2beeljLJK+pzpcRA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICjjCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDExMVoXDTMzMDUyMTEwNDExMFowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmNybDAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSAAwRQIgQQs/08rycdPauCFk8UPQXCMAlsloBe7NwaQGTcdpa0EC
IQCUt8SGvxKmjpcM/z0WP9Dvo8h2k5du1iWDdBkAn+0iiA==
-----END CERTIFICATE-----`;
    }

    async getCtx() {
        return {
            log:     this.logger,
            reqId:   this.reqId,
            request: {
                body: {
                    nonce: this.nonce
                }
            },
            set: sinon.stub()
        };
    }

    async getTarget() {
        return proxyquire('../../src/handlers/verifyAttestationEvidence', {
            './certificateChainParser':            this.certificateChainParser,
            '../clients/pcsAccessLayer/PCSClient': this.pcsClient,
            '../clients/crlAccessLayer/CRLClient': this.crlClient,
            '../qvl':                              this.qvl,
            '../clients/vcsAccessLayer/VCSClient': this.vcsClient,
            '../configLoader':                     this.configLoader
        });
    }

    setupCertificationData() {
        this.qvl.getCertificationData.resolves({
            type: 5,
            data: this.certificationData
        });
        return this;
    }

    setupPckCertificateData(override = {}) {
        this.qvl.getPckCertificateData.resolves({
            fmspc:           override.fmspc || '00906EA10000',
            sgxType:         override.sgxType || 'Standard',
            cpusvn:          override.cpusvn || Buffer.from([3, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            pcesvn:          override.pcesvn || 3,
            dynamicPlatform: Boolean(override.dynamicPlatform),
            cachedKeys:      Boolean(override.cachedKeys),
            smtEnabled:      Boolean(override.smtEnabled),
        });
        return this;
    }

    setupCrlDistributionPoint() {
        this.qvl.getCrlDistributionPoint.resolves('Full Name:   URI:https://certificates.trustedservices.intel.com/IntelSGXRootCA.crl');
        this.crlClient.getCrlFromDistributionPoint.resolves({ status: 200, body: '-----BEGIN CERTIFICATE-----' });
        return this;
    }

    setupTcbInfo(tcbInfo) {
        tcbInfo = tcbInfo ?
            tcbInfo :
            {
                tcbInfo: {
                    issueDate: '2021-08-06T13:55:15Z',
                    tcbLevels: [
                        {
                            tcb: {
                                sgxtcbcomponents: [
                                    {
                                        svn: 3
                                    },
                                    {
                                        svn: 2
                                    },
                                    {
                                        svn: 1
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    }
                                ],
                                tdxtcbcomponents: [
                                    {
                                        svn:      82,
                                        category: 'KRYYIXKC8U',
                                        type:     '@TU9B14XQO'
                                    },
                                    {
                                        svn:      193,
                                        category: '504X036OI0',
                                        type:     'EQJ363GEJV'
                                    },
                                    {
                                        svn:      163,
                                        category: 'JZT5BUBBET',
                                        type:     '@6ZH630STD'
                                    },
                                    {
                                        svn:      140,
                                        category: 'XMJJ814468',
                                        type:     '1G0N1J G9D'
                                    },
                                    {
                                        svn:      247,
                                        category: 'HGVSWL@TCR',
                                        type:     '9WZUC8QV@G'
                                    },
                                    {
                                        svn: 237
                                    },
                                    {
                                        svn: 243
                                    },
                                    {
                                        svn: 10
                                    },
                                    {
                                        svn: 82
                                    },
                                    {
                                        svn:      75,
                                        category: 'GDXEGMOEMR',
                                        type:     'TC145 MZV0'
                                    },
                                    {
                                        svn:      78,
                                        category: 'L9GDQAPJEN',
                                        type:     'I YVRGWSOR'
                                    },
                                    {
                                        svn:      187,
                                        category: 'AW 0H0XEFY',
                                        type:     'PNGZ1XU075'
                                    },
                                    {
                                        svn: 4
                                    },
                                    {
                                        svn: 159
                                    },
                                    {
                                        svn:      89,
                                        category: 'JLH22L7UTB',
                                        type:     'GX3A1IZC82'
                                    },
                                    {
                                        svn: 199
                                    },
                                ],
                                pcesvn: 3,
                            },
                            tcbDate:   '2019-09-01T00:00:00Z',
                            tcbStatus: 'UpToDate'
                        },
                        {
                            tcb: {
                                sgxtcbcomponents: [
                                    {
                                        svn: 3
                                    },
                                    {
                                        svn: 2
                                    },
                                    {
                                        svn:      0,
                                        category: 'cat1',
                                        type:     'type1'
                                    },
                                    {
                                        svn:      0,
                                        category: 'cat1',
                                    },
                                    {
                                        svn:  0,
                                        type: 'type1'
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    }
                                ],
                                tdxtcbcomponents: [
                                    {
                                        svn:      81,
                                        category: 'KRYYIXKC8U',
                                        type:     '@TU9B14XQO'
                                    },
                                    {
                                        svn:      193,
                                        category: '504X036OI0',
                                        type:     'EQJ363GEJV'
                                    },
                                    {
                                        svn:  163,
                                        type: '@6ZH630STD'
                                    },
                                    {
                                        svn:      140,
                                        category: 'XMJJ814468',
                                    },
                                    {
                                        svn:      247,
                                        category: 'HGVSWL@TCR',
                                        type:     '9WZUC8QV@G'
                                    },
                                    {
                                        svn: 237
                                    },
                                    {
                                        svn: 243
                                    },
                                    {
                                        svn: 10
                                    },
                                    {
                                        svn: 82
                                    },
                                    {
                                        svn:      75,
                                        category: 'GDXEGMOEMR',
                                        type:     'TC145 MZV0'
                                    },
                                    {
                                        svn:      78,
                                        category: 'L9GDQAPJEN',
                                        type:     'I YVRGWSOR'
                                    },
                                    {
                                        svn:      187,
                                        category: 'AW 0H0XEFY',
                                        type:     'PNGZ1XU075'
                                    },
                                    {
                                        svn: 4
                                    },
                                    {
                                        svn: 159
                                    },
                                    {
                                        svn:      89,
                                        category: 'JLH22L7UTB',
                                        type:     'GX3A1IZC82'
                                    },
                                    {
                                        svn: 199
                                    },
                                ],
                                pcesvn: 3,
                            },
                            tcbDate:     '2019-09-01T00:00:00Z',
                            tcbStatus:   'ConfigurationNeeded',
                            advisoryIDs: ['INTEL-SA-38861', 'INTEL-SA-68515']
                        }
                    ]
                }
            };
        this.pcsClient.getSgxTcbInfo.resolves({ status: 200, body: tcbInfo, headers: { 'tcb-info-issuer-chain': '' } });
        this.pcsClient.getTdxTcbInfo.resolves({ status: 200, body: tcbInfo, headers: { 'tcb-info-issuer-chain': '' } });
        return this;
    }

    setupQeIdentity(advisoryIDs) {
        const qeIdentity = {
            enclaveIdentity: {
                tcbEvaluationDataNumber: 0,
                tcbLevels:               [
                    {
                        tcb: {
                            isvsvn: 4
                        },
                        advisoryIDs
                    },
                    {
                        tcb: {
                            isvsvn: 12677
                        },
                        advisoryIDs
                    }
                ]
            }
        };
        this.pcsClient.getSgxQeIdentity.resolves({ status: 200, body: qeIdentity });
        this.pcsClient.getTdxQeIdentity.resolves({ status: 200, body: qeIdentity });
        return this;
    }

    setupVerifyQuote(status = 0, errorSource = undefined) {
        this.qvl.verifyQuote.resolves({ status, errorSource });
        return this;
    }

    setupCertificateChain() {
        this.certificateChainParser.parseCertificateChainWithSpecificRoot.resolves({ rootCaPem: '', intermediateCaPem: '', pckCertPem: '' });
        this.certificateChainParser.parseTcbInfoSigningChainWithSpecificRoot.resolves({ rootCaPem: '', tcbSigningCertChain: '' });
        return this;
    }

    setupSignature() {
        this.vcsClient.signVerificationReport.resolves({ status: 200, body: { signature: '' } });
        return this;
    }

    defaultSetup() {
        return this.setupCertificationData()
            .setupPckCertificateData()
            .setupCrlDistributionPoint()
            .setupTcbInfo()
            .setupQeIdentity()
            .setupVerifyQuote()
            .setupCertificateChain()
            .setupSignature();
    }
}

describe('verify attestation evidence handler tests', () => {
    it('execute - SGX - UpToDate', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.sgxQuote
        };
        c.setupCertificationData()
            .setupPckCertificateData()
            .setupCrlDistributionPoint()
            .setupTcbInfo()
            .setupQeIdentity()
            .setupVerifyQuote()
            .setupCertificateChain()
            .setupSignature();
        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.equal(ctx.status, 200);
        assert.equal(c.qvl.getCertificationData.callCount, 1);
        assert.equal(c.qvl.getPckCertificateData.callCount, 1);
        assert.equal(c.qvl.getCrlDistributionPoint.callCount, 2);
        assert.equal(Object.keys(ctx.body).length, 9, 'Unexpected number of fields in response');
        assert.equal((/^\d+$/).test(ctx.body.id), true, 'ID field should be a 128 bit number');
        assert.equal(iso8601Regex.test(ctx.body.timestamp), true, 'Date format should be in ISO 8601');
        assert.equal(ctx.body.version, 5);
        assert.equal(ctx.body.attestationType, 'ECDSA');
        assert.equal(ctx.body.teeType, 'SGX_STANDARD');
        assert.equal(ctx.body.isvQuoteStatus, 'OK');
        assert.equal(ctx.body.isvQuoteBody, 'AwACAAAAAAAEAAkAk5pyM/ecTKmUCg2zlX8GB3cEhXlSheEulmeokact7P4AAAAADQ0DBf+AAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAA/NbIKlebNUxhlIX/ysdhdjxtT2O+JTpqaPcLeJTp9SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAyEBhE5TtWVUKTgl2yS/DCkZ8aq0eu1aesDBuOxNUj9wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
        assert.equal(ctx.body.tcbEvaluationDataNumber, 0);
        assert.equal(iso8601Regex.test(ctx.body.tcbDate), true, 'Date format should be in ISO 8601');
        assert.equal(ctx.body.advisoryIDs, undefined);
    });

    it('execute - SGX - ConfigurationNeeded', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.sgxQuote
        };
        c.setupCertificationData()
            .setupPckCertificateData({
                cpusvn: Buffer.from([3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            })
            .setupCrlDistributionPoint()
            .setupTcbInfo()
            .setupQeIdentity(['INTEL-SA-54321'])
            .setupVerifyQuote()
            .setupCertificateChain()
            .setupSignature();
        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.equal(ctx.status, 200);
        assert.equal(c.qvl.getCertificationData.callCount, 1);
        assert.equal(c.qvl.getPckCertificateData.callCount, 1);
        assert.equal(c.qvl.getCrlDistributionPoint.callCount, 2);
        assert.equal(Object.keys(ctx.body).length, 11, 'Unexpected number of fields in response');
        assert.equal((/^\d+$/).test(ctx.body.id), true, 'ID field should be a 128 bit number');
        assert.equal(iso8601Regex.test(ctx.body.timestamp), true, 'Date format should be in ISO 8601');
        assert.equal(ctx.body.version, 5);
        assert.equal(ctx.body.attestationType, 'ECDSA');
        assert.equal(ctx.body.teeType, 'SGX_STANDARD');
        assert.equal(ctx.body.isvQuoteStatus, 'OK');
        assert.equal(ctx.body.isvQuoteBody, 'AwACAAAAAAAEAAkAk5pyM/ecTKmUCg2zlX8GB3cEhXlSheEulmeokact7P4AAAAADQ0DBf+AAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAA/NbIKlebNUxhlIX/ysdhdjxtT2O+JTpqaPcLeJTp9SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAyEBhE5TtWVUKTgl2yS/DCkZ8aq0eu1aesDBuOxNUj9wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
        assert.equal(ctx.body.tcbEvaluationDataNumber, 0);
        assert.equal(ctx.body.advisoryURL, 'https://security-center.intel.com');
        assert.equal(JSON.stringify(ctx.body.advisoryIDs), JSON.stringify(['INTEL-SA-38861', 'INTEL-SA-54321', 'INTEL-SA-68515']));
    });

    it('execute - SGX - ConfigurationNeeded/TCB_OUT_OF_DATE', async() => {
        // GIVEN
        const nonce = '12345678901234567890123456789012';
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.sgxQuote,
            nonce
        };
        c.setupCertificationData()
            .setupPckCertificateData({
                cpusvn:          Buffer.from([3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                dynamicPlatform: true,
                cachedKeys:      true,
                smtEnabled:      true,
            })
            .setupCrlDistributionPoint()
            .setupTcbInfo()
            .setupQeIdentity()
            .setupVerifyQuote(qvlStatus.STATUS_TCB_OUT_OF_DATE)
            .setupCertificateChain()
            .setupSignature();
        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.equal(ctx.status, 200);
        assert.equal(c.qvl.getCertificationData.callCount, 1);
        assert.equal(c.qvl.getPckCertificateData.callCount, 1);
        assert.equal(c.qvl.getCrlDistributionPoint.callCount, 2);
        assert.equal((/^\d+$/).test(ctx.body.id), true, 'ID field should be a 128 bit number');
        assert.equal(iso8601Regex.test(ctx.body.timestamp), true, 'Date format should be in ISO 8601');
        assert.equal(ctx.body.version, 5);
        assert.equal(ctx.body.attestationType, 'ECDSA');
        assert.equal(ctx.body.teeType, 'SGX_STANDARD');
        assert.equal(ctx.body.isvQuoteStatus, 'TCB_OUT_OF_DATE');
        assert.equal(ctx.body.isvQuoteBody, 'AwACAAAAAAAEAAkAk5pyM/ecTKmUCg2zlX8GB3cEhXlSheEulmeokact7P4AAAAADQ0DBf+AAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAA/NbIKlebNUxhlIX/ysdhdjxtT2O+JTpqaPcLeJTp9SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAyEBhE5TtWVUKTgl2yS/DCkZ8aq0eu1aesDBuOxNUj9wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
        assert.equal(ctx.body.tcbEvaluationDataNumber, 0);
        assert.equal(ctx.body.advisoryURL, 'https://security-center.intel.com');
        assert.equal(JSON.stringify(ctx.body.advisoryIDs), JSON.stringify(['INTEL-SA-38861', 'INTEL-SA-68515']));
        assert.equal(JSON.stringify(ctx.body.tcbComponentsOutOfDate), JSON.stringify([{ category: 'cat1', type: 'type1' }]));
        assert.equal(ctx.body.nonce, nonce);
        assert.equal(JSON.stringify(ctx.body.configuration), JSON.stringify(['DYNAMIC_PLATFORM', 'CACHED_KEYS', 'SMT_ENABLED']));
        assert.equal(Object.keys(ctx.body).length, 14, 'Unexpected number of fields in response');
    });

    it('execute - TDX - UpToDate', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.tdxQuote
        };
        c.setupCertificationData()
            .setupPckCertificateData()
            .setupCrlDistributionPoint()
            .setupTcbInfo()
            .setupQeIdentity()
            .setupVerifyQuote()
            .setupCertificateChain()
            .setupSignature();
        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.equal(ctx.status, 200);
        assert.equal(c.qvl.getCertificationData.callCount, 1);
        assert.equal(c.qvl.getPckCertificateData.callCount, 1);
        assert.equal(c.qvl.getCrlDistributionPoint.callCount, 2);
        assert.equal(Object.keys(ctx.body).length, 9, 'Unexpected number of fields in response');
        assert.equal((/^\d+$/).test(ctx.body.id), true, 'ID field should be a 128 bit number');
        assert.equal(iso8601Regex.test(ctx.body.timestamp), true, 'Date format should be in ISO 8601');
        assert.equal(ctx.body.version, 5);
        assert.equal(ctx.body.attestationType, 'ECDSA');
        assert.equal(ctx.body.teeType, 'TDX');
        assert.equal(ctx.body.isvQuoteStatus, 'OK');
        assert.equal(ctx.body.isvQuoteBody, 'BAACAIEAAAAAAAAAk5pyM/ecTKmUCg2zlX8GB0PP8xCV14+q/cEZXptW+nYebWwaUsGjjPft8wpSS067BJ9ZxwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=');
        assert.equal(ctx.body.tcbEvaluationDataNumber, 0);
    });

    it('execute - TDX - ConfigurationNeeded', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.tdxQuote
        };
        c.setupCertificationData()
            .setupPckCertificateData({
                cpusvn: Buffer.from([3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            })
            .setupCrlDistributionPoint()
            .setupTcbInfo()
            .setupQeIdentity()
            .setupVerifyQuote()
            .setupCertificateChain()
            .setupSignature();
        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.equal(ctx.status, 200);
        assert.equal(c.qvl.getCertificationData.callCount, 1);
        assert.equal(c.qvl.getPckCertificateData.callCount, 1);
        assert.equal(c.qvl.getCrlDistributionPoint.callCount, 2);
        assert.equal(Object.keys(ctx.body).length, 11, 'Unexpected number of fields in response');
        assert.equal((/^\d+$/).test(ctx.body.id), true, 'ID field should be a 128 bit number');
        assert.equal(iso8601Regex.test(ctx.body.timestamp), true, 'Date format should be in ISO 8601');
        assert.equal(ctx.body.version, 5);
        assert.equal(ctx.body.attestationType, 'ECDSA');
        assert.equal(ctx.body.teeType, 'TDX');
        assert.equal(ctx.body.isvQuoteStatus, 'OK');
        assert.equal(ctx.body.isvQuoteBody, 'BAACAIEAAAAAAAAAk5pyM/ecTKmUCg2zlX8GB0PP8xCV14+q/cEZXptW+nYebWwaUsGjjPft8wpSS067BJ9ZxwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=');
        assert.equal(ctx.body.tcbEvaluationDataNumber, 0);
        assert.equal(ctx.body.advisoryURL, 'https://security-center.intel.com');
        assert.equal(JSON.stringify(ctx.body.advisoryIDs), JSON.stringify(['INTEL-SA-38861', 'INTEL-SA-68515']));
    });

    it('execute - TDX - ConfigurationNeeded/TCB_OUT_OF_DATE', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        const nonce = '12345678901234567890123456789012';
        ctx.request.body = {
            isvQuote: c.tdxQuote,
            nonce
        };
        c.setupCertificationData()
            .setupPckCertificateData({
                cpusvn:          Buffer.from([3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                dynamicPlatform: true,
                cachedKeys:      true,
                smtEnabled:      true,
            })
            .setupCrlDistributionPoint()
            .setupTcbInfo()
            .setupQeIdentity()
            .setupVerifyQuote(qvlStatus.STATUS_TCB_OUT_OF_DATE)
            .setupCertificateChain()
            .setupSignature();
        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.equal(ctx.status, 200);
        assert.equal(c.qvl.getCertificationData.callCount, 1);
        assert.equal(c.qvl.getPckCertificateData.callCount, 1);
        assert.equal(c.qvl.getCrlDistributionPoint.callCount, 2);
        assert.equal((/^\d+$/).test(ctx.body.id), true, 'ID field should be a 128 bit number');
        assert.equal(iso8601Regex.test(ctx.body.timestamp), true, 'Date format should be in ISO 8601');
        assert.equal(ctx.body.version, 5);
        assert.equal(ctx.body.attestationType, 'ECDSA');
        assert.equal(ctx.body.teeType, 'TDX');
        assert.equal(ctx.body.isvQuoteStatus, 'TCB_OUT_OF_DATE');
        assert.equal(ctx.body.isvQuoteBody, 'BAACAIEAAAAAAAAAk5pyM/ecTKmUCg2zlX8GB0PP8xCV14+q/cEZXptW+nYebWwaUsGjjPft8wpSS067BJ9ZxwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=');
        assert.equal(ctx.body.tcbEvaluationDataNumber, 0);
        assert.equal(ctx.body.advisoryURL, 'https://security-center.intel.com');
        assert.equal(JSON.stringify(ctx.body.advisoryIDs), JSON.stringify(['INTEL-SA-38861', 'INTEL-SA-68515']));
        assert.equal(JSON.stringify(ctx.body.tcbComponentsOutOfDate), JSON.stringify([{ category: 'cat1', type: 'type1' }, { category: 'KRYYIXKC8U', type: '@TU9B14XQO' }]));
        assert.equal(JSON.stringify(ctx.body.configuration), JSON.stringify(['DYNAMIC_PLATFORM', 'CACHED_KEYS', 'SMT_ENABLED']));
        assert.equal(ctx.body.nonce, nonce);
        assert.equal(Object.keys(ctx.body).length, 14, 'Unexpected number of fields in response');
    });

    it('execute - SGX - TCB level mismatch', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.tdxQuote
        };
        c.setupCertificationData()
            .setupPckCertificateData({
                cpusvn: Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            })
            .setupCrlDistributionPoint()
            .setupTcbInfo()
            .setupQeIdentity()
            .setupVerifyQuote()
            .setupCertificateChain()
            .setupSignature();
        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.equal(ctx.status, 400);
        assert.equal(c.qvl.getCertificationData.callCount, 1);
        assert.equal(c.qvl.getPckCertificateData.callCount, 1);
        assert.equal(c.qvl.getCrlDistributionPoint.callCount, 2);
        assert.equal(ctx.body, undefined, 'Unexpected body response');
    });

    it('execute - SGX - Enclave TCB level mismatch', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.tdxQuote
        };
        c.setupCertificationData()
            .setupPckCertificateData()
            .setupCrlDistributionPoint()
            .setupTcbInfo()
            .setupVerifyQuote()
            .setupCertificateChain()
            .setupSignature();
        const qeIdentity = {
            enclaveIdentity: {
                tcbEvaluationDataNumber: 0,
                tcbLevels:               [
                    {
                        tcb: {
                            isvsvn: 555
                        }
                    }
                ]
            }
        };
        c.pcsClient.getSgxQeIdentity.resolves({ status: 200, body: qeIdentity });
        c.pcsClient.getTdxQeIdentity.resolves({ status: 200, body: qeIdentity });
        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.equal(ctx.status, 400);
        assert.equal(c.qvl.getCertificationData.callCount, 1);
        assert.equal(c.qvl.getPckCertificateData.callCount, 1);
        assert.equal(c.qvl.getCrlDistributionPoint.callCount, 2);
        assert.equal(ctx.body, undefined, 'Unexpected body response');
    });

    it('execute - TDX - TCB level mismatch', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.tdxQuote
        };
        c.setupCertificationData()
            .setupPckCertificateData()
            .setupCrlDistributionPoint()
            .setupTcbInfo({
                tcbInfo: {
                    issueDate: '2021-08-06T13:55:15Z',
                    tcbLevels: [
                        {
                            tcb: {
                                sgxtcbcomponents: [
                                    {
                                        svn: 3
                                    },
                                    {
                                        svn: 2
                                    },
                                    {
                                        svn: 1
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    },
                                    {
                                        svn: 0
                                    }
                                ],
                                tdxtcbcomponents: [
                                    {
                                        svn:      83,
                                        category: 'KRYYIXKC8U',
                                        type:     '@TU9B14XQO'
                                    },
                                    {
                                        svn:      193,
                                        category: '504X036OI0',
                                        type:     'EQJ363GEJV'
                                    },
                                    {
                                        svn:      163,
                                        category: 'JZT5BUBBET',
                                        type:     '@6ZH630STD'
                                    },
                                    {
                                        svn:      140,
                                        category: 'XMJJ814468',
                                        type:     '1G0N1J G9D'
                                    },
                                    {
                                        svn:      247,
                                        category: 'HGVSWL@TCR',
                                        type:     '9WZUC8QV@G'
                                    },
                                    {
                                        svn: 237
                                    },
                                    {
                                        svn: 243
                                    },
                                    {
                                        svn: 10
                                    },
                                    {
                                        svn: 82
                                    },
                                    {
                                        svn:      75,
                                        category: 'GDXEGMOEMR',
                                        type:     'TC145 MZV0'
                                    },
                                    {
                                        svn:      78,
                                        category: 'L9GDQAPJEN',
                                        type:     'I YVRGWSOR'
                                    },
                                    {
                                        svn:      187,
                                        category: 'AW 0H0XEFY',
                                        type:     'PNGZ1XU075'
                                    },
                                    {
                                        svn: 4
                                    },
                                    {
                                        svn: 159
                                    },
                                    {
                                        svn:      89,
                                        category: 'JLH22L7UTB',
                                        type:     'GX3A1IZC82'
                                    },
                                    {
                                        svn: 199
                                    },
                                ],
                                pcesvn: 3,
                            },
                            tcbDate:   '2019-09-01T00:00:00Z',
                            tcbStatus: 'UpToDate'
                        }
                    ]
                }
            })
            .setupQeIdentity()
            .setupVerifyQuote()
            .setupCertificateChain()
            .setupSignature();
        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.equal(ctx.status, 400);
        assert.equal(c.qvl.getCertificationData.callCount, 1);
        assert.equal(c.qvl.getPckCertificateData.callCount, 1);
        assert.equal(c.qvl.getCrlDistributionPoint.callCount, 2);
        assert.equal(ctx.body, undefined, 'Unexpected body response');
    });

    it('execute - TDX - unexpected empty advisoryIDs', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.tdxQuote
        };
        c.setupCertificationData()
            .setupPckCertificateData({
                cpusvn: Buffer.from([3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            })
            .setupCrlDistributionPoint()
            .setupTcbInfo({
                tcbInfo: {
                    issueDate: '2021-08-06T13:55:15Z',
                    tcbLevels:
                        [
                            {
                                tcb: {
                                    sgxtcbcomponents: [
                                        {
                                            svn: 3
                                        },
                                        {
                                            svn: 2
                                        },
                                        {
                                            svn: 1
                                        },
                                        {
                                            svn: 0
                                        },
                                        {
                                            svn: 0
                                        },
                                        {
                                            svn: 0
                                        },
                                        {
                                            svn: 0
                                        },
                                        {
                                            svn: 0
                                        },
                                        {
                                            svn: 0
                                        },
                                        {
                                            svn: 0
                                        },
                                        {
                                            svn: 0
                                        },
                                        {
                                            svn: 0
                                        },
                                        {
                                            svn: 0
                                        },
                                        {
                                            svn: 0
                                        },
                                        {
                                            svn: 0
                                        },
                                        {
                                            svn: 0
                                        }
                                    ],
                                    tdxtcbcomponents: [
                                        {
                                            svn: 82
                                        },
                                        {
                                            svn: 193
                                        },
                                        {
                                            svn: 163
                                        },
                                        {
                                            svn: 140
                                        },
                                        {
                                            svn: 247
                                        },
                                        {
                                            svn: 237
                                        },
                                        {
                                            svn: 243
                                        },
                                        {
                                            svn: 10
                                        },
                                        {
                                            svn: 82
                                        },
                                        {
                                            svn: 75
                                        },
                                        {
                                            svn: 78
                                        },
                                        {
                                            svn: 187
                                        },
                                        {
                                            svn: 4
                                        },
                                        {
                                            svn: 159
                                        },
                                        {
                                            svn: 89
                                        },
                                        {
                                            svn: 199
                                        },
                                    ],
                                    pcesvn: 3,
                                },
                                tcbDate:   '2019-09-01T00:00:00Z',
                                tcbStatus: 'UpToDate'
                            },
                            {
                                tcb: {
                                    sgxtcbcomponents: [
                                        {
                                            svn: 3
                                        },
                                        {
                                            svn: 2
                                        },
                                        {
                                            svn: 0
                                        },
                                        {
                                            svn: 0
                                        },
                                        {
                                            svn: 0
                                        },
                                        {
                                            svn: 0
                                        },
                                        {
                                            svn: 0
                                        },
                                        {
                                            svn: 0
                                        },
                                        {
                                            svn: 0
                                        },
                                        {
                                            svn: 0
                                        },
                                        {
                                            svn: 0
                                        },
                                        {
                                            svn: 0
                                        },
                                        {
                                            svn: 0
                                        },
                                        {
                                            svn: 0
                                        },
                                        {
                                            svn: 0
                                        },
                                        {
                                            svn: 0
                                        }
                                    ],
                                    tdxtcbcomponents: [
                                        {
                                            svn: 82
                                        },
                                        {
                                            svn: 193
                                        },
                                        {
                                            svn: 163
                                        },
                                        {
                                            svn: 140,
                                        },
                                        {
                                            svn: 247
                                        },
                                        {
                                            svn: 237
                                        },
                                        {
                                            svn: 243
                                        },
                                        {
                                            svn: 10
                                        },
                                        {
                                            svn: 82
                                        },
                                        {
                                            svn: 75
                                        },
                                        {
                                            svn: 78
                                        },
                                        {
                                            svn: 187
                                        },
                                        {
                                            svn: 4
                                        },
                                        {
                                            svn: 159
                                        },
                                        {
                                            svn: 89
                                        },
                                        {
                                            svn: 199
                                        },
                                    ],
                                    pcesvn: 3,
                                },
                                tcbDate:     '2019-09-01T00:00:00Z',
                                tcbStatus:   'ConfigurationNeeded',
                                advisoryIDs: [] // should be filled in real scenario
                            }
                        ]
                }
            })
            .setupQeIdentity()
            .setupVerifyQuote()
            .setupCertificateChain()
            .setupSignature();
        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.equal(ctx.status, 200);
        assert.equal(ctx.body.advisoryIDs, undefined);
    });

    it('execute - Invalid nonce', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.tdxQuote,
            nonce:    '123456789012345678901234567890123' // too long nonce
        };
        c.setupCertificationData()
            .setupPckCertificateData()
            .setupCrlDistributionPoint()
            .setupTcbInfo()
            .setupQeIdentity()
            .setupVerifyQuote()
            .setupCertificateChain()
            .setupSignature();
        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.equal(ctx.status, 400);
        assert.equal(c.qvl.getCertificationData.callCount, 0);
        assert.equal(c.qvl.getPckCertificateData.callCount, 0);
        assert.equal(c.qvl.getCrlDistributionPoint.callCount, 0);
        assert.equal(ctx.body, undefined, 'Unexpected body response');
    });

    it('execute - quote parsing failure', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.tdxQuote
        };
        c.setupCertificationData()
            .setupPckCertificateData()
            .setupCrlDistributionPoint()
            .setupTcbInfo()
            .setupQeIdentity()
            .setupVerifyQuote()
            .setupCertificateChain()
            .setupSignature();
        // WHEN
        c.qvl.getCertificationData.throws('Problem');
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.equal(ctx.status, 400);
        assert.equal(c.qvl.getCertificationData.callCount, 1);
        assert.equal(c.qvl.getPckCertificateData.callCount, 0);
        assert.equal(c.qvl.getCrlDistributionPoint.callCount, 0);
        assert.equal(ctx.body, undefined, 'Unexpected body response');
    });

    const anyErrorSource = -1;
    const allErrorSources = [...Array(Object.keys(errorSource).length).keys()];
    const qvlPositiveStatuses = [
        { qvlStatus: qvlStatus.STATUS_OK, isvQuoteStatus: 'OK' },
        { qvlStatus: qvlStatus.STATUS_INVALID_QUOTE_SIGNATURE, isvQuoteStatus: 'SIGNATURE_INVALID' },
        { qvlStatus: qvlStatus.STATUS_SGX_PCK_REVOKED, isvQuoteStatus: 'REVOKED' },
        { qvlStatus: qvlStatus.STATUS_PCK_REVOKED, isvQuoteStatus: 'REVOKED' },
        { qvlStatus: qvlStatus.STATUS_TCB_REVOKED, isvQuoteStatus: 'REVOKED' },
        { qvlStatus: qvlStatus.STATUS_SGX_INTERMEDIATE_CA_REVOKED, isvQuoteStatus: 'REVOKED' },
        { qvlStatus: qvlStatus.STATUS_TCB_OUT_OF_DATE, isvQuoteStatus: 'TCB_OUT_OF_DATE' },
        { qvlStatus: qvlStatus.STATUS_TCB_CONFIGURATION_NEEDED, isvQuoteStatus: 'CONFIGURATION_NEEDED' },
        { qvlStatus: qvlStatus.STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED, isvQuoteStatus: 'TCB_OUT_OF_DATE_AND_CONFIGURATION_NEEDED' },
        { qvlStatus: qvlStatus.STATUS_TCB_SW_HARDENING_NEEDED, isvQuoteStatus: 'SW_HARDENING_NEEDED' },
        { qvlStatus: qvlStatus.STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED, isvQuoteStatus: 'CONFIGURATION_AND_SW_HARDENING_NEEDED' }
    ];
    const qvlExpectedNegativeStatuses = [
        { qvlStatus: qvlStatus.STATUS_UNSUPPORTED_CERT_FORMAT, errorSource: errorSource.VERIFY_PCK_CERTIFICATE },
        { qvlStatus: qvlStatus.STATUS_SGX_ROOT_CA_MISSING, errorSource: errorSource.VERIFY_PCK_CERTIFICATE },
        { qvlStatus: qvlStatus.STATUS_SGX_ROOT_CA_INVALID_EXTENSIONS, errorSource: errorSource.VERIFY_PCK_CERTIFICATE },
        { qvlStatus: qvlStatus.STATUS_SGX_ROOT_CA_INVALID_ISSUER, errorSource: errorSource.VERIFY_PCK_CERTIFICATE },
        { qvlStatus: qvlStatus.STATUS_SGX_INTERMEDIATE_CA_MISSING, errorSource: anyErrorSource },
        { qvlStatus: qvlStatus.STATUS_SGX_INTERMEDIATE_CA_INVALID_EXTENSIONS, errorSource: anyErrorSource },
        { qvlStatus: qvlStatus.STATUS_SGX_INTERMEDIATE_CA_INVALID_ISSUER, errorSource: anyErrorSource },
        { qvlStatus: qvlStatus.STATUS_SGX_PCK_MISSING, errorSource: anyErrorSource },
        { qvlStatus: qvlStatus.STATUS_SGX_PCK_INVALID_EXTENSIONS, errorSource: anyErrorSource },
        { qvlStatus: qvlStatus.STATUS_SGX_PCK_INVALID_ISSUER, errorSource: anyErrorSource },
        { qvlStatus: qvlStatus.STATUS_SGX_PCK_CERT_CHAIN_UNTRUSTED, errorSource: anyErrorSource },
        { qvlStatus: qvlStatus.STATUS_UNSUPPORTED_QUOTE_FORMAT, errorSource: anyErrorSource },
        { qvlStatus: qvlStatus.STATUS_UNSUPPORTED_PCK_CERT_FORMAT, errorSource: anyErrorSource },
        { qvlStatus: qvlStatus.STATUS_INVALID_PCK_CERT, errorSource: anyErrorSource },
        { qvlStatus: qvlStatus.STATUS_TCB_NOT_SUPPORTED, errorSource: anyErrorSource },
        { qvlStatus: qvlStatus.STATUS_INVALID_QE_REPORT_SIGNATURE, errorSource: anyErrorSource },
        { qvlStatus: qvlStatus.STATUS_INVALID_QE_REPORT_DATA, errorSource: anyErrorSource },
        { qvlStatus: qvlStatus.STATUS_QE_IDENTITY_MISMATCH, errorSource: anyErrorSource },
        { qvlStatus: qvlStatus.STATUS_SGX_PCK_CERT_CHAIN_EXPIRED, errorSource: anyErrorSource },
        { qvlStatus: qvlStatus.STATUS_TDX_MODULE_MISMATCH, errorSource: anyErrorSource }
    ];
    const qvlUnexpectedStatuses = [...Array(Object.keys(qvlStatus).length).keys()]
        .filter(i => !qvlPositiveStatuses.map(s => s.qvlStatus).includes(i))
        .concat([-1, Object.keys(qvlStatus).length]) // values outside of range
        .map(i => {
            const obj = qvlExpectedNegativeStatuses.find(x => x.qvlStatus === i);
            if (obj?.errorSource === anyErrorSource) {
                return null;
            }
            return { qvlStatus: i, errorSources: allErrorSources.filter(x => x !== obj?.errorSource) };
        })
        .filter(x => x !== null);

    async function testQvlStatus(qvlStatus, errorSource, expectedHttpStatus, errors, isvQuoteStatus) {

        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.sgxQuote
        };
        c.setupCertificationData()
            .setupPckCertificateData()
            .setupCrlDistributionPoint()
            .setupTcbInfo()
            .setupQeIdentity()
            .setupVerifyQuote(qvlStatus, errorSource)
            .setupCertificateChain()
            .setupSignature();

        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.equal(ctx.status, expectedHttpStatus, `Http statuses don't match for QVL status ${qvlStatus}`);
        assert.equal(ctx.body?.isvQuoteStatus, isvQuoteStatus, `isvQuoteStatus don't match for QVL status ${qvlStatus}`);
        assert.equal(c.logger.error.callCount, errors, `Unexpected number of errors for QVL status ${qvlStatus}`);
    }
    /* eslint-disable no-await-in-loop */
    async function testUnexpectedQvlStatuses(source) {
        for (const { qvlStatus } of qvlUnexpectedStatuses.filter(x => x.errorSources.includes(source))) {
            await testQvlStatus(qvlStatus, source, 500, 1);
        }
    }

    it('execute - qvl returns positive status results in status 200', async() => {
        for (const { qvlStatus, isvQuoteStatus } of qvlPositiveStatuses) {
            await testQvlStatus(qvlStatus, undefined, 200, 0, isvQuoteStatus);
        }
    });

    it('execute - qvl returns expected negative status results in status 400', async() => {
        for (const qvlExpectedNegativeStatus of qvlExpectedNegativeStatuses) {
            await testQvlStatus(qvlExpectedNegativeStatus.qvlStatus, qvlExpectedNegativeStatus.errorSource, 400, 1);
        }
    });
    /* eslint-enable no-await-in-loop */

    it('execute - qvl returns unexpected status during pck cert verification results in status 500', async() => {
        await testUnexpectedQvlStatuses(errorSource.VERIFY_PCK_CERTIFICATE);
    });
    it('execute - qvl returns unexpected status during tcb info verification results in status 500', async() => {
        await testUnexpectedQvlStatuses(errorSource.VERIFY_TCB_INFO);
    });
    it('execute - qvl returns unexpected status during QE identity verification results in status 500', async() => {
        await testUnexpectedQvlStatuses(errorSource.VERIFY_ENCLAVE_IDENTITY);
    });
    it('execute - qvl returns unexpected status during quote verification results in status 500', async() => {
        await testUnexpectedQvlStatuses(errorSource.VERIFY_QUOTE);
    });

    it('execute - qvl returns no errorSource despite throwing error', async() => {
        const expectedStatusForAnySource = qvlExpectedNegativeStatuses.find(x => x.errorSource === anyErrorSource).qvlStatus;
        await testQvlStatus(expectedStatusForAnySource, undefined, 500, 1);
    });

    describe('nonce', () => {
        it('too long', async() => {
            // GIVEN
            const c = new TestContext();
            const target = await c.getTarget();
            const ctx = await c.getCtx();
            ctx.request.body = {
                isvQuote: c.sgxQuote,
                nonce:    '123456789012345678901234567890123'  // 33 characters
            };
            // WHEN
            await target.verifyAttestationEvidence(ctx);
            // THEN
            assert.strictEqual(ctx.status, 400);
            assert.strictEqual(ctx.hasOwnProperty('body'), false);
            assertMockCalledOnceWithArgs(ctx.log.error, 'Provided nonce is longer than 32 characters: ', ctx.request.body.nonce);
        });

        it('not provided', async() => {
            // GIVEN
            const c = new TestContext();
            const target = await c.getTarget();
            const ctx = await c.getCtx();
            ctx.request.body = {
                isvQuote: c.sgxQuote
            };
            c.defaultSetup();
            // WHEN
            await target.verifyAttestationEvidence(ctx);
            // THEN
            assert.strictEqual(ctx.status, 200);
            assert.strictEqual(ctx.body.hasOwnProperty('nonce'), false);
            assert.strictEqual(ctx.log.error.callCount, 0);
        });
    });

    describe('configuration', () => {

        it('no flags - no configuration field', async() => {
            // GIVEN
            const c = new TestContext();
            const target = await c.getTarget();
            const ctx = await c.getCtx();
            ctx.request.body = {
                isvQuote: c.sgxQuote,
                nonce:    c.nonce
            };
            c.defaultSetup();
            // WHEN
            await target.verifyAttestationEvidence(ctx);
            // THEN
            assert.strictEqual(ctx.status, 200);
            assert.strictEqual(ctx.body.hasOwnProperty('configuration'), false);
        });

        it('dynamic platform', async() => {
            // GIVEN
            const c = new TestContext();
            const target = await c.getTarget();
            const ctx = await c.getCtx();
            ctx.request.body = {
                isvQuote: c.sgxQuote,
                nonce:    c.nonce
            };
            c.defaultSetup();
            c.setupPckCertificateData({ dynamicPlatform: true });
            // WHEN
            await target.verifyAttestationEvidence(ctx);
            // THEN
            assert.strictEqual(ctx.status, 200);
            assert.deepEqual(ctx.body.configuration, ['DYNAMIC_PLATFORM']);
        });

        it('cached keys', async() => {
            // GIVEN
            const c = new TestContext();
            const target = await c.getTarget();
            const ctx = await c.getCtx();
            ctx.request.body = {
                isvQuote: c.sgxQuote,
                nonce:    c.nonce
            };
            c.defaultSetup();
            c.setupPckCertificateData({ cachedKeys: true });
            // WHEN
            await target.verifyAttestationEvidence(ctx);
            // THEN
            assert.strictEqual(ctx.status, 200);
            assert.deepEqual(ctx.body.configuration, ['CACHED_KEYS']);
        });

        it('SMT enabled', async() => {
            // GIVEN
            const c = new TestContext();
            const target = await c.getTarget();
            const ctx = await c.getCtx();
            ctx.request.body = {
                isvQuote: c.sgxQuote,
                nonce:    c.nonce
            };
            c.defaultSetup();
            c.setupPckCertificateData({ smtEnabled: true });
            // WHEN
            await target.verifyAttestationEvidence(ctx);
            // THEN
            assert.strictEqual(ctx.status, 200);
            assert.deepEqual(ctx.body.configuration, ['SMT_ENABLED']);
        });

        it('multiple flags', async() => {
            // GIVEN
            const c = new TestContext();
            const target = await c.getTarget();
            const ctx = await c.getCtx();
            ctx.request.body = {
                isvQuote: c.sgxQuote,
                nonce:    c.nonce
            };
            c.defaultSetup();
            c.setupPckCertificateData({
                dynamicPlatform: true,
                cachedKeys:      true,
                smtEnabled:      true
            });
            // WHEN
            await target.verifyAttestationEvidence(ctx);
            // THEN
            assert.strictEqual(ctx.status, 200);
            assert.deepEqual(ctx.body.configuration, ['DYNAMIC_PLATFORM', 'CACHED_KEYS', 'SMT_ENABLED']);
        });

    });

    describe('wrong certification data', () => {

        it('error retrieving data from quote', async() => {
            // GIVEN
            const c = new TestContext();
            const target = await c.getTarget();
            const ctx = await c.getCtx();
            ctx.request.body = {
                isvQuote: c.sgxQuote,
                nonce:    c.nonce
            };
            c.defaultSetup();
            c.qvl.getCertificationData.rejects(new Error());
            // WHEN
            await target.verifyAttestationEvidence(ctx);
            // THEN
            assert.strictEqual(ctx.status, 400);
            assert.strictEqual(ctx.log.error.args[0][0].message, 'Failed to retrieve certification data from quote');
        });

        it('not supported certification data type', async() => {
            // GIVEN
            const c = new TestContext();
            const target = await c.getTarget();
            const ctx = await c.getCtx();
            ctx.request.body = {
                isvQuote: c.sgxQuote,
                nonce:    c.nonce
            };
            c.defaultSetup();
            c.qvl.getCertificationData.resolves({
                type: 1,
                data: c.certificationData
            });
            // WHEN
            await target.verifyAttestationEvidence(ctx);
            // THEN
            assert.strictEqual(ctx.status, 400);
            assert.strictEqual(String(ctx.log.error.args[0][0]), 'Error: Not supported certification data type: 1');
        });

    });

    it('PCK certificate without required extensions', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.sgxQuote,
            nonce:    c.nonce
        };
        c.defaultSetup();
        c.qvl.getPckCertificateData.rejects(new Error());
        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.strictEqual(ctx.status, 400);
        assert.strictEqual(ctx.log.error.args[0][0].message, 'PCK Cert does not contain required extensions');
    });

    it('Sgx TcbInfo retrieval failure', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.sgxQuote,
            nonce:    c.nonce
        };
        c.defaultSetup();
        c.pcsClient.getSgxTcbInfo.resolves({ status: 404 });
        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.strictEqual(ctx.status, 400);
        assert.strictEqual(ctx.log.error.args[0][0].message, 'Failed to retrieve required TcbInfo. PCS returned status: 404');
    });

    it('TcbInfo retrieval failure, FMSP/TCB not found', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.sgxQuote,
            nonce:    c.nonce
        };
        c.defaultSetup();
        c.pcsClient.getSgxTcbInfo.resolves({ status: 400 });
        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.strictEqual(ctx.status, 500);
        assert.strictEqual(ctx.log.error.args[0][0].message, 'Failed to retrieve required TcbInfo. PCS returned status: 400');
    });

    it('Tdx TcbInfo retrieval failure', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.tdxQuote,
            nonce:    c.nonce
        };
        c.defaultSetup();
        c.pcsClient.getTdxTcbInfo.resolves({ status: 404 });
        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.strictEqual(ctx.status, 400);
        assert.strictEqual(ctx.log.error.args[0][0].message, 'Failed to retrieve required TcbInfo. PCS returned status: 404');
    });

    it('Sgx QeIdentity retrieval failure', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.sgxQuote,
            nonce:    c.nonce
        };
        c.defaultSetup();
        c.pcsClient.getSgxQeIdentity.resolves({ status: 404 });
        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.strictEqual(ctx.status, 500);
        assert.strictEqual(ctx.log.error.args[0][0].message, 'Failed to retrieve required QeIdentity. PCS returned status: 404');
    });

    it('Tdx QeIdentity retrieval failure', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.tdxQuote,
            nonce:    c.nonce
        };
        c.defaultSetup();
        c.pcsClient.getTdxQeIdentity.resolves({ status: 404 });
        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.strictEqual(ctx.status, 500);
        assert.strictEqual(ctx.log.error.args[0][0].message, 'Failed to retrieve required QeIdentity. PCS returned status: 404');
    });

    it('execute - get certification data fails', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.sgxQuote
        };
        c.defaultSetup();
        c.qvl.getCertificationData.rejects({
            error:  'sgxAttestationGetQECertificationDataSize failed',
            status: 37
        });
        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.equal(ctx.status, 400);
        assert.equal(c.qvl.getCertificationData.callCount, 1);
    });

    it('execute - CRL distribution point is in wrong format', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.sgxQuote
        };
        c.defaultSetup();
        c.qvl.getCrlDistributionPoint.resolves('https://certificates.trustedservices.intel.com/IntelSGXRootCA.crl');

        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.strictEqual(ctx.status, 400);
        assert.strictEqual(c.qvl.getCertificationData.callCount, 1);
        assert.strictEqual(c.qvl.getPckCertificateData.callCount, 1);
        assert.strictEqual(c.qvl.getCrlDistributionPoint.callCount, 2);
    });

    it('execute - get CRL distribution point fails', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.sgxQuote
        };
        c.defaultSetup();
        c.qvl.getCrlDistributionPoint.rejects({
            error: 'Error getting CRL distribution point'
        });

        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.strictEqual(ctx.status, 400);
        assert.strictEqual(c.qvl.getCertificationData.callCount, 1);
        assert.strictEqual(c.qvl.getPckCertificateData.callCount, 1);
        assert.strictEqual(c.qvl.getCrlDistributionPoint.callCount, 2);
    });

    it('execute - get CRL from distribution point fails', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.sgxQuote
        };
        c.defaultSetup();
        c.crlClient.getCrlFromDistributionPoint.resolves({ status: 404 });

        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.strictEqual(ctx.status, 500);
        assert.strictEqual(ctx.log.error.args[0][0].message, 'Failed to retrieve one of CRLs. Distribution Point returned status: 404');
    });

    it('execute - get CRL in DER format from distribution point', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        const hexString = 'AABBCCDDEEFF0123456789';
        ctx.request.body = {
            isvQuote: c.sgxQuote
        };
        c.defaultSetup();
        c.crlClient.getCrlFromDistributionPoint.resolves({ status: 200, body: Buffer.from(hexString, 'hex') });

        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.strictEqual(ctx.status, 200);
        assert.strictEqual(c.qvl.verifyQuote.callCount, 1);
        assert.strictEqual(c.qvl.verifyQuote.args[0][7], hexString.toLowerCase());
        assert.strictEqual(c.qvl.verifyQuote.args[0][8], hexString.toLowerCase());
    });

    it('execute - tcb levels out of order', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();

        ctx.request.body = {
            isvQuote: c.sgxQuote
        };
        c.defaultSetup()
            .setupVerifyQuote(qvlStatus.STATUS_TCB_OUT_OF_DATE);

        const tcbInfo = (await c.pcsClient.getSgxTcbInfo()).body.tcbInfo;
        tcbInfo.tcbLevels = tcbInfo.tcbLevels.reverse();
        c.setupTcbInfo({ tcbInfo });
        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.strictEqual(ctx.status, 200);
    });

    it('scalable sgx type', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.sgxQuote
        };
        c.defaultSetup();
        c.setupPckCertificateData({
            sgxType: 'Scalable'
        });
        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.strictEqual(ctx.status, 200);
        assert.strictEqual(ctx.body.teeType, 'SGX_SCALABLE');
    });

    it('scalable with integrity sgx type', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.sgxQuote
        };
        c.defaultSetup();
        c.setupPckCertificateData({
            sgxType: 'ScalableWithIntegrity'
        });
        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.strictEqual(ctx.status, 200);
        assert.strictEqual(ctx.body.teeType, 'SGX_SCALABLE_WITH_INTEGRITY');
    });

    it('not supported sgx type', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.sgxQuote
        };
        c.defaultSetup();
        c.setupPckCertificateData({
            sgxType: 'NotSupported'
        });
        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.strictEqual(ctx.status, 500);
        assert.strictEqual(ctx.log.error.args[0][0].message, 'Unsupported sgxType');
    });

    it('sign verification report failure', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: c.tdxQuote,
            nonce:    c.nonce
        };
        c.defaultSetup();
        c.vcsClient.signVerificationReport.resolves({ status: 404 });
        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.strictEqual(ctx.status, 500);
        assert.strictEqual(ctx.log.error.args[0][0].message, 'Failed to sign the report. VCS returned status: 404');
    });

    it('no isvQuote', async() => {
        // GIVEN
        const c = new TestContext();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {};
        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.strictEqual(ctx.status, 400);
    });

    it('quote not base64', async() => {
        // GIVEN
        const c = new TestContext().defaultSetup();
        const target = await c.getTarget();
        const ctx = await c.getCtx();
        ctx.request.body = {
            isvQuote: '!@#$%^&*()' //special characters that aren't base64
        };

        // WHEN
        await target.verifyAttestationEvidence(ctx);
        // THEN
        assert.strictEqual(ctx.status, 400);
        assert.strictEqual(ctx.log.error.callCount, 1);
        assert.strictEqual(c.qvl.getCertificationData.callCount, 0);
    });
});
