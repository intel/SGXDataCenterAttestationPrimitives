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
 const assert = require('assert');
 const { X509Certificate } = require('crypto');

 class TestContext {
  constructor() {
    this.rootCaPublicKey = '3059301306072a8648ce3d020106082a8648ce3d030107034200040ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f567918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394';
    this.rootCaPem = `-----BEGIN CERTIFICATE-----
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
    this.intermediateCaPem = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`;
    this.pckPem = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`;
    this.anotherCert = `-----BEGIN CERTIFICATE-----
MIIDnDCCAoSgAwIBAgIJAMmlcQsaw/9fMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExFDASBgNV
BAoMC1NHWCBOb25wcm9kMRswGQYDVQQDDBJzZ3gtbm9ucHJvZC1zZXJ2ZXIwHhcN
MjAwNDAzMTEzMDU3WhcNMzAwNDAxMTEzMDU3WjBjMQswCQYDVQQGEwJVUzELMAkG
A1UECAwCQ0ExFDASBgNVBAcMC1NhbnRhIENsYXJhMRQwEgYDVQQKDAtTR1ggTm9u
cHJvZDEbMBkGA1UEAwwSc2d4LW5vbnByb2Qtc2VydmVyMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAs6CFe+MyEcy9ALgVvyACCWXs3xyKSlC7qzIjtFJF
eXuWogI2cpqmv+E6Yq9cyzV3wWyZqyfAsWNrs4z1SRlPpNEC65P+LqofIYFQVFV9
/b4ok/uBCxL5fN7iYSZzTTyJ5d6NDdKYKtcu6ZtTID9lgXapXu9wNi2lgWqci2Sb
EvYGpc225TKA64DYZNjoPKEyyJz21Re2ZZqYUcPTGB/oDGjw+J3GRXhtcptSrLmw
RFjwFflAq7q00fR+DOKYzmwQtQUeIuEWaaOjrwAzvW8rKdvJqwb44Tc41IcJGSlu
HrKsB/39/xGdNa7rda54YAQ97cYm6s8TfW2jgL39/9rbIwIDAQABo1MwUTAdBgNV
HQ4EFgQUCK7s7Jis2JlAuOmOKMZOEV1PKNMwHwYDVR0jBBgwFoAUCK7s7Jis2JlA
uOmOKMZOEV1PKNMwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEA
UhzsZ65wmPO3ChQURU8lSFxRH+dte7ILWLrnsbiKXhctLa51K7mJW3alEFj9exvh
/vRuXelp9beNkTPUuXUuVu8rMEchaVLy/fI3vGzn8gf4r6yKYbZ0vET91jwwR1Di
WuF2JBhi2dE/QLZDAguzbWdx+Y4cDUbmjsn/asf6cYauI6wPgAHwthTjuR+pr8qV
jPMIv0C05DmEhlc1RMDan8DdhdxO9LipZwdKEkM8PhBKy0iHcLhq6NSKWZLcLDQX
JyDpy2i+mxBomCMr4Q1gk6VWBSAz0stYwwg/g06jPiahFXYr2hkHerlNudrk8Wo+
gVhdEh0IOF2UJJVNYn9+2A==
-----END CERTIFICATE-----`;
      this.badEndLinePem = `-----BEGIN CERTIFICATE-----
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
      this.tcbInfoSigningCertPem = `-----BEGIN CERTIFICATE-----
MIICiDCCAi6gAwIBAgIUOGmGYZPE2lFghsw8+siUsai+2yEwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMCAXDTIyMDUxOTA4NDkxNVoYDzIwNTIwNTE5MDg0OTE1WjBsMR4w
HAYDVQQDDBVJbnRlbCBTR1ggVENCIFNpZ25pbmcxGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXYVFKEWN6t8kISYy
Sy0MnWA5uhMmc2/DkPhDjrcXOJBL7J41hU44IccEtMDeLtC6tZS4a5fsf1BsVBnP
lcD0LKOBrzCBrDAfBgNVHSMEGDAWgBQxQ5A8cqzvyMiAJ1b7mU3kCIi1GjBMBgNV
HR8ERTBDMEGgP6A9hjtodHRwOi8vbm9uLWV4aXN0aW5nLWRlYnVnLW9ubHkuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmNybDAdBgNVHQ4EFgQUOGmGYZPE2lFghsw8
+siUsai+2yEwDgYDVR0PAQH/BAQDAgbAMAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0E
AwIDSAAwRQIhANeHlhzC5Lp4EnRSQUQfS2hFbG5P6OM0IsVjRvIIWs78AiA7hXqH
qwb1ASfXtioQB5XXC2O46KRaGiwpvz/oAOD/rg==
-----END CERTIFICATE-----`;
    this.pck = new X509Certificate(this.pckPem);
    this.intermediateCa = new X509Certificate(this.intermediateCaPem);
    this.rootCa = new X509Certificate(this.rootCaPem);
    this.tcbInfoSigningCert = new X509Certificate(this.tcbInfoSigningCertPem);

  }

  async getTarget() {
      return proxyquire('../../src/handlers/certificateChainParser', {});
  }
}

describe('certificate chain parser tests', () => {

  it('less than 3 certs provided', async() => {
    // GIVEN
    const c = new TestContext();
    // WHEN
    const target = await c.getTarget();
    
    const resultPromise = target.parseCertificateChainWithSpecificRoot(c.rootCaPublicKey, c.rootCaPem + c.intermediateCaPem);
    // THEN
    await assert.rejects(resultPromise, /Certification data is not a chain of 3 certificates in PEM format/);
  });

  it('more than 3 certs provided', async() => {
    // GIVEN
    const c = new TestContext();
    // WHEN
    const target = await c.getTarget();
    
    const resultPromise = target.parseCertificateChainWithSpecificRoot(c.rootCaPublicKey, c.rootCaPem + c.intermediateCaPem + c.pckPem + c.pckPem);
    // THEN
    await assert.rejects(resultPromise, /Certification data is not a chain of 3 certificates in PEM format/);
  });

  it('no provided root ca in chain', async() => {
    // GIVEN
    const c = new TestContext();
    // WHEN
    const target = await c.getTarget();
    
    const resultPromise = target.parseCertificateChainWithSpecificRoot(c.rootCaPublicKey, c.pckPem + c.intermediateCaPem + c.anotherCert);
    // THEN
    await assert.rejects(resultPromise, /No trusted root CA in provided chain/);
  });

  it('no cert signed by root ca in chain', async() => {
    // GIVEN
    const c = new TestContext();
    // WHEN
    const target = await c.getTarget();
    
    const resultPromise = target.parseCertificateChainWithSpecificRoot(c.rootCaPublicKey, c.pckPem + c.anotherCert + c.rootCaPem);
    // THEN
    await assert.rejects(resultPromise, /No intermediate CA issued by trusted root CA found in provided chain/);
  });

  it('no cert signed by intermediate ca in chain', async() => {
    // GIVEN
    const c = new TestContext();
    // WHEN
    const target = await c.getTarget();
    
    const resultPromise = target.parseCertificateChainWithSpecificRoot(c.rootCaPublicKey, c.anotherCert + c.intermediateCaPem + c.rootCaPem);
    // THEN
    await assert.rejects(resultPromise, /No PCK cert issued by intermediate CA found in provided chain/);
  });

    it('2 self signed', async() => {
        // GIVEN
        const c = new TestContext();
        // WHEN
        const target = await c.getTarget();

        const resultPromise = target.parseCertificateChainWithSpecificRoot(c.rootCaPublicKey, c.rootCaPem + c.intermediateCaPem + c.rootCaPem);
        // THEN
        await assert.rejects(resultPromise, /Certification data contains duplicated certificates/);
    });

    it('parse certificates - order from top to bottom', async() => {
      // GIVEN
      const c = new TestContext();
      // WHEN
      const target = await c.getTarget();
      const {
          // X509 Certificates
          rootCa,
          intermediateCa,
          pckCert,
          // PEM Certificates
          rootCaPem,
          intermediateCaPem,
          pckCertPem
      } = await target.parseCertificateChainWithSpecificRoot(c.rootCaPublicKey, c.pckPem + c.intermediateCaPem + c.rootCaPem);
      // THEN
      assert.strictEqual(rootCaPem, c.rootCaPem);
      assert.strictEqual(intermediateCaPem, c.intermediateCaPem);
      assert.strictEqual(pckCertPem, c.pckPem);
      assert.deepEqual(rootCa, c.rootCa);
      assert.deepEqual(intermediateCa, c.intermediateCa);
      assert.deepEqual(pckCert, c.pck);
  });

  it('parse certificates - order from bottom to top', async() => {
    // GIVEN
    const c = new TestContext();
    // WHEN
    const target = await c.getTarget();
    const {
        // X509 Certificates
        rootCa,
        intermediateCa,
        pckCert,
        // PEM Certificates
        rootCaPem,
        intermediateCaPem,
        pckCertPem
    } = await target.parseCertificateChainWithSpecificRoot(c.rootCaPublicKey, c.rootCaPem + c.intermediateCaPem + c.pckPem);
    // THEN
    assert.strictEqual(rootCaPem, c.rootCaPem);
    assert.strictEqual(intermediateCaPem, c.intermediateCaPem);
    assert.strictEqual(pckCertPem, c.pckPem);
    assert.deepEqual(rootCa, c.rootCa);
    assert.deepEqual(intermediateCa, c.intermediateCa);
    assert.deepEqual(pckCert, c.pck);
  });

  it('parse certificates - support illogical but possibly used order', async() => {
    // GIVEN
    const c = new TestContext();
    // WHEN
    const target = await c.getTarget();
    const {
        // X509 Certificates
        rootCa,
        intermediateCa,
        pckCert,
        // PEM Certificates
        rootCaPem,
        intermediateCaPem,
        pckCertPem
    } = await target.parseCertificateChainWithSpecificRoot(c.rootCaPublicKey, c.pckPem + c.rootCaPem + c.intermediateCaPem);
    // THEN
    assert.strictEqual(rootCaPem, c.rootCaPem);
    assert.strictEqual(intermediateCaPem, c.intermediateCaPem);
    assert.strictEqual(pckCertPem, c.pckPem);
    assert.deepEqual(rootCa, c.rootCa);
    assert.deepEqual(intermediateCa, c.intermediateCa);
    assert.deepEqual(pckCert, c.pck);
  });

  it('cannot parse certificates - bad end line', async() => {
      // GIVEN
      const c = new TestContext();
      // WHEN
      const target = await c.getTarget();
      // THEN
      const resultPromise = target.parseCertificateChainWithSpecificRoot(c.rootCaPublicKey, c.rootCaPem + c.badEndLinePem + c.intermediateCaPem);
      // THEN
      await assert.rejects(resultPromise, /bad end line/);
  });

    it('root with public key not found', async() => {
        // GIVEN
        const c = new TestContext();
        // WHEN
        const target = await c.getTarget();

        const resultPromise = target.parseCertificateChainWithSpecificRoot('0a0a0a0a', c.rootCaPem +  c.intermediateCaPem + c.pckPem);
        // THEN
        await assert.rejects(resultPromise, /No trusted root CA in provided chain. Expected public key: 0a0a0a0a/);
    });

});

describe('TCB Info Signing chain parser tests', () => {

    it('success', async() => {
        // GIVEN
        const c = new TestContext();
        // WHEN
        const target = await c.getTarget();

        const {
            // X509 Certificates
            rootCa,
            tcbInfoSigningCert,
            rootCaPem,
            tcbInfoSigningCertPem,
        } = await target.parseTcbInfoSigningChainWithSpecificRoot(c.rootCaPublicKey, c.rootCaPem + c.tcbInfoSigningCertPem);
        // THEN
        assert.strictEqual(rootCaPem, c.rootCaPem);
        assert.strictEqual(tcbInfoSigningCertPem, c.tcbInfoSigningCertPem);
        assert.deepEqual(rootCa, c.rootCa);
        assert.deepEqual(tcbInfoSigningCert, c.tcbInfoSigningCert);
    });

    it('success with different order', async() => {
        // GIVEN
        const c = new TestContext();
        // WHEN
        const target = await c.getTarget();

        const {
            // X509 Certificates
            rootCa,
            tcbInfoSigningCert,
            rootCaPem,
            tcbInfoSigningCertPem,
        } = await target.parseTcbInfoSigningChainWithSpecificRoot(c.rootCaPublicKey, c.tcbInfoSigningCertPem + c.rootCaPem);
        // THEN
        assert.strictEqual(rootCaPem, c.rootCaPem);
        assert.strictEqual(tcbInfoSigningCertPem, c.tcbInfoSigningCertPem);
        assert.deepEqual(rootCa, c.rootCa);
        assert.deepEqual(tcbInfoSigningCert, c.tcbInfoSigningCert);
    });

    it('root with public key not found', async() => {
        // GIVEN
        const c = new TestContext();
        // WHEN
        const target = await c.getTarget();

        const resultPromise = target.parseTcbInfoSigningChainWithSpecificRoot('0a0a0a0a', c.rootCaPem +  c.tcbInfoSigningCertPem);
        // THEN
        await assert.rejects(resultPromise, /No trusted root CA in provided chain. Expected public key: 0a0a0a0a/);
    });

    it('less than 2 certs provided', async() => {
        // GIVEN
        const c = new TestContext();
        // WHEN
        const target = await c.getTarget();

        const resultPromise = target.parseTcbInfoSigningChainWithSpecificRoot(c.rootCaPublicKey, c.rootCaPem);
        // THEN
        await assert.rejects(resultPromise, /TCB Info Signing Chain is not a chain of 2 certificates in PEM format/);
    });

    it('duplicates provided', async() => {
        // GIVEN
        const c = new TestContext();
        // WHEN
        const target = await c.getTarget();

        const resultPromise = target.parseTcbInfoSigningChainWithSpecificRoot(c.rootCaPublicKey, c.rootCaPem + c.rootCaPem);
        // THEN
        await assert.rejects(resultPromise, /TCB Info Signing Chain contains duplicated certificates/);
    });

    it('bad cert parsing error', async() => {
        // GIVEN
        const c = new TestContext();
        // WHEN
        const target = await c.getTarget();

        const resultPromise = target.parseTcbInfoSigningChainWithSpecificRoot(c.rootCaPublicKey, c.rootCaPem + c.badEndLinePem);
        // THEN
        await assert.rejects(resultPromise, /bad end line/);
    });

    it('tcb info signing cert is not found', async() => {
        // GIVEN
        const c = new TestContext();
        // WHEN
        const target = await c.getTarget();

        const resultPromise = target.parseTcbInfoSigningChainWithSpecificRoot(c.rootCaPublicKey, c.rootCaPem + c.anotherCert);
        // THEN
        await assert.rejects(resultPromise, /No TCB Info Signing Cert issued by trusted root CA found in provided chain./);
    });
});
