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

const qvlStatus = require('../../src/qvl/status');
const errorSource = require('../../src/qvl/verifyQuoteErrorSource');
const proxyquire = require('proxyquire').noCallThru().noPreserveCache();
const assert = require('assert');
const sinon = require('sinon');
const _ = require('lodash');

class TestContext {

    constructor() {
        this.logger = {
            error: sinon.stub()
        };
        this.wrapper = {
            version: sinon.stub()
        };

        this.quote = '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Y2FsaXR5PWZhbHNlCkF1dGhvcml0eUtleUlkZW50aWZpZXIgWwpLZXlJZGVudGlmaWVyIFsKMDAwMDogMzEgNDMgOTAgM0MgNzIgQUMgRUYgQzggICBDOCA4MCAyNyA1NiBGQiA5OSA0RCBFNCAgMUMuPHIuLi4uLidWLi5NLgowMDEwOiAwOCA4OCBCNSAxQSAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAuLi4uCl0KXQoKWzJdOiBPYmplY3RJZDogMi41LjI5LjE5IENyaXRpY2FsaXR5PXRydWUKQmFzaWNDb25zdHJhaW50czpbCiAgQ0E6dHJ1ZQogIFBhdGhMZW46MQpdCgpbM106IE9iamVjdElkOiAyLjUuMjkuMzEgQ3JpdGljYWxpdHk9ZmFsc2UKQ1JMRGlzdHJpYnV0aW9uUG9pbnRzIFsKICBbRGlzdHJpYnV0aW9uUG9pbnQ6CiAgICAgW1VSSU5hbWU6IGh0dHA6Ly9ub24tZXhpc3RpbmctZGVidWctb25seS5pbnRlbC5jb20vSW50ZWxTR1hSb290Q0EuY3JsXQpdXQoKWzRdOiBPYmplY3RJZDogMi41LjI5LjE1IENyaXRpY2FsaXR5PXRydWUKS2V5VXNhZ2UgWwogIEtleV9DZXJ0U2lnbgogIENybF9TaWduCl0KCls1XTogT2JqZWN0SWQ6IDIuNS4yOS4xNCBDcml0aWNhbGl0eT1mYWxzZQpTdWJqZWN0S2V5SWRlbnRpZmllciBbCktleUlkZW50aWZpZXIgWwowMDAwOiAzMSA0MyA5MCAzQyA3MiBBQyBFRiBDOCAgIEM4IDgwIDI3IDU2IEZCIDk5IDREIEU0ICAxQy48ci4uLi4uJ1YuLk0uCjAwMTA6IDA4IDg4IEI1IDFBICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC4uLi4KXQpdCgpdCiAgQWxnb3JpdGhtOiBbU0hBMjU2d2l0aEVDRFNBXQogIFNpZ25hdHVyZToKMDAwMDogMzAgNDUgMDIgMjEgMDAgOUMgOEQgQTYgICBDOCA2NCAwMCAzOCBBRCA4RCBCRCAwOSAgMEUuIS4uLi4uZC44Li4uLgowMDEwOiAzQSA2MyA1NSBERCBDQSA2RiA5RiAxOCAgIDA0IDQyIDVBIDg1IEQzIEY5IDhBIDU4ICA6Y1UuLm8uLi5CWi4uLi5YCjAwMjA6IDkyIEZFIEU0IEY3IDQ4IDAyIDIwIDVBICAgRkUgNUIgNUYgQzQgRDggMkQgMzkgRDAgIC4uLi5ILiBaLltfLi4tOS4KMDAzMDogNDYgQjkgM0EgNEEgRDEgMjAgMzIgQTkgICA0NiBDMyAxQyBCMSA3RSBDNCBBNyA4QiAgRi46Si4gMi5GLi4uLi4uLgowMDQwOiBDNyAwRiAxNiBFQiA2NCA5MiBDRSAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAuLi4uZC4uCgpdWwpbCiAgVmVyc2lvbjogVjMKICBTdWJqZWN0OiBDPVVTLCBTVD1DQSwgTD1TYW50YSBDbGFyYSwgTz1JbnRlbCBDb3Jwb3JhdGlvbiwgQ049SW50ZWwgU0dYIFBDSyBQcm9jZXNzb3IgQ0EKICBTaWduYXR1cmUgQWxnb3JpdGhtOiBTSEEyNTZ3aXRoRUNEU0EsIE9JRCA9IDEuMi44NDAuMTAwNDUuNC4zLjIKCiAgS2V5OiAgU3VuIEVDIHB1YmxpYyBrZXksIDI1NiBiaXRzCiAgcHVibGljIHggY29vcmQ6IDIwMjUyNjI5NDkxMjM0NzY5MDEwNDEzODM0MzQwMjE1NDgwMjkyODQ4MTU1MjgzMDUwNDczODIxMDY1OTAyODMzMTQ3NzU0NDM3MDUxCiAgcHVibGljIHkgY29vcmQ6IDY2OTQ0OTg3OTk4MTY3NTUzMjMxMzY1OTU5MjYwNjI2NjUyNzEyNjIzMDQ2ODExNzMzMTQwNTI5NDI2ODM5Njc2MTM3MDA1NjEzNjEzCiAgcGFyYW1ldGVyczogc2VjcDI1NnIxIFtOSVNUIFAtMjU2LCBYOS42MiBwcmltZTI1NnYxXSAoMS4yLjg0MC4xMDA0NS4zLjEuNykKICBWYWxpZGl0eTogW0Zyb206IFRodSBNYXkgMTkgMTA6NDk6MTUgQ0VTVCAyMDIyLAogICAgICAgICAgICAgICBUbzogU3VuIE1heSAxOSAxMDo0OToxNSBDRVNUIDIwNTJdCiAgSXNzdWVyOiBDPVVTLCBTVD1DQSwgTD1TYW50YSBDbGFyYSwgTz1JbnRlbCBDb3Jwb3JhdGlvbiwgQ049SW50ZWwgU0dYIFJvb3QgQ0EKICBTZXJpYWxOdW1iZXI6IFsgICAgMjg4OTEwZmIgZTAwNDE4YTAgMzgzZjUyYjUgM2YxZDQ3YzAgMzJlMmIyZjNdCgpDZXJ0aWZpY2F0ZSBFeHRlbnNpb25zOiA1ClsxXTogT2JqZWN0SWQ6IDIuNS4yOS4zNSBDcml0aWNhbGl0eT1mYWxzZQpBdXRob3JpdHlLZXlJZGVudGlmaWVyIFsKS2V5SWRlbnRpZmllciBbCjAwMDA6IDMxIDQzIDkwIDNDIDcyIEFDIEVGIEM4ICAgQzggODAgMjcgNTYgRkIgOTkgNEQgRTQgIDFDLjxyLi4uLi4nVi4uTS4KMDAxMDogMDggODggQjUgMUEgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLi4uLgpdCl0KClsyXTogT2JqZWN0SWQ6IDIuNS4yOS4xOSBDcml0aWNhbGl0eT10cnVlCkJhc2ljQ29uc3RyYWludHM6WwogIENBOnRydWUKICBQYXRoTGVuOjAKXQoKWzNdOiBPYmplY3RJZDogMi41LjI5LjMxIENyaXRpY2FsaXR5PWZhbHNlCkNSTERpc3RyaWJ1dGlvblBvaW50cyBbCiAgW0Rpc3RyaWJ1dGlvblBvaW50OgogICAgIFtVUklOYW1lOiBodHRwOi8vbm9uLWV4aXN0aW5nLWRlYnVnLW9ubHkuaW50ZWwuY29tL0ludGVsU0dYUm9vdENBLmNybF0KXV0KCls0XTogT2JqZWN0SWQ6IDIuNS4yOS4xNSBDcml0aWNhbGl0eT10cnVlCktleVVzYWdlIFsKICBLZXlfQ2VydFNpZ24KICBDcmxfU2lnbgpdCgpbNV06IE9iamVjdElkOiAyLjUuMjkuMTQgQ3JpdGljYWxpdHk9ZmFsc2UKU3ViamVjdEtleUlkZW50aWZpZXIgWwpLZXlJZGVudGlmaWVyIFsKMDAwMDogMjggODkgMTAgRkIgRTAgMDQgMTggQTAgICAzOCAzRiA1MiBCNSAzRiAxRCA0NyBDMCAgKC4uLi4uLi44P1IuPy5HLgowMDEwOiAzMiBFMiBCMiBGMyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAyLi4uCl0KXQoKXQogIEFsZ29yaXRobTogW1NIQTI1NndpdGhFQ0RTQV0KICBTaWduYXR1cmU6CjAwMDA6IDMwIDQ0IDAyIDIwIDQ3IDA4IDJBIEExICAgRjYgQTkgOEUgOUIgNTggNDggMTggOUMgIDBELiBHLiouLi4uLlhILi4KMDAxMDogRjYgNUIgQzkgMTAgNTYgODcgQjcgODYgICA3QyBCMiAwMiAxNiA3NyA1RiAxNiBBRCAgLlsuLlYuLi4uLi4ud18uLgowMDIwOiA2RiBGOSAzQyBFOSAwMiAyMCA3NSA1NiAgIEM0IEIxIDRBIDUzIDJCIDE2IDM0IDBFICBvLjwuLiB1Vi4uSlMrLjQuCjAwMzA6IDNBIDM3IDlCIEQwIDJGIDYwIDk2IDk1ICAgMUEgQkMgMDggQ0EgMjYgOEQgQ0EgQzMgIDo3Li4vYC4uLi4uLiYuLi4KMDA0MDogNkQgQ0YgQTcgRUYgMEIgOEIgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbS4uLi4uCgpdWwpbCiAgVmVyc2lvbjogVjMKICBTdWJqZWN0OiBDPVVTLCBTVD1DQSwgTD1TYW50YSBDbGFyYSwgTz1JbnRlbCBDb3Jwb3JhdGlvbiwgQ049SW50ZWwgU0dYIFBDSyBDZXJ0aWZpY2F0ZQogIFNpZ25hdHVyZSBBbGdvcml0aG06IFNIQTI1NndpdGhFQ0RTQSwgT0lEID0gMS4yLjg0MC4xMDA0NS40LjMuMgoKICBLZXk6ICBTdW4gRUMgcHVibGljIGtleSwgMjU2IGJpdHMKICBwdWJsaWMgeCBjb29yZDogMTAwOTM1MjYxNzEwMTIyMDQ3NzExNTE5MTAwNTYxOTcwNjYwNTUxMTA0MDk1NjY4ODYzNjI2NzkxODUxMDI5NTg4MzU0OTYxMzY0MjMyCiAgcHVibGljIHkgY29vcmQ6IDc0MDI0NTcyNzQ2NTA0MjIwNTg4NTEyMzM2OTAwMjU2NDAzMzkxNzQzODc5MzA0MjgyNTI1MTYyMDAzNDg4NjI5ODM1NTAzMTU0ODk5CiAgcGFyYW1ldGVyczogc2VjcDI1NnIxIFtOSVNUIFAtMjU2LCBYOS42MiBwcmltZTI1NnYxXSAoMS4yLjg0MC4xMDA0NS4zLjEuNykKICBWYWxpZGl0eTogW0Zyb206IFRodSBNYXkgMTkgMTA6NDk6MTUgQ0VTVCAyMDIyLAogICAgICAgICAgICAgICBUbzogU3VuIE1heSAxOSAxMDo0OToxNSBDRVNUIDIwNTJdCiAgSXNzdWVyOiBDPVVTLCBTVD1DQSwgTD1TYW50YSBDbGFyYSwgTz1JbnRlbCBDb3Jwb3JhdGlvbiwgQ049SW50ZWwgU0dYIFBDSyBQcm9jZXNzb3IgQ0EKICBTZXJpYWxOdW1iZXI6IFsgICAgYzk3ZDM2ZDEgMzgxMTgwMmIgZDFjNmQ5MDkgNThlYjU1MzIgNDRmMTRmODFdCgpDZXJ0aWZpY2F0ZSBFeHRlbnNpb25zOiA2ClsxXTogT2JqZWN0SWQ6IDEuMi44NDAuMTEzNzQxLjEuMTMuMSBDcml0aWNhbGl0eT1mYWxzZQpFeHRlbnNpb24gdW5rbm93bjogREVSIGVuY29kZWQgT0NURVQgc3RyaW5nID0KMDAwMDogMDQgODIgMDEgQ0UgMzAgODIgMDEgQ0EgICAzMCAxRSAwNiAwQSAyQSA4NiA0OCA4NiAgLi4uLjAuLi4wLi4uKi5ILgowMDEwOiBGOCA0RCAwMSAwRCAwMSAwMSAwNCAxMCAgIDlCIDJCIDgyIDM1IDUwIDU5IDIzIDEzICAuTS4uLi4uLi4rLjVQWSMuCjAwMjA6IEMzIDhEIEE0IEUzIDdGIDFDIDExIDQxICAgMzAgODIgMDEgNkQgMDYgMEEgMkEgODYgIC4uLi4uLi5BMC4ubS4uKi4KMDAzMDogNDggODYgRjggNEQgMDEgMEQgMDEgMDIgICAzMCA4MiAwMSA1RCAzMCAxMCAwNiAwQiAgSC4uTS4uLi4wLi5dMC4uLgowMDQwOiAyQSA4NiA0OCA4NiBGOCA0RCAwMSAwRCAgIDAxIDAyIDAxIDAyIDAxIDE3IDMwIDEwICAqLkguLk0uLi4uLi4uLjAuCjAwNTA6IDA2IDBCIDJBIDg2IDQ4IDg2IEY4IDREICAgMDEgMEQgMDEgMDIgMDIgMDIgMDEgMkQgIC4uKi5ILi5NLi4uLi4uLi0KMDA2MDogMzAgMTAgMDYgMEIgMkEgODYgNDggODYgICBGOCA0RCAwMSAwRCAwMSAwMiAwMyAwMiAgMC4uLiouSC4uTS4uLi4uLgowMDcwOiAwMSAyQyAzMCAxMSAwNiAwQiAyQSA4NiAgIDQ4IDg2IEY4IDREIDAxIDBEIDAxIDAyICAuLDAuLi4qLkguLk0uLi4uCjAwODA6IDA0IDAyIDAyIDAwIEZGIDMwIDExIDA2ICAgMEIgMkEgODYgNDggODYgRjggNEQgMDEgIC4uLi4uMC4uLiouSC4uTS4KMDA5MDogMEQgMDEgMDIgMDUgMDIgMDIgMDAgRjUgICAzMCAxMSAwNiAwQiAyQSA4NiA0OCA4NiAgLi4uLi4uLi4wLi4uKi5ILgowMEEwOiBGOCA0RCAwMSAwRCAwMSAwMiAwNiAwMiAgIDAyIDAwIDg4IDMwIDExIDA2IDBCIDJBICAuTS4uLi4uLi4uLjAuLi4qCjAwQjA6IDg2IDQ4IDg2IEY4IDREIDAxIDBEIDAxICAgMDIgMDcgMDIgMDIgMDAgOTkgMzAgMTAgIC5ILi5NLi4uLi4uLi4uMC4KMDBDMDogMDYgMEIgMkEgODYgNDggODYgRjggNEQgICAwMSAwRCAwMSAwMiAwOCAwMiAwMSAyOSAgLi4qLkguLk0uLi4uLi4uKQowMEQwOiAzMCAxMCAwNiAwQiAyQSA4NiA0OCA4NiAgIEY4IDREIDAxIDBEIDAxIDAyIDA5IDAyICAwLi4uKi5ILi5NLi4uLi4uCjAwRTA6IDAxIDI4IDMwIDEwIDA2IDBCIDJBIDg2ICAgNDggODYgRjggNEQgMDEgMEQgMDEgMDIgIC4oMC4uLiouSC4uTS4uLi4KMDBGMDogMEEgMDIgMDEgMUUgMzAgMTAgMDYgMEIgICAyQSA4NiA0OCA4NiBGOCA0RCAwMSAwRCAgLi4uLjAuLi4qLkguLk0uLgowMTAwOiAwMSAwMiAwQiAwMiAwMSA1RCAzMCAxMSAgIDA2IDBCIDJBIDg2IDQ4IDg2IEY4IDREICAuLi4uLl0wLi4uKi5ILi5NCjAxMTA6IDAxIDBEIDAxIDAyIDBDIDAyIDAyIDAwICAgRjkgMzAgMTAgMDYgMEIgMkEgODYgNDggIC4uLi4uLi4uLjAuLi4qLkgKMDEyMDogODYgRjggNEQgMDEgMEQgMDEgMDIgMEQgICAwMiAwMSA0MiAzMCAxMSAwNiAwQiAyQSAgLi5NLi4uLi4uLkIwLi4uKgowMTMwOiA4NiA0OCA4NiBGOCA0RCAwMSAwRCAwMSAgIDAyIDBFIDAyIDAyIDAwIENGIDMwIDExICAuSC4uTS4uLi4uLi4uLjAuCjAxNDA6IDA2IDBCIDJBIDg2IDQ4IDg2IEY4IDREICAgMDEgMEQgMDEgMDIgMEYgMDIgMDIgMDAgIC4uKi5ILi5NLi4uLi4uLi4KMDE1MDogRUEgMzAgMTEgMDYgMEIgMkEgODYgNDggICA4NiBGOCA0RCAwMSAwRCAwMSAwMiAxMCAgLjAuLi4qLkguLk0uLi4uLgowMTYwOiAwMiAwMiAwMCBEOSAzMCAxMiAwNiAwQiAgIDJBIDg2IDQ4IDg2IEY4IDREIDAxIDBEICAuLi4uMC4uLiouSC4uTS4uCjAxNzA6IDAxIDAyIDExIDAyIDAzIDAwIDlGIEI3ICAgMzAgMUYgMDYgMEIgMkEgODYgNDggODYgIC4uLi4uLi4uMC4uLiouSC4KMDE4MDogRjggNEQgMDEgMEQgMDEgMDIgMTIgMDQgICAxMCAxNyAyRCAyQyBGRiBGNSA4OCA5OSAgLk0uLi4uLi4uLi0sLi4uLgowMTkwOiAyOSAyOCAxRSA1RCBGOSA0MiBDRiBFQSAgIEQ5IDMwIDEwIDA2IDBBIDJBIDg2IDQ4ICApKC5dLkIuLi4wLi4uKi5ICjAxQTA6IDg2IEY4IDREIDAxIDBEIDAxIDAzIDA0ICAgMDIgNzIgRTggMzAgMTQgMDYgMEEgMkEgIC4uTS4uLi4uLnIuMC4uLioKMDFCMDogODYgNDggODYgRjggNEQgMDEgMEQgMDEgICAwNCAwNCAwNiA4QyBCMiBGNyBDMCBCNCAgLkguLk0uLi4uLi4uLi4uLgowMUMwOiA2OSAzMCAwRiAwNiAwQSAyQSA4NiA0OCAgIDg2IEY4IDREIDAxIDBEIDAxIDA1IDBBICBpMC4uLiouSC4uTS4uLi4uCjAxRDA6IDAxIDAwICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC4uCgoKWzJdOiBPYmplY3RJZDogMi41LjI5LjM1IENyaXRpY2FsaXR5PWZhbHNlCkF1dGhvcml0eUtleUlkZW50aWZpZXIgWwpLZXlJZGVudGlmaWVyIFsKMDAwMDogMjggODkgMTAgRkIgRTAgMDQgMTggQTAgICAzOCAzRiA1MiBCNSAzRiAxRCA0NyBDMCAgKC4uLi4uLi44P1IuPy5HLgowMDEwOiAzMiBFMiBCMiBGMyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAyLi4uCl0KXQoKWzNdOiBPYmplY3RJZDogMi41LjI5LjE5IENyaXRpY2FsaXR5PXRydWUKQmFzaWNDb25zdHJhaW50czpbCiAgQ0E6ZmFsc2UKICBQYXRoTGVuOiB1bmRlZmluZWQKXQoKWzRdOiBPYmplY3RJZDogMi41LjI5LjMxIENyaXRpY2FsaXR5PWZhbHNlCkNSTERpc3RyaWJ1dGlvblBvaW50cyBbCiAgW0Rpc3RyaWJ1dGlvblBvaW50OgogICAgIFtVUklOYW1lOiBodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50ZWwuY29tL0ludGVsU0dYUENLUHJvY2Vzc29yLmNybF0KXV0KCls1XTogT2JqZWN0SWQ6IDIuNS4yOS4xNSBDcml0aWNhbGl0eT10cnVlCktleVVzYWdlIFsKICBEaWdpdGFsU2lnbmF0dXJlCiAgTm9uX3JlcHVkaWF0aW9uCl0KCls2XTogT2JqZWN0SWQ6IDIuNS4yOS4xNCBDcml0aWNhbGl0eT1mYWxzZQpTdWJqZWN0S2V5SWRlbnRpZmllciBbCktleUlkZW50aWZpZXIgWwowMDAwOiA5NCAwRiAxQiA0QyAwRCAyMyA0NyA4MiAgIEM1IEZFIEYzIDkzIDcyIENCIDE3IDQyICAuLi5MLiNHLi4uLi5yLi5CCjAwMTA6IEFDIEFFIDBFIDY2ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC4uLmYKXQpdCgpdCiAgQWxnb3JpdGhtOiBbU0hBMjU2d2l0aEVDRFNBXQogIFNpZ25hdHVyZToKMDAwMDogMzAgNDYgMDIgMjEgMDAgRkIgNDEgREMgICA3NyBEOSA1MiAyNyA5MiAxNiBBMCBBNSAgMEYuIS4uQS53LlInLi4uLgowMDEwOiAzMCA2OCA1MyBEQiAzNSA2QiA5OCBFNyAgIDdGIDU5IENEIEI1IEY4IDdCIDcyIDRFICAwaFMuNWsuLi5ZLi4uLnJOCjAwMjA6IEZDIDQ5IDdGIDkzIEU4IDAyIDIxIDAwICAgRkEgNzYgRUUgNzMgMkYgMkQgQTUgOEUgIC5JLi4uLiEuLnYucy8tLi4KMDAzMDogODcgRTYgQUYgMDggNjYgQjUgQjcgMEYgICAwMCAzNCAxNyBGOSA0QSA1MiA5MyA1NiAgLi4uLmYuLi4uNC4uSlIuVgowMDQwOiAwOSAxOSA3NyA4QiBCMyA3NSA2RSA2QyAgICAgICAgICAgICAgICAgICAgICAgICAgICAuLncuLnVubAoKXQ==';
        this.standardPckCertificate = `-----BEGIN CERTIFICATE-----
MIIEhjCCBCugAwIBAgIVAMl9NtE4EYAr0cbZCVjrVTJE8U+BMAoGCCqGSM49BAMC
MHExIzAhBgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQK
DBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNV
BAgMAkNBMQswCQYDVQQGEwJVUzAgFw0yMjA1MTkwODQ5MTVaGA8yMDUyMDUxOTA4
NDkxNVowcDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBDZXJ0aWZpY2F0ZTEaMBgG
A1UECgwRSW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQsw
CQYDVQQIDAJDQTELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AATfJ1VnkHV9M8yDNH4JkPHv4WMQ85ocJqknmEJm1sHVCKOobGVVWvYAVAx0Qv+P
8oAjVIz0u8sgN1d7Zm2wPrbTo4ICnTCCApkwHwYDVR0jBBgwFoAUKIkQ++AEGKA4
P1K1Px1HwDLisvMwWAYDVR0fBFEwTzBNoEugSYZHaHR0cHM6Ly9jZXJ0aWZpY2F0
ZXMudHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9JbnRlbFNHWFBDS1Byb2Nlc3Nv
ci5jcmwwHQYDVR0OBBYEFJQPG0wNI0eCxf7zk3LLF0Ksrg5mMA4GA1UdDwEB/wQE
AwIGwDAMBgNVHRMBAf8EAjAAMIIB3QYJKoZIhvhNAQ0BBIIBzjCCAcowHgYKKoZI
hvhNAQ0BAQQQmyuCNVBZIxPDjaTjfxwRQTCCAW0GCiqGSIb4TQENAQIwggFdMBAG
CyqGSIb4TQENAQIBAgEXMBAGCyqGSIb4TQENAQICAgEtMBAGCyqGSIb4TQENAQID
AgEsMBEGCyqGSIb4TQENAQIEAgIA/zARBgsqhkiG+E0BDQECBQICAPUwEQYLKoZI
hvhNAQ0BAgYCAgCIMBEGCyqGSIb4TQENAQIHAgIAmTAQBgsqhkiG+E0BDQECCAIB
KTAQBgsqhkiG+E0BDQECCQIBKDAQBgsqhkiG+E0BDQECCgIBHjAQBgsqhkiG+E0B
DQECCwIBXTARBgsqhkiG+E0BDQECDAICAPkwEAYLKoZIhvhNAQ0BAg0CAUIwEQYL
KoZIhvhNAQ0BAg4CAgDPMBEGCyqGSIb4TQENAQIPAgIA6jARBgsqhkiG+E0BDQEC
EAICANkwEgYLKoZIhvhNAQ0BAhECAwCftzAfBgsqhkiG+E0BDQECEgQQFy0s//WI
mSkoHl35Qs/q2TAQBgoqhkiG+E0BDQEDBAJy6DAUBgoqhkiG+E0BDQEEBAaMsvfA
tGkwDwYKKoZIhvhNAQ0BBQoBADAKBggqhkjOPQQDAgNJADBGAiEA+0Hcd9lSJ5IW
oKUwaFPbNWuY539ZzbX4e3JO/El/k+gCIQD6du5zLy2ljofmrwhmtbcPADQX+UpS
k1YJGXeLs3VubA==
-----END CERTIFICATE-----`;

        this.scalablePckCertificate = `-----BEGIN CERTIFICATE-----
MIIFADCCBKWgAwIBAgIUDqW3QZNJGlU7Z64xmJ/Arv7rUk8wCgYIKoZIzj0EAwIw
cDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBQbGF0Zm9ybSBDQTEaMBgGA1UECgwR
SW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQI
DAJDQTELMAkGA1UEBhMCVVMwHhcNMjIwNTEyMDg0MzI2WhcNMjkwNTEyMDg0MzI2
WjBwMSIwIAYDVQQDDBlJbnRlbCBTR1ggUENLIENlcnRpZmljYXRlMRowGAYDVQQK
DBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNV
BAgMAkNBMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABM1j
Mok/JG5aF5dmEN3yU+UWtHFKjia89b5vvaIZD3oUjcoKTY8sf6NYE1PPJTqPTFHx
dua8vly1pxSBDTVSe9KjggMbMIIDFzAfBgNVHSMEGDAWgBTtuYIDdPNuVuxFlJO5
vsEacMQ9tDBvBgNVHR8EaDBmMGSgYqBghl5odHRwczovL3ByZTEzLWdyZWVuLXBj
cy5zZ3hucC5hZHNkY3NwLmNvbS9zZ3gvY2VydGlmaWNhdGlvbi92My9wY2tjcmw/
Y2E9cGxhdGZvcm0mZW5jb2Rpbmc9ZGVyMB0GA1UdDgQWBBTezqyoFXPa8PcSAUDD
lZqttLIyuTAOBgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH/BAIwADCCAkQGCSqGSIb4
TQENAQSCAjUwggIxMB4GCiqGSIb4TQENAQEEEGN47uJQUYj5rpm5A7tfzvUwggFu
BgoqhkiG+E0BDQECMIIBXjAQBgsqhkiG+E0BDQECAQIBADARBgsqhkiG+E0BDQEC
AgICANgwEQYLKoZIhvhNAQ0BAgMCAgD7MBEGCyqGSIb4TQENAQIEAgIAwDAQBgsq
hkiG+E0BDQECBQIBADARBgsqhkiG+E0BDQECBgICAPgwEQYLKoZIhvhNAQ0BAgcC
AgDBMBEGCyqGSIb4TQENAQIIAgIA3zARBgsqhkiG+E0BDQECCQICAMUwEAYLKoZI
hvhNAQ0BAgoCAR0wEAYLKoZIhvhNAQ0BAgsCAVswEAYLKoZIhvhNAQ0BAgwCATUw
EQYLKoZIhvhNAQ0BAg0CAgDtMBAGCyqGSIb4TQENAQIOAgEjMBEGCyqGSIb4TQEN
AQIPAgIAujARBgsqhkiG+E0BDQECEAICALQwEQYLKoZIhvhNAQ0BAhECAi6GMB8G
CyqGSIb4TQENAQISBBAA2PvAAPjB38UdWzXtI7q0MBAGCiqGSIb4TQENAQMEAgAA
MBQGCiqGSIb4TQENAQQEBs19ugQAADAPBgoqhkiG+E0BDQEFCgEBMB4GCiqGSIb4
TQENAQYEEE1IunY4uzprOPjsRxFkF7wwRAYKKoZIhvhNAQ0BBzA2MBAGCyqGSIb4
TQENAQcBAQH/MBAGCyqGSIb4TQENAQcCAQH/MBAGCyqGSIb4TQENAQcDAQEAMAoG
CCqGSM49BAMCA0kAMEYCIQCCA5avU/QqQ/W28BCUoWsZUpG0Ly+uxzAkQ/3rcYEt
lwIhAKh9jYja0prJNGYfhC4mFv1mbphhgfB75Ni9gWA0uGJs
-----END CERTIFICATE-----`;

        this.scalableWihIntegrityPckCertificate = `-----BEGIN CERTIFICATE-----
MIIE8jCCBJigAwIBAgIUDqW3QZNJGlU7Z64xmJ/Arv7rUk8wCgYIKoZIzj0EAwIw
cDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBQbGF0Zm9ybSBDQTEaMBgGA1UECgwR
SW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQI
DAJDQTELMAkGA1UEBhMCVVMwHhcNMjIwNTEyMDg0MzI3WhcNMjkwNTEyMDg0MzI3
WjBwMSIwIAYDVQQDDBlJbnRlbCBTR1ggUENLIENlcnRpZmljYXRlMRowGAYDVQQK
DBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNV
BAgMAkNBMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABM1j
Mok/JG5aF5dmEN3yU+UWtHFKjia89b5vvaIZD3oUjcoKTY8sf6NYE1PPJTqPTFHx
dua8vly1pxSBDTVSe9KjggMOMIIDCjAfBgNVHSMEGDAWgBTtuYIDdPNuVuxFlJO5
vsEacMQ9tDBiBgNVHR8EWzBZMFegVaBThlFodHRwczovL3ByZTEzLWdyZWVuLXBj
cy5zZ3hucC5hZHNkY3NwLmNvbS9zZ3gvY2VydGlmaWNhdGlvbi92Mi9wY2tjcmw/
Y2E9cGxhdGZvcm0wHQYDVR0OBBYEFN7OrKgVc9rw9xIBQMOVmq20sjK5MA4GA1Ud
DwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMIICRAYJKoZIhvhNAQ0BBIICNTCCAjEw
HgYKKoZIhvhNAQ0BAQQQY3ju4lBRiPmumbkDu1/O9TCCAW4GCiqGSIb4TQENAQIw
ggFeMBAGCyqGSIb4TQENAQIBAgEAMBEGCyqGSIb4TQENAQICAgIA2DARBgsqhkiG
+E0BDQECAwICAPswEQYLKoZIhvhNAQ0BAgQCAgDAMBAGCyqGSIb4TQENAQIFAgEA
MBEGCyqGSIb4TQENAQIGAgIA+DARBgsqhkiG+E0BDQECBwICAMEwEQYLKoZIhvhN
AQ0BAggCAgDfMBEGCyqGSIb4TQENAQIJAgIAxTAQBgsqhkiG+E0BDQECCgIBHTAQ
BgsqhkiG+E0BDQECCwIBWzAQBgsqhkiG+E0BDQECDAIBNTARBgsqhkiG+E0BDQEC
DQICAO0wEAYLKoZIhvhNAQ0BAg4CASMwEQYLKoZIhvhNAQ0BAg8CAgC6MBEGCyqG
SIb4TQENAQIQAgIAtDARBgsqhkiG+E0BDQECEQICLoYwHwYLKoZIhvhNAQ0BAhIE
EADY+8AA+MHfxR1bNe0jurQwEAYKKoZIhvhNAQ0BAwQCAAAwFAYKKoZIhvhNAQ0B
BAQGzX26BAAAMA8GCiqGSIb4TQENAQUKAQEwHgYKKoZIhvhNAQ0BBgQQTUi6dji7
Oms4+OxHEWQXvDBEBgoqhkiG+E0BDQEHMDYwEAYLKoZIhvhNAQ0BBwEBAf8wEAYL
KoZIhvhNAQ0BBwIBAf8wEAYLKoZIhvhNAQ0BBwMBAQAwCgYIKoZIzj0EAwIDSAAw
RQIgBme4bAQyOHVIM+4/hMbJegEMiXSLSH9UZ5bloaTP2MECIQCujD8VLLhJ31nj
m0nxa0ExVWWrSBSL2uSM81uKftgmrw==
-----END CERTIFICATE-----`;

        this.tcbSigningCert = `-----BEGIN CERTIFICATE-----
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
        this.intermediateCert = `-----BEGIN CERTIFICATE-----
MIICkjCCAjmgAwIBAgIUKIkQ++AEGKA4P1K1Px1HwDLisvMwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMCAXDTIyMDUxOTA4NDkxNVoYDzIwNTIwNTE5MDg0OTE1WjBxMSMw
IQYDVQQDDBpJbnRlbCBTR1ggUENLIFByb2Nlc3NvciBDQTEaMBgGA1UECgwRSW50
ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJD
QTELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQsxpUCw8rk
6HAhIMk+5fda2Qft0yGFazF8oHAd593Zu5QBhTxnrTlNKG6lgBF440/Kom1jrYMc
0ldzKwIZn4Ito4G1MIGyMB8GA1UdIwQYMBaAFDFDkDxyrO/IyIAnVvuZTeQIiLUa
MEwGA1UdHwRFMEMwQaA/oD2GO2h0dHA6Ly9ub24tZXhpc3RpbmctZGVidWctb25s
eS5pbnRlbC5jb20vSW50ZWxTR1hSb290Q0EuY3JsMB0GA1UdDgQWBBQoiRD74AQY
oDg/UrU/HUfAMuKy8zAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIB
ADAKBggqhkjOPQQDAgNHADBEAiBHCCqh9qmOm1hIGJz2W8kQVoe3hnyyAhZ3Xxat
b/k86QIgdVbEsUpTKxY0Djo3m9AvYJaVGrwIyiaNysNtz6fvC4s=
-----END CERTIFICATE-----`;

        this.rootCaCert = `-----BEGIN CERTIFICATE-----
MIICiDCCAi6gAwIBAgIUMUOQPHKs78jIgCdW+5lN5AiItRowCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTIyMDUxOTA4NDkxNVoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgD2FXqq4lPgCVgFx0+Y+YvFt
78HeveFaQsoQ8DIHH0SRJE4hWxIRjBklmkh/GkOzeNIU8UdS1GcwHz5OUBCEV6OB
tTCBsjAfBgNVHSMEGDAWgBQxQ5A8cqzvyMiAJ1b7mU3kCIi1GjBMBgNVHR8ERTBD
MEGgP6A9hjtodHRwOi8vbm9uLWV4aXN0aW5nLWRlYnVnLW9ubHkuaW50ZWwuY29t
L0ludGVsU0dYUm9vdENBLmNybDAdBgNVHQ4EFgQUMUOQPHKs78jIgCdW+5lN5AiI
tRowDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYIKoZIzj0E
AwIDSAAwRQIhAJyNpshkADitjb0JOmNV3cpvnxgEQlqF0/mKWJL+5PdIAiBa/ltf
xNgtOdBGuTpK0SAyqUbDHLF+xKeLxw8W62SSzg==
-----END CERTIFICATE-----`;

        this.rootCaCertNotTrusted = `-----BEGIN CERTIFICATE-----
MIICkjCCAjegAwIBAgIUVs38UHvRdwK2UoHC07LcgvA5+3owCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE5MDgyODExMzUxNVoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5OrBrf+Fu4b8cZB0kCHhTBAH
eo/NX9IWlGVfIRLlNEa+k8v5ahmfFlkBbHPN/EKcX5BW5HDidc9dYG8fRWoStaOB
vjCBuzAfBgNVHSMEGDAWgBRWzfxQe9F3ArZSgcLTstyC8Dn7ejBVBgNVHR8ETjBM
MEqgSKBGhkRodHRwczovL2Zha2UtY3JsLWRpc3RyaWJ1dGlvbi1wb2ludC11cmwu
aW50ZWwuY29tL0ludGVsU0dYUm9vdENBLmNybDAdBgNVHQ4EFgQUVs38UHvRdwK2
UoHC07LcgvA5+3owDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEw
CgYIKoZIzj0EAwIDSQAwRgIhAKz1aFTu1JcXhbVOyxnuqxO84wKeRRc1+1vi+q2a
JsrtAiEA4/5hDa8ri0X4kBaFfe9d0oCqaN8tXA0fuslGoZVhzmU=
-----END CERTIFICATE-----`;

        this.tcbInfo = '{"tcbInfo":{"version":3,"issueDate":"2022-05-19T08:49:16Z","nextUpdate":"2049-10-04T08:49:16Z","fmspc":"8cb2f7c0b469","pceId":"72e8","tcbLevels":[{"tcb":{"sgxtcbcomponents":[{"svn":23},{"svn":45},{"svn":44},{"svn":255},{"svn":245},{"svn":136},{"svn":153},{"svn":41},{"svn":40},{"svn":30},{"svn":93},{"svn":249},{"svn":66},{"svn":207},{"svn":234},{"svn":217}],"pcesvn":40887},"tcbStatus":"UpToDate","tcbDate":"2022-05-19T08:49:16Z","advisoryIDs":["INTEL-SA-38861","INTEL-SA-68515"]}],"id":"SGX","tcbType":0,"tcbEvaluationDataNumber":0},"signature":"db060eb4aa81465703331311547b8396ee7c68d2ace96242da976dea35b1929aaecd993af9f24df1ed0dbd10bbabd764f64580992439cc5bbcf315be0307739b"}';
        this.qeIdentity = '{"enclaveIdentity":{"id":"QE","version":2,"issueDate":"2022-05-19T08:49:16Z","nextUpdate":"2049-10-04T08:49:16Z","tcbEvaluationDataNumber":0,"miscselect":"24CFEE3E","miscselectMask":"FFFFFFFF","attributes":"1dc1ba9e57df0c52f8da0aae19ad0388","attributesMask":"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF","mrsigner":"ceac8454d29bc4968130335756bc0eba746580ac9a08ba21f7b2e115bbc0cbc4","isvprodid":9594,"tcbLevels":[{"tcb":{"isvsvn":51866},"tcbDate":"2022-05-19T08:49:16Z","tcbStatus":"UpToDate"}]},"signature":"de1a7221811d2990d3c6bed38cbf42ca07456f72fc0743f7dd9e27bf51b78d552c9f42cc5147859c39a7e4654cc01d027e1465b32e440757bb57055d3eaef566"}';
        this.tcbSigningCertChain = `${this.rootCaCert}\n${this.tcbSigningCert}`;
        this.pckCertIssuerCertChain = `${this.rootCaCert}\n${this.intermediateCert}`;
        this.intermediateCrl = '308201293081d1020101300a06082a8648ce3d04030230713123302106035504030c1a496e74656c205347582050434b2050726f636573736f72204341311a3018060355040a0c11496e74656c20436f72706f726174696f6e3114301206035504070c0b53616e746120436c617261310b300906035504080c024341310b3009060355040613025553170d3232303531393038343931355a170d3439313030343038343931355aa02f302d300a0603551d140403020101301f0603551d23041830168014288910fbe00418a0383f52b53f1d47c032e2b2f3300a06082a8648ce3d04030203470030440220619b3d28a4d71d4932da0fa18c66968917f89fa65ebf8ca1281e9ea6f973b87c02202a6c92f5d447f35d765fad76cdfc1da10e106c09488a59bee92d69bad8f1315c';
        this.rootCrl = '308201213081c8020101300a06082a8648ce3d0403023068311a301806035504030c11496e74656c2053475820526f6f74204341311a3018060355040a0c11496e74656c20436f72706f726174696f6e3114301206035504070c0b53616e746120436c617261310b300906035504080c024341310b3009060355040613025553170d3232303531393038343931355a170d3439313030343038343931355aa02f302d300a0603551d140403020101301f0603551d230418301680143143903c72acefc8c8802756fb994de40888b51a300a06082a8648ce3d0403020348003045022100bc0980401119231caca34a76bbfd47e44127aa5f7f6e66bac8144554ef91165902203091aaa5900c90eabc8a617ad03a41b91f8e19bab3258a75198c10a652b1f522';
    }

    async getTarget() {
        return require('../../src/qvl');
    }

    async getMock() {
        return proxyquire('../../src/qvl', {
            '../../native/QuoteVerificationLibraryWrapper.node':         this.wrapper,
            '../../native/QuoteVerificationLibraryWrapperd.node':        this.wrapper,
            '../qvl/cmake-build-debug/QuoteVerificationLibraryWrapperd': this.wrapper
        });
    }
}

// Only basic wrapper tests without QVL logic specific tests as it's tested in QVL UTs.
describe('qvlTest', () => {
    it('get version - positive', async() => {
        // GIVEN
        const c = new TestContext();
        // WHEN
        const wrapper = await c.getTarget();
        const version = await wrapper.getVersion('test-request-id', c.logger);
        const expected = { body: { status: 'OK', version: '1.0.0' } };
        // THEN
        assert(_.isEqual(version, expected),
            `\nExpected: ${JSON.stringify(expected)}\nActual:   ${JSON.stringify(version)}`);
    });

    it('get version - negative', async() => {
        // GIVEN
        const c = new TestContext();
        // WHEN
        c.wrapper.version.rejects();
        const wrapper = await c.getMock();
        const version = await wrapper.getVersion('test-request-id', c.logger);
        const expected = { body: { status: 'FAILED', version: 'NA' } };
        // THEN
        assert(_.isEqual(version, expected),
            `\nExpected: ${JSON.stringify(expected)}\nActual:   ${JSON.stringify(version)}`);
    });

    it('Get Certification Data - positive', async() => {
        // GIVEN
        const c = new TestContext();
        const quote = Buffer.from(c.quote, 'base64');
        const wrapper = await c.getTarget();

        // WHEN
        const result = await wrapper.getCertificationData('test-request-id', quote);

        // THEN
        assert.equal(result.type, 5);
    });

    it('Get Certification Data - negative', async() => {
        // GIVEN
        const c = new TestContext();
        const quote = Buffer.from('AwACAAAAAAAEAAkAk5pyM/ec', 'base64'); // wrong quote
        const wrapper = await c.getTarget();

        // WHEN
        const resultPromise = wrapper.getCertificationData('test-request-id', quote);

        // THEN
        await assert.rejects(resultPromise, {
            error:  'sgxAttestationGetQECertificationDataSize failed',
            status: 37
        });
    });

    it('Get PCK Certificate Data - positive - Standard', async() => {
        // GIVEN
        const c = new TestContext();
        const wrapper = await c.getTarget();

        // WHEN
        const result = await wrapper.getPckCertificateData('test-request-id', c.standardPckCertificate);

        // THEN
        assert(result.fmspc, '00906EA10000');
        assert(result.sgxType, 'Standard');
        assert(result.dynamicPlatform === undefined);
        assert(result.cachedKeys === undefined);
        assert(result.smtEnabled === undefined);
    });

    it('Get PCK Certificate Data - positive - Scalable', async() => {
        // GIVEN
        const c = new TestContext();
        const wrapper = await c.getTarget();

        // WHEN
        const result = await wrapper.getPckCertificateData('test-request-id', c.scalablePckCertificate);

        // THEN
        assert(result.fmspc, '00906EA10000');
        assert(result.sgxType, 'Scalable');
        assert(result.dynamicPlatform === true);
        assert(result.cachedKeys === true);
        assert(result.smtEnabled === false);
    });

    it('Get PCK Certificate Data - positive - ScalableWithIntegrity', async() => {
        // GIVEN
        const c = new TestContext();
        const wrapper = await c.getTarget();

        // WHEN
        const result = await wrapper.getPckCertificateData('test-request-id', c.scalableWihIntegrityPckCertificate);

        // THEN
        assert(result.fmspc, '00906EA10000');
        assert(result.sgxType, 'ScalableWithIntegrity');
        assert(result.dynamicPlatform === true);
        assert(result.cachedKeys === true);
        assert(result.smtEnabled === false);
    });

    it('Get PCK Certificate Data - negative', async() => {
        // GIVEN
        const c = new TestContext();
        const wrapper = await c.getTarget();

        // WHEN
        const resultPromise = wrapper.getPckCertificateData('test-request-id', 'wrong cert');

        // THEN
        await assert.rejects(resultPromise, {
            error: 'Error getting data from PCK certificate: PEM_read_bio_X509 failed error:0909006C:PEM routines:get_name:no start line'
        });
    });

    it('Get CRL distribution point - positive', async() => {
        // GIVEN
        const c = new TestContext();
        const wrapper = await c.getTarget();

        // WHEN
        const result = await wrapper.getCrlDistributionPoint('test-request-id', c.standardPckCertificate);
        // THEN
        assert.equal(result, 'Full Name:  URI:https://certificates.trustedservices.intel.com/IntelSGXPCKProcessor.crl');
    });

    it('Get CRL distribution point - negative', async() => {
        // GIVEN
        const c = new TestContext();
        const wrapper = await c.getTarget();

        // WHEN
        const resultPromise = wrapper.getCrlDistributionPoint('test-request-id', 'wrong cert');

        // THEN
        await assert.rejects(resultPromise, {
            error: 'Error getting CRL distribution point: PEM_read_bio_X509 failed error:0909006C:PEM routines:get_name:no start line'
        });
    });

    it('Verify quote - positive but TCB out of date', async() => {
        const c = new TestContext();
        const wrapper = await c.getTarget();
        const quote = Buffer.from(c.quote, 'base64');

        const result = await wrapper.verifyQuote('test-request-id', quote, c.standardPckCertificate, c.tcbInfo, c.qeIdentity, c.pckCertIssuerCertChain, c.tcbSigningCertChain,
            c.intermediateCrl, c.rootCrl, c.rootCaCert, c.rootCaCert);

        assert.deepEqual(result, {
            status: qvlStatus.STATUS_OK
        });

    });

    it('Verify quote - wrong pck certificate', async() => {
        const c = new TestContext();
        const wrapper = await c.getTarget();
        const quote = Buffer.from(c.quote, 'base64');

        const result = await wrapper.verifyQuote('test-request-id', quote, 'GARBAGE', c.tcbInfo, c.qeIdentity, c.pckCertIssuerCertChain, c.tcbSigningCertChain,
            c.intermediateCrl, c.rootCrl, c.rootCaCert, c.rootCaCert);

        assert.deepEqual(result, {
            status:      qvlStatus.STATUS_UNSUPPORTED_CERT_FORMAT,
            errorSource: errorSource.VERIFY_PCK_CERTIFICATE,
            error:       'PCK certificate verification failed'
        });
    });

    it('Verify quote - wrong tcb info', async() => {
        const c = new TestContext();
        const wrapper = await c.getTarget();
        const quote = Buffer.from(c.quote, 'base64');

        const result = await wrapper.verifyQuote('test-request-id', quote, c.standardPckCertificate, 'GARBAGE', c.qeIdentity, c.pckCertIssuerCertChain, c.tcbSigningCertChain,
            c.intermediateCrl, c.rootCrl, c.rootCaCert, c.rootCaCert);

        assert.deepEqual(result, {
            status:      qvlStatus.STATUS_SGX_TCB_INFO_UNSUPPORTED_FORMAT,
            errorSource: errorSource.VERIFY_TCB_INFO,
            error:       'TCB info verification failed'
        });
    });

    it('Verify quote - wrong QE Identity', async() => {
        const c = new TestContext();
        const wrapper = await c.getTarget();
        const quote = Buffer.from(c.quote, 'base64');

        const result = await wrapper.verifyQuote('test-request-id', quote, c.standardPckCertificate, c.tcbInfo, 'GARBAGE', c.pckCertIssuerCertChain, c.tcbSigningCertChain,
            c.intermediateCrl, c.rootCrl, c.rootCaCert, c.rootCaCert);

        assert.deepEqual(result, {
            status:      qvlStatus.STATUS_SGX_ENCLAVE_IDENTITY_UNSUPPORTED_FORMAT,
            errorSource: errorSource.VERIFY_ENCLAVE_IDENTITY,
            error:       'Enclave identity verification failed'
        });
    });

    it('Verify quote - wrong pck cert chain', async() => {
        const c = new TestContext();
        const wrapper = await c.getTarget();
        const quote = Buffer.from(c.quote, 'base64');

        const result = await wrapper.verifyQuote('test-request-id', quote, c.standardPckCertificate, c.tcbInfo, c.qeIdentity, 'GARBAGE', c.tcbSigningCertChain,
            c.intermediateCrl, c.rootCrl, c.rootCaCert, c.rootCaCert);

        assert.deepEqual(result, {
            status:      qvlStatus.STATUS_UNSUPPORTED_CERT_FORMAT,
            errorSource: errorSource.VERIFY_PCK_CERTIFICATE,
            error:       'PCK certificate verification failed'
        });
    });

    it('Verify quote - wrong tcb signing chain', async() => {
        const c = new TestContext();
        const wrapper = await c.getTarget();
        const quote = Buffer.from(c.quote, 'base64');

        const result = await wrapper.verifyQuote('test-request-id', quote, c.standardPckCertificate, c.tcbInfo, c.qeIdentity, c.pckCertIssuerCertChain, 'GARBAGE',
            c.intermediateCrl, c.rootCrl, c.rootCaCert, c.rootCaCert);

        assert.deepEqual(result, {
            status:      qvlStatus.STATUS_UNSUPPORTED_CERT_FORMAT,
            errorSource: errorSource.VERIFY_TCB_INFO,
            error:       'TCB info verification failed'
        });
    });

    it('Verify quote - wrong intermediate CRL', async() => {
        const c = new TestContext();
        const wrapper = await c.getTarget();
        const quote = Buffer.from(c.quote, 'base64');

        const result = await wrapper.verifyQuote('test-request-id', quote, c.standardPckCertificate, c.tcbInfo, c.qeIdentity, c.pckCertIssuerCertChain, c.tcbSigningCertChain,
            'GARBAGE', c.rootCrl, c.rootCaCert, c.rootCaCert);

        assert.deepEqual(result, {
            status:      qvlStatus.STATUS_SGX_CRL_UNSUPPORTED_FORMAT,
            errorSource: errorSource.VERIFY_PCK_CERTIFICATE,
            error:       'PCK certificate verification failed'
        });
    });

    it('Verify quote - wrong root CRL', async() => {
        const c = new TestContext();
        const wrapper = await c.getTarget();
        const quote = Buffer.from(c.quote, 'base64');

        const result = await wrapper.verifyQuote('test-request-id', quote, c.standardPckCertificate, c.tcbInfo, c.qeIdentity, c.pckCertIssuerCertChain, c.tcbSigningCertChain,
            c.intermediateCrl, 'GARBAGE', c.rootCaCert, c.rootCaCert);

        assert.deepEqual(result, {
            status:      qvlStatus.STATUS_SGX_CRL_UNSUPPORTED_FORMAT,
            errorSource: errorSource.VERIFY_PCK_CERTIFICATE,
            error:       'PCK certificate verification failed'
        });
    });

    it('Verify quote - wrong root CA cert', async() => {
        const c = new TestContext();
        const wrapper = await c.getTarget();
        const quote = Buffer.from(c.quote, 'base64');

        const result = await wrapper.verifyQuote('test-request-id', quote, c.standardPckCertificate, c.tcbInfo, c.qeIdentity, c.pckCertIssuerCertChain, c.tcbSigningCertChain,
            c.intermediateCrl, c.rootCrl, 'GARBAGE', c.rootCaCert);

        assert.deepEqual(result, {
            status:      qvlStatus.STATUS_TRUSTED_ROOT_CA_UNSUPPORTED_FORMAT,
            errorSource: errorSource.VERIFY_PCK_CERTIFICATE,
            error:       'PCK certificate verification failed'
        });
    });

    it('Verify quote - wrong TCB Signing root CA cert', async() => {
        const c = new TestContext();
        const wrapper = await c.getTarget();
        const quote = Buffer.from(c.quote, 'base64');

        const result = await wrapper.verifyQuote('test-request-id', quote, c.standardPckCertificate, c.tcbInfo, c.qeIdentity, c.pckCertIssuerCertChain, c.tcbSigningCertChain,
            c.intermediateCrl, c.rootCrl, c.rootCaCert, 'GARBAGE');

        assert.deepEqual(result, {
            status:      qvlStatus.STATUS_UNSUPPORTED_CERT_FORMAT,
            errorSource: errorSource.VERIFY_TCB_INFO,
            error:       'TCB info verification failed'
        });
    });

    it('Verify quote - correct PCK Cert chain Root and not correct TCB Signing Chain root', async() => {
        const c = new TestContext();
        const wrapper = await c.getTarget();
        const quote = Buffer.from(c.quote, 'base64');

        const result = await wrapper.verifyQuote('test-request-id', quote, c.standardPckCertificate, c.tcbInfo, c.qeIdentity, c.pckCertIssuerCertChain, c.tcbSigningCertChain,
            c.intermediateCrl, c.rootCrl, c.rootCaCert, c.rootCaCertNotTrusted);

        assert.deepEqual(result, {
            status:      qvlStatus.STATUS_SGX_TCB_SIGNING_CERT_CHAIN_UNTRUSTED,
            errorSource: errorSource.VERIFY_TCB_INFO,
            error:       'TCB info verification failed'
        });
    });

    it('Verify quote - correct TCB Signing chain Root and not correct PCK cert Chain root', async() => {
        const c = new TestContext();
        const wrapper = await c.getTarget();
        const quote = Buffer.from(c.quote, 'base64');

        const result = await wrapper.verifyQuote('test-request-id', quote, c.standardPckCertificate, c.tcbInfo, c.qeIdentity, c.pckCertIssuerCertChain, c.tcbSigningCertChain,
            c.intermediateCrl, c.rootCrl, c.rootCaCertNotTrusted, c.rootCaCert);

        assert.deepEqual(result, {
            status:      qvlStatus.STATUS_SGX_PCK_CERT_CHAIN_UNTRUSTED,
            errorSource: errorSource.VERIFY_PCK_CERTIFICATE,
            error:       'PCK certificate verification failed'
        });
    });
});
