process.env.NODE_ENV = 'test';

var assert = require('assert');
var pckdb = require('../pckdb.js');
var path = require('path');
var pckclient = require('../pckclient.js');
var X509 = require('../x509.js');
var fs = require('fs');
let chai = require('chai');
let chaiHttp = require('chai-http');
let server = require('../pccs_server');
let should = chai.should();

chai.use(chaiHttp);


var qeid='4771B150A36FD0CFA63216DF1D3B6BFF';
var encppid = '7506E7BF90E1E0D4E7F6F4AEA689DC2B25CEC96E433DB1CD1AB8666FCB000749A5EC71A647854B173250C519564EFC2CDC45663A67D0DB0A0A56C091088EDFA29CEBBB6EF50C06115E42B075A2C2D0037EEACB40211845696853B484BC42012EF9BAF80C05DA1804999385596187783EE8E049915A58D250B8509093D538DCD1AE4D605EDBA7B0409D42B6ADEFFA0A7CE04CAE13475D55B8F1010D03CF281113FAAC0E95F2F5A6B7410255805C64ECD50E50F32EDEF97D9C89B340982916897D50AF0C15E1B4E62B562693B35F48FC35DBEC15BE9E3A6A14760480442B3796E08DF0F053DAC8F195900BFEF59182A89E5C9BD745968635D76046920278A2A6E3F56CC1C7CFB6384018424D4363BA4F41829BDA4E275321B9E9BF69941E09C154CC6A021720E18094F2F41B0E03A53F5E3C03A275C2EA78DD025E7E3C3D64119D340FC1A69D83F3CE18468C673636E16EBE9A4D75CCBD5914F95B127CB5B7D075B89DE846181A983359C0FD34ACCCB8B34A0BD91814034E9E1E64D2812EBECA7F';
var pceid='0000';
var cpusvn ='00060204FF0100000000000000000000';
var pcesvn ='0700';
var fmspc = '00808E300000';

/*
* Test the /GET route
*/
describe('/GET pckcert', () => {
    //before(async () => {
    //    await pckdb.sequelize.sync({force:true});
    //});

    // NOTE : Truncate is faster than sequelize.sync
    before(function (done) {
        Promise.all(Object.values(pckdb.sequelize.models).map(function(model){
            return model.destroy({truncate:true});
        }));
        done();
    });

    it('Get pckcert without parameters should fail', (done) => {
        chai.request(server)
            .get('/sgx/certification/v2/pckcert')
            .end((err, res) => {
                res.should.have.status(400);
                done();
            });
    });
    it('Get pckcert without qeid should fail', (done) => {
        chai.request(server)
            .get('/sgx/certification/v2/pckcert?encppid=' + encppid + '&pceid=' + pceid + '&cpusvn=' + cpusvn + '&pcesvn=' + pcesvn)
            .end((err, res) => {
                res.should.have.status(400);
                done();
            });
    });
    it('Get pckcert without encppid should fail', (done) => {
        chai.request(server)
            .get('/sgx/certification/v2/pckcert?qeid=' + qeid + '&pceid=' + pceid + '&cpusvn=' + cpusvn + '&pcesvn=' + pcesvn)
            .end((err, res) => {
                res.should.have.status(400);
                done();
            });
    });
    it('Get pckcert without pceid should fail', (done) => {
        chai.request(server)
            .get('/sgx/certification/v2/pckcert?qeid=' + qeid + '&encppid=' + encppid + '&cpusvn=' + cpusvn + '&pcesvn=' + pcesvn)
            .end((err, res) => {
                res.should.have.status(400);
                done();
            });
    });
    it('Get pckcert without cpusvn should fail', (done) => {
        chai.request(server)
            .get('/sgx/certification/v2/pckcert?qeid=' + qeid + '&encppid=' + encppid + '&pceid=' + pceid + '&pcesvn=' + pcesvn)
            .end((err, res) => {
                res.should.have.status(400);
                done();
            });
    });
    it('Get pckcert without pcesvn should fail', (done) => {
        chai.request(server)
            .get('/sgx/certification/v2/pckcert?qeid=' + qeid + '&encppid=' + encppid + '&pceid=' + pceid + '&cpusvn=' + cpusvn)
            .end((err, res) => {
                res.should.have.status(400);
                done();
            });
    });
    it('Get pckcert with valid parameters should succeed', (done) => {
        chai.request(server)
            .get('/sgx/certification/v2/pckcert?qeid=' + qeid + '&encrypted_ppid=' + encppid + '&pceid=' + pceid + '&cpusvn=' + cpusvn + '&pcesvn=' + pcesvn)
            .end((err, res) => {
                res.should.have.status(200);
                done();
            });
    });
    it('Get pckcert again should succeed', (done) => {
        chai.request(server)
            .get('/sgx/certification/v2/pckcert?qeid=' + qeid + '&encrypted_ppid=' + encppid + '&pceid=' + pceid + '&cpusvn=' + cpusvn + '&pcesvn=' + pcesvn)
            .end((err, res) => {
                res.should.have.status(200);
                done();
            });
    });
    it('Get pckcert from cache should succeed', async () => {
        var pckcert = await pckdb.getCert(qeid, cpusvn, pcesvn, pceid);
        while (pckcert == null) {
            // wait for cache ready
            pckcert = await pckdb.getCert(qeid, cpusvn, pcesvn, pceid);
        }

        chai.request(server)
            .get('/sgx/certification/v2/pckcert?qeid=' + qeid + '&pceid=' + pceid + '&cpusvn=' + cpusvn + '&pcesvn=' + pcesvn)
            .end((err, res) => {
                res.should.have.status(200);
            });
    });
});

describe('/GET pckcrl', () => {
    before(function (done) {
        Promise.all(Object.values(pckdb.sequelize.models).map(function(model){
            return model.destroy({truncate:true});
        }));
        done();
    });

    it('Get pckcrl without parameters should fail', (done) => {
        chai.request(server)
            .get('/sgx/certification/v2/pckcrl')
            .end((err, res) => {
                res.should.have.status(400);
                done();
            });
    });
    it('Get pckcrl with invalid ca parameter should fail', (done) => {
        chai.request(server)
            .get('/sgx/certification/v2/pckcrl?ca=abc')
            .end((err, res) => {
                res.should.have.status(400);
                done();
            });
    });
    it('Get pckcrl with valid parameters should succeed', (done) => {
        chai.request(server)
            .get('/sgx/certification/v2/pckcrl?ca=processor')
            .end((err, res) => {
                res.should.have.status(200);
                done();
            });
    });
    it('Get pckcrl again should succeed', (done) => {
        chai.request(server)
            .get('/sgx/certification/v2/pckcrl?ca=processor')
            .end((err, res) => {
                res.should.have.status(200);
                done();
            });
    });
    it('Get pckcrl from cache should succeed', async () => {
        let pckcrl = await pckdb.getPckCrl('processor');
        while (pckcrl == null) {
            // wait for cache ready
            pckcrl = await pckdb.getPckCrl('processor');
        }

        chai.request(server)
            .get('/sgx/certification/v2/pckcrl?ca=processor')
            .end((err, res) => {
                res.should.have.status(200);
            });
    });
});

describe('/GET tcb', () => {
    before(function (done) {
        Promise.all(Object.values(pckdb.sequelize.models).map(function(model){
            return model.destroy({truncate:true});
        }));
        done();
    });

    it('Get tcb without parameters should fail', (done) => {
        chai.request(server)
            .get('/sgx/certification/v2/tcb')
            .end((err, res) => {
                res.should.have.status(400);
                done();
            });
    });
    it('Get tcb with invalid fmspc parameter should fail', (done) => {
        chai.request(server) 
            .get('/sgx/certification/v2/pckcrl?fmspc=abc') 
            .end((err, res) => { 
                res.should.have.status(400); 
                done();
            });
    });
    it('Get tcb with valid parameters should succeed', (done) => {
        chai.request(server)
            .get('/sgx/certification/v2/tcb?fmspc=' + fmspc)
            .end((err, res) => {
                res.should.have.status(200);
                done();
            });
    });
    it('Get tcb again should succeed', (done) => {
        chai.request(server)
            .get('/sgx/certification/v2/tcb?fmspc=' + fmspc)
            .end((err, res) => {
                res.should.have.status(200);
                done();
            });
    });
    it('Get tcb from cache should succeed', async () => {
        let tcb_info = await pckdb.getTcb(fmspc);
        while (tcb_info == null) {
            // wait for cache ready
            tcb_info = await pckdb.getTcb(fmspc); 
        } 
        chai.request(server)
            .get('/sgx/certification/v2/tcb?fmspc=' + fmspc)
            .end((err, res) => {
                res.should.have.status(200);
            });
    });
});

describe('/GET QEIdentity', () => {
    before(function (done) {
        Promise.all(Object.values(pckdb.sequelize.models).map(function(model){
            return model.destroy({truncate:true});
        }));
        done();
    });

    it('Get QEIdentity  should succeed', (done) => {
        chai.request(server)
            .get('/sgx/certification/v2/qe/identity')
            .end((err, res) => {
                res.should.have.status(200);
                done();
            });
    });
    it('Get QEIdentity again should succeed', (done) => {
        chai.request(server)
            .get('/sgx/certification/v2/qe/identity')
            .end((err, res) => {
                res.should.have.status(200);
                done();
            });
    });
    it('Get QEIdentity from cache should succeed', async () => {
        let qe_identity = await pckdb.getQEIdentity();
        while (qe_identity == null) {
            // wait for cache ready
            qe_identity = await pckdb.getQEIdentity();
        } 
        chai.request(server)
            .get('/sgx/certification/v2/qe/identity')
            .end((err, res) => {
                res.should.have.status(200);
            });
    });
});

describe('/GET rootcacrl', () => {
    before(function (done) {
        Promise.all(Object.values(pckdb.sequelize.models).map(function(model){
            return model.destroy({truncate:true});
        }));
        done();
    });

    it('Get rootcacrl should succeed', (done) => {
        chai.request(server)
            .get('/sgx/certification/v2/rootcacrl')
            .end((err, res) => {
                res.should.have.status(200);
                done();
            });
    });

    it('Get rootcacrl again should succeed', (done) => {
        chai.request(server)
            .get('/sgx/certification/v2/rootcacrl')
            .end((err, res) => {
                res.should.have.status(200);
                done();
            });
    });
});

describe('pckdb.js', function(){
    before(function (done) {
        Promise.all(Object.values(pckdb.sequelize.models).map(function(model){
            return model.destroy({truncate:true});
        }));
        done();
    });

    describe('#upsertCert()', function(){
        it('Insert a PCK record with valid values should succeed.', async function(){
            let tcbm = '020200000000000000000000000000000600';
            let fmspc = '000000000000';
            let cert_file = path.join(__dirname, 'pck_cert0.cer');
            let pck_cert = fs.readFileSync(cert_file, 'utf8');;

            let pckcert = await pckdb.upsertCert(qeid, encppid, cpusvn, pcesvn, pceid, tcbm, fmspc, pck_cert);
            assert.ok(true);
        });
    });

    describe('#getCert()', function(){
        it('Get a non-existent record should return null.', async function(){
            //var qeid='05347b4393c8ad143dd30a599cc58827';
            let qeid='99997b4393c8ad143dd30a599cc58827';
            let pceid='0000';
            let cpusvn ='02020000000000000000000000000000';
            let pcesvn ='0000';
            let pckcert = await pckdb.getCert(qeid, cpusvn, pcesvn, pceid);
            assert.equal(pckcert, null);
        });
    });

    describe('#upsertPckCertchain()', function(){
        it('Upsert a valid certchain should succeed.', async function(){
            let cert_file = path.join(__dirname, 'certchain0.dat');
            let pck_certchain = fs.readFileSync(cert_file, 'utf8');;
            const result = await pckdb.upsertPckCertchain(pck_certchain);
            assert.ok(true);
        });
    });
    
    describe('#upsertPckCrl()', function(){
        it('Insert a PCK CRL record with valid values should succeed.', async function(){
            let ca ='processor';
            let crl_file = path.join(__dirname, 'pckcrl.dat');
            let pckcrl = fs.readFileSync(crl_file, 'utf8');;

            let pck_crl = await pckdb.upsertPckCrl(ca, pckcrl);
            assert.ok(true);
        });
    });

    describe('#getPckCrl()', function(){
        it('Get an existing PCK CRL record should succeed.', async function(){
            let ca ='processor';
            let pckcrl = await pckdb.getPckCrl(ca);
            assert.ok(true);
        });
    });

    describe('#getAllPckCrls()', function(){
        it('Get all PCK CRLs should succeed.', async function(){
            let pckcrls = await pckdb.getAllPckCrls();
            assert.ok(true);
        });
    });

    describe('#upsertTcb()', function(){
        it('Insert a TCBInfo record with valid values should succeed.', async function(){
            let fmspc = '002000000000';
            let tcbinfo_blob = 'This is a valid tcbinfo';

            let tcbinfo = await pckdb.upsertTcb(fmspc, tcbinfo_blob);
            assert.ok(true);
        });
    });

    describe('#getTcb()', function(){
        it('Get an existing TCBInfo record should succeed.', async function(){
            let fmspc = '002000000000';
            let tcbinfo = await pckdb.getTcb(fmspc);
            assert.ok(true);
        });
    });

    describe('#getAllTcbs()', function(){
        it('Get all TCBInfo records should succeed.', async function(){
            let tcbinfos = await pckdb.getAllTcbs();
            assert.ok(true);
        });
    });

    describe('#upsertQEIdentity()', function(){
        it('Insert a QEIdentity record with valid values should succeed.', async function(){
            let qeidentity_blob = 'This is a valid QE Identity';

            let qeidentity = await pckdb.upsertQEIdentity(qeidentity_blob);
            assert.ok(true);
        });
    });

    describe('#getQEIdentity()', function(){
        it('Get QEIdentity record should succeed.', async function(){
            let qeidentity = await pckdb.getQEIdentity();
            assert.ok(true);
        });
    });
});

describe('x509.js', function(){
    describe('#parseCert()', function(){
        it('Parse a valid root cert to get CDP uri should succeed.', function(){
            let cert_file = path.join(__dirname, 'root0.cer');
            let root_cert = fs.readFileSync(cert_file, 'utf8');
            let x509 = new X509();
            assert.equal(x509.fmspc, null);
            assert.equal(x509.cdp_uri, null);
            assert.equal(x509.parseCert(unescape(root_cert)), true);
            assert.notEqual(x509.cdp_uri, null);
        });
    });
});

describe('pck_client.js', function(){
    describe('#getFromUrl()', function(){
        it('HTTP Get from a valid CDP uri should succeed.', async ()=>{
            let uri = 'https://certificates.trustedservices.intel.com/IntelSGXRootCA.crl';            
            try {
                const result = await pckclient.getFileFromUrl(uri);
            }
            catch(err){
                assert.ok(false);
            }
            assert.ok(true);
        });
    });
});

