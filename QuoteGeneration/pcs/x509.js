const { Certificate } = require('@fidm/x509')
const { ASN1 } = require('@fidm/asn1')

const SGX_EXTENSIONS_OID = '1.2.840.113741.1.13.1';
const TAG_OID = 6;
const SGX_EXTENSIONS_FMSPC_OID = '1.2.840.113741.1.13.1.4';

function X509(){
    if (!(this instanceof X509)) {
        return new X509();
    }

    this.fmspc = null;
}

X509.prototype.parseCert=function(cert_buffer) {
    let cert = Certificate.fromPEM(cert_buffer);
    let extensions = cert.extensions;
    let sgx_extensions = null;
    for (var i = 0; i < extensions.length; i++)
    {
        if (extensions[i].oid === SGX_EXTENSIONS_OID)
        {
            sgx_extensions = extensions[i].value;
            break;
        }
    }
    if (sgx_extensions == null)
        return false;

    let asn1 = ASN1.fromDER(sgx_extensions);
    let sgx_ext_values = asn1.value;
    for (var i = 0; i < sgx_ext_values.length; i++)
    {
        var obj = sgx_ext_values[i];
        if (obj.value[0].tag == TAG_OID && obj.value[0].value === SGX_EXTENSIONS_FMSPC_OID)
        {
            this.fmspc = obj.value[1].value.toString('hex');
            return true; 
        }
    }
    return false;
}

module.exports = X509
