import * as asn1js from 'asn1js';

const chai = require('chai');
const expect = chai.expect;
const assert = chai.assert;
const should = chai.should();

import * as cc from '../../src/index';

const USE_CONSOLE_OUTPUT = process.env.USE_CONSOLE_OUTPUT || false;

const digestOid = new asn1js.ObjectIdentifier({
  value: '2.16.840.1.101.3.4.2.1'
});

describe('X509 Certificate Public Key', function () {
  const testCerts = {
    'TestCA-EC-SHA256': '-----BEGIN CERTIFICATE-----\n' +
      'MIIB1TCCAXugAwIBAgIBATAKBggqhkjOPQQDAjBKMQswCQYDVQQGEwJLUjEMMAoG\n' +
      'A1UEChMDT3JnMRIwEAYDVQQLEwlDQU9yZ1VuaXQxGTAXBgNVBAMTEFRlc3RDQS1F\n' +
      'Qy1TSEEyNTYwHhcNMjAwNjEwMDQ0ODAwWhcNMzAwNjEwMDQ0ODAwWjBKMQswCQYD\n' +
      'VQQGEwJLUjEMMAoGA1UEChMDT3JnMRIwEAYDVQQLEwlDQU9yZ1VuaXQxGTAXBgNV\n' +
      'BAMTEFRlc3RDQS1FQy1TSEEyNTYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQc\n' +
      'Vh6umNtZqLpu5m72Yacb6H+xDT16K6SzARxS1MXFsguwIVH80XbsSF+A6Tb8Qf2D\n' +
      'NlKelTpShVMx6t+rq1GFo1IwUDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSr\n' +
      'pYHG01qlORbQ/8jEqFFqt/yG7zALBgNVHQ8EBAMCAQYwEQYJYIZIAYb4QgEBBAQD\n' +
      'AgAHMAoGCCqGSM49BAMCA0gAMEUCIEXA1OAA5UJ7WWMMhfU6CHE75TETgZic2uqq\n' +
      'rXyfRSM1AiEA2crUaTUaeeUjdVRA4/xfEfTbXRCdEKqqHOTNwMcHMos=\n' +
      '-----END CERTIFICATE-----\n',
    'Test1_of_TestCA-EC-SHA256': '-----BEGIN CERTIFICATE-----\n' +
      'MIIByjCCAXCgAwIBAgIBAjAKBggqhkjOPQQDAjBKMQswCQYDVQQGEwJLUjEMMAoG\n' +
      'A1UEChMDT3JnMRIwEAYDVQQLEwlDQU9yZ1VuaXQxGTAXBgNVBAMTEFRlc3RDQS1F\n' +
      'Qy1TSEEyNTYwHhcNMjAwNjEwMDQ1MTAwWhcNMjEwNjEwMDQ1MTAwWjBSMQswCQYD\n' +
      'VQQGEwJLUjEMMAoGA1UEChMDT3JnMREwDwYDVQQLEwhUZXN0Q2VydDEiMCAGA1UE\n' +
      'AwwZVGVzdDFfb2ZfVGVzdENBLUVDLVNIQTI1NjBJMBMGByqGSM49AgEGCCqGSM49\n' +
      'AwEBAzIABKSK+SY9VRDf9s3PDd71Mh4sT1ejgQk/mVU4RtXoxJh3DlW+WnAKx2Kv\n' +
      '4JT1TTXv26NPME0wDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUSJ7e9KuaYvna9hXG\n' +
      'TKUi+06hrXgwCwYDVR0PBAQDAgXgMBEGCWCGSAGG+EIBAQQEAwIGQDAKBggqhkjO\n' +
      'PQQDAgNIADBFAiBFsFOoNA3fvnxsrjKf4Nh4srJs9+QxHRkZOckoYjjHOwIhAKwf\n' +
      'BRU8h7FT+L1yMWl45dpr84rO+elsPZRll10PFAZA\n' +
      '-----END CERTIFICATE-----\n',
    'TestCA-RSA-SHA256': '-----BEGIN CERTIFICATE-----\n' +
      'MIIDYzCCAkugAwIBAgIBATANBgkqhkiG9w0BAQsFADBLMQswCQYDVQQGEwJLUjEM\n' +
      'MAoGA1UEChMDT3JnMRIwEAYDVQQLEwlDQU9yZ1VuaXQxGjAYBgNVBAMTEVRlc3RD\n' +
      'QS1SU0EtU0hBMjU2MB4XDTIwMDYxMDA0NDcwMFoXDTMwMDYxMDA0NDcwMFowSzEL\n' +
      'MAkGA1UEBhMCS1IxDDAKBgNVBAoTA09yZzESMBAGA1UECxMJQ0FPcmdVbml0MRow\n' +
      'GAYDVQQDExFUZXN0Q0EtUlNBLVNIQTI1NjCCASIwDQYJKoZIhvcNAQEBBQADggEP\n' +
      'ADCCAQoCggEBAMUhPW6ozIaAt6oGLE7mY2mO3UOSEt1razrmFJi8bVDsjwk5U9YX\n' +
      'Q5SfE2aceAolLOgSmg78DMRJYAHbNkPMYjmNp0U7PQ7PuDSgJxEw2Xgl5YaykHoB\n' +
      '62HlDrEKSI8Hx3QRWXpkg5W3POzI8L0j3cuYSX/TVsFcPPagPoTszTTa6aKE5P53\n' +
      '3SoZUoa4yTtN3/weV9AZsaSzJ2SbSBKKHVcOCiliBol2IMtVgsAMRIJkoi04hI13\n' +
      'OZ2OzK5pbwe93JUxUmi5AoSLkdbU1qGRZ34ovVMgK1vqhMZjZdH/e4GZEgmzElFs\n' +
      'UbXQfKtzSESad57VQf0Q91KFUNET+WGIsfMCAwEAAaNSMFAwDwYDVR0TAQH/BAUw\n' +
      'AwEB/zAdBgNVHQ4EFgQUi/Na1APJkF9FAOSu8GhouJOZVDUwCwYDVR0PBAQDAgEG\n' +
      'MBEGCWCGSAGG+EIBAQQEAwIABzANBgkqhkiG9w0BAQsFAAOCAQEAGkHiu30Q2sCL\n' +
      'v3EwX2i8l17VXDzqUSIbrTZPEys7qk5gsnOLX3lcsA6j2cYcxU/WC26xC5kvTnRD\n' +
      'HPd8ZyrFJm2nXTSCGlEV7/6C+KPaj8wrF605l2Dzb3W+7dSXuCUCFYy1xTOJwccE\n' +
      '2tzHGG2GMrvU8JwZ6+5+mYqN/cJJqaSauMQRMB2fqgg2regwmoj3Tn/mfp42qOXD\n' +
      'mECxnadUvvKiAU/XXe7sF0rZJB9CAuJ2qW23cisyoU5ONUfvv6YPtchwKlxlOnrt\n' +
      'rEWP8ruuIAgpeJ56R8S1d13fRhycV8Oo67r+p5O6Jc1sND7xZqP/7erkpqaNuQwf\n' +
      '06Z/fPJD4w==\n' +
      '-----END CERTIFICATE-----\n',
    'Test1_of_TestCA-RSA-SHA256': '-----BEGIN CERTIFICATE-----\n' +
      'MIIDaDCCAlCgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBLMQswCQYDVQQGEwJLUjEM\n' +
      'MAoGA1UEChMDT3JnMRIwEAYDVQQLEwlDQU9yZ1VuaXQxGjAYBgNVBAMTEVRlc3RD\n' +
      'QS1SU0EtU0hBMjU2MB4XDTIwMDYxMDA0NTAwMFoXDTIxMDYxMDA0NTAwMFowUzEL\n' +
      'MAkGA1UEBhMCS1IxDDAKBgNVBAoTA09yZzERMA8GA1UECxMIVGVzdENlcnQxIzAh\n' +
      'BgNVBAMMGlRlc3QxX29mX1Rlc3RDQS1SU0EtU0hBMjU2MIIBIjANBgkqhkiG9w0B\n' +
      'AQEFAAOCAQ8AMIIBCgKCAQEAw5p1QXX+yKROL/ctBzLVubep6BAOsBvd7zLCap4l\n' +
      'ZC1n/Z2sxRJFGb1DBmJ8Vai7Xbkcg+knzZK1tffME9nmWtqHvikSl3Qo9rttiFOA\n' +
      'zutA8/yKTah7VByP5vuoTd/EJ03wy3qUHR16oA3Z/JevQ9k929sl+p0Ay1jj8ePB\n' +
      'bpFDv+QAswYdjFXma9qGugkx7ozx+a6LXSaemv9mwf3eoJrZ1zCoxxINHFQDPugl\n' +
      'b++vXtXTrVYHilgJT17OtJw3NEcq8QFzggbMlrxaKVCj0RUn46Ih18CeIE/3+M2O\n' +
      'ocWT5k66HmF8w4Swn79T5CxSdzwY3yd0x9A/lpxeszrOtQIDAQABo08wTTAMBgNV\n' +
      'HRMBAf8EAjAAMB0GA1UdDgQWBBSsc4XR9zGi7awSrpS6FvwZ2YUdNDALBgNVHQ8E\n' +
      'BAMCBeAwEQYJYIZIAYb4QgEBBAQDAgZAMA0GCSqGSIb3DQEBCwUAA4IBAQC5Pl+G\n' +
      'vJ104efj0Y19Ro7hLcFyfETSw0WL4eOWLwuwlPZKlhTHi3MgrbzhKYJxn3rq4oKv\n' +
      'vDcm5klHKFArGOUnY+YRaXmab3pKR6LouwJ3dbcTiDAFmhHUFFqBDZYUZsspUiZz\n' +
      'UnJ46IHo9IT/CjO+tP+6vskGquOabjIxXVNgjvOnpLBcyrLbntCPFcjBRnSiHT8U\n' +
      'Z2kxxoi1IX2PSN+UZsKJACPlhgKac4Daavzcess7JLdhgheJLNF0zMFq+/ClTFZ9\n' +
      'LrwYFKsFsfVf5XkT8W25xVgCTXmyOkrHM0gAgJF4p60u0rgsAQ14THn64TEfYDmT\n' +
      'Q/Ce45UExmZTJE7J\n' +
      '-----END CERTIFICATE-----\n'
  };

  const SAMPLE_1_EC_CERT = `-----BEGIN CERTIFICATE-----
MIIBnDCCAUmgAwIBAgIIaSktAb0RM30wCgYIKoZIzj0EAwIwEDEOMAwGA1UEAxMF
YWFhYWEwHhcNMjIxMjAyMDIzOTAwWhcNMjMxMjAyMDIzOTAwWjAQMQ4wDAYDVQQD
EwVhYWFhYTBOMBAGByqGSM49AgEGBSuBBAAhAzoABLSp/lbCuQD6LHbnxSQavCQt
P1YRkGQ1rhUJQabJ3IvIBkLBbj3UKyNUkRGb6xrUbvDXuogRPKzjo4GXMIGUMAwG
A1UdEwEB/wQCMAAwHQYDVR0OBBYEFOmyFuoTsO5N2uv6SrHlqsWU+mUtMAsGA1Ud
DwQEAwID6DATBgNVHSUEDDAKBggrBgEFBQcDATAQBgNVHREECTAHggVhYWFhYTAR
BglghkgBhvhCAQEEBAMCBkAwHgYJYIZIAYb4QgENBBEWD3hjYSBjZXJ0aWZpY2F0
ZTAKBggqhkjOPQQDAgNBADA+Ah0A9NE9kPoBcpOMTMa3Djnl1pAwLPblse5pIUqH
IgIdAJu5uwhDBn6tvCuA8woK7uw4qHKjoJ+al38AC7Y=
-----END CERTIFICATE-----`.trim();
  const SAMPLE_1_EC_KEY = '-----BEGIN EC PRIVATE KEY-----\n' +
    'MGgCAQEEHGkVlnf6DSsCM+n81SGwqDdZ/Yr9ETuy1q7WUtigBwYFK4EEACGhPAM6\n' +
    'AAS0qf5WwrkA+ix258UkGrwkLT9WEZBkNa4VCUGmydyLyAZCwW491CsjVJERm+sa\n' +
    '1G7w17qIETys4w==\n' +
    '-----END EC PRIVATE KEY-----'.trim();

  const SAMPLE_2_RSA_CERT = `-----BEGIN CERTIFICATE-----
MIIDGDCCAgCgAwIBAgIILm/rIr/RbhQwDQYJKoZIhvcNAQELBQAwEDEOMAwGA1UE
AxMFYmJiYmIwHhcNMjIxMjAyMDI1MDAwWhcNMjMxMjAyMDI1MDAwWjAQMQ4wDAYD
VQQDEwViYmJiYjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANtPsyq5
XsXS6qxVnTdo0aa+S8EtB8FPCpS+VFYRoeE8dQmfzH66KCc23ZY2U+/2SiQZuyuA
/W/vJPh4c0oJE+wvxJePJhtC3Oft79Mq3ptxx2WV+b8AVjb0JeN0mK+TQ0j8GkP0
awqW/XX0il2//In45T9dSTweh3BnxhvtyJtnzrSX4juPNKbYZiDB4UGwP0XX9DSG
uUNJJURBMB3JeRZVH2853YA3fPhE2AOk1Xup1b7wAMMUzSQPlrbNfQ+DEFgi42CT
r5RHuYNhsPajyRS1B3viVU2OKxDeeDTYjJaWn1fMizlhnO3kgBNXHYMik/3JWVCW
y/jm3VQlN7bGmAcCAwEAAaN2MHQwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUndGJ
1OF99TnS4Xlj1j5FITwnym4wCwYDVR0PBAQDAgPoMBMGA1UdJQQMMAoGCCsGAQUF
BwMBMBAGA1UdEQQJMAeCBWJiYmJiMBEGCWCGSAGG+EIBAQQEAwIGQDANBgkqhkiG
9w0BAQsFAAOCAQEAN88gFkK9q9x0c+hmpM8ihAJxPvlrdTuJpXHoQ3ELHihBds4Y
DBVORdxzsnA/t/wtiHQkfw/lDkr8zKOTRE2uQ9GLDsM0DneA5oxiUfLBVi5WiMG0
JQazOeAwx1bMOiezSuUoe1KencghZeQ49uMXpNQGs5dFMrfI3WqNYc5xVcGSqon9
o8/1QmKrg9XwS+0uIKWPFD5KT0jMw716AdQapSgSTJEEZPIhVi6mFZDNJCowCvvf
y6mJUbBwCM3JwOAF3eEGnFFgyq90VEpMNxPnSTLVNbkL+23qkL+t/v/70bzPAIoJ
kxsiUNvE9sgKP9VwAyhuiCvIFcwyImL9PwnByQ==
-----END CERTIFICATE-----`.trim();
  const SAMPLE_2_RSA_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA20+zKrlexdLqrFWdN2jRpr5LwS0HwU8KlL5UVhGh4Tx1CZ/M
frooJzbdljZT7/ZKJBm7K4D9b+8k+HhzSgkT7C/El48mG0Lc5+3v0yrem3HHZZX5
vwBWNvQl43SYr5NDSPwaQ/RrCpb9dfSKXb/8ifjlP11JPB6HcGfGG+3Im2fOtJfi
O480pthmIMHhQbA/Rdf0NIa5Q0klREEwHcl5FlUfbzndgDd8+ETYA6TVe6nVvvAA
wxTNJA+Wts19D4MQWCLjYJOvlEe5g2Gw9qPJFLUHe+JVTY4rEN54NNiMlpafV8yL
OWGc7eSAE1cdgyKT/clZUJbL+ObdVCU3tsaYBwIDAQABAoIBADzvIwfO418xoBRr
4TfA/udGXkP5H/t826LCUypq0cCEDLy00puvW3Kx0tVmmOHGW4k2QQPwXfpYxrvm
s5mxdgCcsRGvK1ZNuJUUThstARbNgSpfhjmkfU/dfB17iuTVlM9VhHK3GXqiwx+f
50XvDtrC9ecqIyv6C4WWv7uI0MEkjcwr39BrxOLekjtY+Wlt5G6paPLE3SUevjgu
owey0vWS8MtH8wZZ8K/THKSaRlEZUYUU1j5c02u84nuT/K7Jvp/RCDpM9O2+KWIu
O/Ui7qOd9Fjsjnc3DTeAglk3NGcHHljsY3qL+fQo0NAdkXlRONRf7k86m8yKDyjh
m5Li0kECgYEA9lgWbg4H41mjB8hU1yQRuWeBLXTlw9JseA+FJ/+PrHto5IBtter4
t/GIOVcTV9EZjELMCaMKqfDRgb4YYL6qkehgUly3fV0vFs24UdpK4l6XALVjfuzL
ZZczzTrHQ8K/SIbz5ESozWCVQV3JSTyBtuOL9+6tEgkUEiBhAT0h12cCgYEA4+ha
4E0jl8jLZ5G6Ogl/HfqZiKz2B+aJioJtLAGE9p8yt34FGm8BWGyKbDTUQhQ8bjq/
RTS4KaGZ6X6gcLNzCdoCMmEf9Qx/Chg01a3RLdBim09qz9uZ1vFayW61BVAhGfCY
Xm0zdEsRHmN46ks63Ruw8x2Z/1gLbXUvqMDx9mECgYBp21x4GmtlVOVruLhMYuGC
7GlkITGCvm+CABlWIMmacsWWO2HppHkQgifpi/Nx7xatYR7QnVE9yZAd0pQjLouZ
e2O4wMLQijRr9ibYdZdsQv1cfpWsuxCELT9DV5i9E3ijL+qqEp7+8hvxJN4ULH4J
GyrQda3FbEVFrMhCggSCzQKBgQC3DB85OhuVREvCYnQdOxVi4azA7pIopEvh+IFw
r8O4RQL6B3hX08JT39GJuSCl9hTXP83x6rbjkQzKUc7Q1gBWcEgFaKa/LYs3c1u0
J4fzcQRR04ZpbepwjacqVAWGP+ZmLCxk4vZJuCUGsEQkgcnEXwJPMX5HbNK41j8y
Hc344QKBgQDVV8o0HKzLBXdmKhlx9OJIH9QeFlE8jaVVo0M/JM/O4UuAK+OVTvOQ
C1n9yZSmVt8K0CW8te9ibDua3IBow09ixo7P3CM4Xkgs7KWXjQJ18fvJ1Ex4pIcD
RntwM3puA0UzxXtC0emoTP3LKIcAXUmXAGsh6Dx+gb5fmZTprIa4pg==
-----END RSA PRIVATE KEY-----`.trim();

  it('TestCA-EC-SHA256: PEM to PublicKey Object', function () {
    const certPem = testCerts['TestCA-EC-SHA256'];
    const publicKey = cc.createAsymmetricKey({
      format: 'pem',
      key: certPem
    });
    should.exist(publicKey);
    expect(publicKey.isPublic()).to.true;
    expect(publicKey.isPrivate()).to.false;
    expect(publicKey.isSecret()).to.false;
  });

  it('TestCA-RSA-SHA256: PEM to PublicKey Object', function () {
    const certPem = testCerts['TestCA-RSA-SHA256'];
    const publicKey = cc.createAsymmetricKey({
      format: 'pem',
      key: certPem
    });
    should.exist(publicKey);
    expect(publicKey.isPublic()).to.true;
    expect(publicKey.isPrivate()).to.false;
    expect(publicKey.isSecret()).to.false;
  });

  it('Test1_of_TestCA-EC-SHA256: PEM to PublicKey Object', function () {
    const certPem = testCerts['Test1_of_TestCA-EC-SHA256'];
    const publicKey = cc.createAsymmetricKey({
      format: 'pem',
      key: certPem
    });
    should.exist(publicKey);
    expect(publicKey.isPublic()).to.true;
    expect(publicKey.isPrivate()).to.false;
    expect(publicKey.isSecret()).to.false;
  });

  it('Test1_of_TestCA-RSA-SHA256: PEM to PublicKey Object', function () {
    const certPem = testCerts['Test1_of_TestCA-RSA-SHA256'];
    const publicKey = cc.createAsymmetricKey({
      format: 'pem',
      key: certPem
    });
    should.exist(publicKey);
    expect(publicKey.isPublic()).to.true;
    expect(publicKey.isPrivate()).to.false;
    expect(publicKey.isSecret()).to.false;
  });

  it('Test1_of_TestCA-EC-SHA256: PEM to Certificate Object', function () {
    const certPem = testCerts['Test1_of_TestCA-EC-SHA256'];
    const publicKey = cc.createCertificate({
      format: 'pem',
      key: certPem
    });
    should.exist(publicKey);
    expect(publicKey.isPublic()).to.true;
    expect(publicKey.isPrivate()).to.false;
    expect(publicKey.isSecret()).to.false;
  });

  it('Test1_of_TestCA-RSA-SHA256: PEM to Certificate Object', function () {
    const certPem = testCerts['Test1_of_TestCA-RSA-SHA256'];
    const publicKey = cc.createAsymmetricKey({
      format: 'pem',
      key: certPem
    });
    should.exist(publicKey);
    expect(publicKey.isPublic()).to.true;
    expect(publicKey.isPrivate()).to.false;
    expect(publicKey.isSecret()).to.false;
  });

  function toDer(pem: string): Buffer {
    return Buffer.from(
      pem.split('\n')
        .filter(v => !v.startsWith('-'))
        .join(''),
      'base64'
    );
  }

  it('TestCA-EC-SHA256: DER', function () {
    const certPem = testCerts['TestCA-EC-SHA256'];
    const publicKey = cc.createAsymmetricKey({
      key: toDer(certPem)
    });
    should.exist(publicKey);
    expect(publicKey.isPublic()).to.true;
    expect(publicKey.isPrivate()).to.false;
    expect(publicKey.isSecret()).to.false;
  });

  it('TestCA-RSA-SHA256: PEM', function () {
    const certPem = testCerts['TestCA-RSA-SHA256'];
    const publicKey = cc.createAsymmetricKey({
      key: toDer(certPem)
    });
    should.exist(publicKey);
    expect(publicKey.isPublic()).to.true;
    expect(publicKey.isPrivate()).to.false;
    expect(publicKey.isSecret()).to.false;
  });

  it('Test1_of_TestCA-EC-SHA256: PEM', function () {
    const certPem = testCerts['Test1_of_TestCA-EC-SHA256'];
    const publicKey = cc.createAsymmetricKey({
      key: toDer(certPem)
    });
    should.exist(publicKey);
    expect(publicKey.isPublic()).to.true;
    expect(publicKey.isPrivate()).to.false;
    expect(publicKey.isSecret()).to.false;
  });

  it('Test1_of_TestCA-RSA-SHA256: PEM', function () {
    const certPem = testCerts['Test1_of_TestCA-RSA-SHA256'];
    const publicKey = cc.createAsymmetricKey({
      key: toDer(certPem)
    });
    should.exist(publicKey);
    expect(publicKey.isPublic()).to.true;
    expect(publicKey.isPrivate()).to.false;
    expect(publicKey.isSecret()).to.false;
  });

  it('EC Certificate: signature and verify', function () {
    const certificate = cc.createCertificate(SAMPLE_1_EC_CERT);
    const privateKey = cc.createPrivateKey(SAMPLE_1_EC_KEY);

    const signature = privateKey.sign(digestOid, Buffer.from([0x1, 0x1, 0x1, 0x1]));
    const verifySuccess = certificate.verify(digestOid, Buffer.from([0x1, 0x1, 0x1, 0x1]), signature);
    const verifyFailure = certificate.verify(digestOid, Buffer.from([0x1, 0x1, 0x1, 0x2]), signature);

    if (USE_CONSOLE_OUTPUT) {
      console.log(`signature = ${signature.toString('hex')}`);
      console.log(`verifySuccess = ${verifySuccess}`);
      console.log(`verifyFailure = ${verifyFailure}`);
    }

    expect(
      verifySuccess
    ).to.equal(true);

    expect(
      verifyFailure
    ).to.equal(false);
  });

  it('RSA Certificate: signature and verify', function () {
    const certificate = cc.createCertificate(SAMPLE_2_RSA_CERT);
    const privateKey = cc.createPrivateKey(SAMPLE_2_RSA_KEY);

    const signature = privateKey.sign(digestOid, Buffer.from([0x1, 0x1, 0x1, 0x1]));
    const verifySuccess = certificate.verify(digestOid, Buffer.from([0x1, 0x1, 0x1, 0x1]), signature);
    const verifyFailure = certificate.verify(digestOid, Buffer.from([0x1, 0x1, 0x1, 0x2]), signature);

    if (USE_CONSOLE_OUTPUT) {
      console.log(`signature = ${signature.toString('hex')}`);
      console.log(`verifySuccess = ${verifySuccess}`);
      console.log(`verifyFailure = ${verifyFailure}`);
    }

    expect(
      verifySuccess
    ).to.equal(true);

    expect(
      verifyFailure
    ).to.equal(false);
  });
});
