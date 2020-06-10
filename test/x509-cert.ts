import * as asn1js from 'asn1js';
import PkijsCertificate from 'pkijs/build/Certificate';

const chai = require('chai');
const expect = chai.expect;
const assert = chai.assert;
const should = chai.should();

import * as cc from '../src';

const USE_CONSOLE_OUTPUT = process.env.USE_CONSOLE_OUTPUT || false;

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

  it('TestCA-EC-SHA256: PEM', function () {
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

  it('TestCA-RSA-SHA256: PEM', function () {
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

  it('Test1_of_TestCA-EC-SHA256: PEM', function () {
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

  it('Test1_of_TestCA-RSA-SHA256: PEM', function () {
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

});
