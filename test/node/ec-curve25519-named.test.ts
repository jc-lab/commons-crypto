import * as chai from 'chai';
import * as asn1js from 'asn1js';

import * as cc from '../../src/index';
import {AsymmetricAlgorithmType, createAsymmetricAlgorithm} from '../../src/index';

const expect = chai.expect;
const assert = chai.assert;
const should = chai.should();

const USE_CONSOLE_OUTPUT = process.env.USE_CONSOLE_OUTPUT || false;

const digestOid = new asn1js.ObjectIdentifier({
  value: '2.16.840.1.101.3.4.2.1'
});

describe('EC Curve25519 Named Curve', function () {
  const priKeyA = cc.createPrivateKey(`-----BEGIN PRIVATE KEY-----
MIGXAgEAMBUGByqGSM49AgEGCisGAQQBl1UBBQEEezB5AgEBBCAJkuwqEpA3W4PR
7NmkgZJKr+k9GKLYhgIWBXsdh4Rbi6AMBgorBgEEAZdVAQUBoUQDQgAEemaD67XI
UnRNAxpsYS9PcNxniXXYNMHIifK8z6xPWO1Hjfvf0qPbj3dRRBleL/EnnBKbtIk8
phCVN7pKkbZnCg==
-----END PRIVATE KEY-----`);
  const pubKeyA = cc.createPublicKey(`-----BEGIN PUBLIC KEY-----
MFswFQYHKoZIzj0CAQYKKwYBBAGXVQEFAQNCAAR6ZoPrtchSdE0DGmxhL09w3GeJ
ddg0wciJ8rzPrE9Y7UeN+9/So9uPd1FEGV4v8SecEpu0iTymEJU3ukqRtmcK
-----END PUBLIC KEY-----`);

  const priKeyB = cc.createPrivateKey(`-----BEGIN PRIVATE KEY-----
MIGXAgEAMBUGByqGSM49AgEGCisGAQQBl1UBBQEEezB5AgEBBCACPzK2RWUeWAmJ
IRU96fqIWBWhZmARn2exRaKAJA/UR6AMBgorBgEEAZdVAQUBoUQDQgAEU7ZiGIdf
XHHNjT+qW9wFG2Z3jnW5z9ErvaHJyXPUm81ivYgftzA+2ssT+z+6ToZZZbOjWSXE
7FlNHg+mZtcLYQ==
-----END PRIVATE KEY-----`);
  const pubKeyB = cc.createPublicKey(`-----BEGIN PUBLIC KEY-----
MFswFQYHKoZIzj0CAQYKKwYBBAGXVQEFAQNCAARTtmIYh19ccc2NP6pb3AUbZneO
dbnP0Su9ocnJc9SbzWK9iB+3MD7ayxP7P7pOhllls6NZJcTsWU0eD6Zm1wth
-----END PUBLIC KEY-----`);

  it('signature and verify are throw', function () {
    const signatureFn = priKeyA.sign.bind(priKeyA, digestOid, Buffer.from([0x1, 0x1, 0x1, 0x1]));
    const verifyFn = pubKeyA.verify.bind(pubKeyA, digestOid, Buffer.from([0x1, 0x1, 0x1, 0x1]), Buffer.from([]));

    expect(signatureFn).to.throw;
    expect(verifyFn).to.throw;
  });

  it('ECDH', function () {
    const secretA = priKeyA.dhComputeSecret(pubKeyB);
    const secretB = priKeyB.dhComputeSecret(pubKeyA);
    // bc-prov output
    const expectedValue = Buffer.from('0335ebcaf8021d92e2dfb61bfeef85a71bb65707a519be171e3525f689c94c17', 'hex');
    if(USE_CONSOLE_OUTPUT) {
      console.log(`secretA = ${secretA.toString('hex')}`);
      console.log(`secretB = ${secretB.toString('hex')}`);
      console.log(`expectedValue = ${expectedValue.toString('hex')}`);
    }
    expect(secretA).to.eql(secretB);
    expect(secretA).to.eql(expectedValue);
  });

  it('Export sec1 private key', function () {
    //TODO: Need double check
    const exceptValue = `-----BEGIN EC PRIVATE KEY-----
MHkCAQEEIAmS7CoSkDdbg9Hs2aSBkkqv6T0YotiGAhYFex2HhFuLoAwGCisGAQQB
l1UBBQGhRANCAAR6ZoPrtchSdE0DGmxhL09w3GeJddg0wciJ8rzPrE9Y7UeN+9/S
o9uPd1FEGV4v8SecEpu0iTymEJU3ukqRtmcK
-----END EC PRIVATE KEY-----`;

    const output = priKeyA.export({
      type: 'specific',
      format: 'pem'
    });

    if(USE_CONSOLE_OUTPUT) {
      console.log(`output : ${output}`);
    }

    expect(output.trim()).to.equal(exceptValue.trim());
  });

  it('Export spki public key', function () {
    //TODO: Need double check
    const exceptValue = `-----BEGIN PUBLIC KEY-----
MFswFQYHKoZIzj0CAQYKKwYBBAGXVQEFAQNCAAR6ZoPrtchSdE0DGmxhL09w3GeJ
ddg0wciJ8rzPrE9Y7UeN+9/So9uPd1FEGV4v8SecEpu0iTymEJU3ukqRtmcK
-----END PUBLIC KEY-----`;

    const output = pubKeyA.export({
      type: 'specific',
      format: 'pem'
    });

    if(USE_CONSOLE_OUTPUT) {
      console.log(`output : ${output}`);
    }

    expect(output.trim()).to.equal(exceptValue.trim());
  });

  it('Export pkcs8 private key', function () {
    //TODO: Need double check
    const exceptValue = `-----BEGIN PRIVATE KEY-----
MIGJAgEAMBUGByqGSM49AgEGCisGAQQBl1UBBQEEbTBrAgEBBCAJkuwqEpA3W4PR
7NmkgZJKr+k9GKLYhgIWBXsdh4Rbi6FEA0IABHpmg+u1yFJ0TQMabGEvT3DcZ4l1
2DTByInyvM+sT1jtR43739Kj2493UUQZXi/xJ5wSm7SJPKYQlTe6SpG2Zwo=
-----END PRIVATE KEY-----`;

    const output = priKeyA.export({
      type: 'pkcs8',
      format: 'pem'
    });

    if(USE_CONSOLE_OUTPUT) {
      console.log(`output : ${output}`);
    }

    expect(output.trim()).to.equal(exceptValue.trim());
  });
});
