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

describe('EC Curve25519 OpenSSL Named Curve', function () {
  const priKeyA = cc.createPrivateKey(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIJAcewan21g2T/B9H+yDfrpOriIpvy8Gd5NLtI1LyXd/
-----END PRIVATE KEY-----`);
  const pubKeyA = cc.createPublicKey(`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VuAyEAhH1G/0aHz996HrKvoaG5IKz6agr6nhWp/Oor/YFTDQU=
-----END PUBLIC KEY-----`);

  const priKeyB = cc.createPrivateKey(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEICjbaFgXrrA2P/8c6wDOHHlg7tKwTKqVqGwOdfy0wRNI
-----END PRIVATE KEY-----`);
  const pubKeyB = cc.createPublicKey(`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VuAyEAtZJdjBkGE7WWPLJi23iFFiweY8D1qcU/uQdi9eH0SiE=
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
    const expectedValue = Buffer.from('4ff6d5e5be76a8824ac2a4a78f9c268aee03dcbccf64811f62c11b588bb0243d', 'hex');
    if (USE_CONSOLE_OUTPUT) {
      console.log(`secretA = ${secretA.toString('hex')}`);
      console.log(`secretB = ${secretB.toString('hex')}`);
      console.log(`expectedValue = ${expectedValue.toString('hex')}`);
    }
    expect(secretA).to.eql(secretB);
    expect(secretA).to.eql(expectedValue);
  });
});
