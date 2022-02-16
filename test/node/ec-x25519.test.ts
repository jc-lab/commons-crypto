import * as chai from 'chai';
import * as asn1js from 'asn1js';

import * as cc from '../../src/index';
import {AsymmetricAlgorithmType, createAsymmetricAlgorithm} from '../../src/index';

const expect = chai.expect;
const assert = chai.assert;
const should = chai.should();

const USE_CONSOLE_OUTPUT = true; // process.env.USE_CONSOLE_OUTPUT || false;

const digestOid = new asn1js.ObjectIdentifier({
  value: '2.16.840.1.101.3.4.2.1'
});

describe('EC X25519 Curve', function () {
  // https://tools.ietf.org/html/rfc7748#section-6.1

  const aliceSecretKey = cc.createPrivateKey(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIHcHbQpzGKV9PBbBclGyZkXfTC+H68CZKrF3+6UduSwq
-----END PRIVATE KEY-----`) as cc.EllipticKeyObject;
  const alicePublicKey = cc.createPublicKey(`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VuAyEAhSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=
-----END PUBLIC KEY-----`) as cc.EllipticKeyObject;

  const bobSecretKey = cc.createPrivateKey(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIF2rCH5iSopLeeF/i4OADuZvO7EpJhi2/Rwviyf/iODr
-----END PRIVATE KEY-----`) as cc.EllipticKeyObject;
  const bobPublicKey = cc.createPublicKey(`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VuAyEA3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=
-----END PUBLIC KEY-----`) as cc.EllipticKeyObject;
  const expectedSsharedKey = Buffer.from('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742', 'hex');

  it('convert to public key', function () {
    console.log('aliceSecretKey to public(LE) : ', Buffer.from(aliceSecretKey.getECKeyPair().getPublic('array')).reverse().toString('hex'));
    console.log('alicePublicKey to public(LE) : ', Buffer.from(alicePublicKey.getECKeyPair().getPublic('array')).reverse().toString('hex'));
    expect(aliceSecretKey.getECKeyPair().getPublic().encode('hex', true)).eql(alicePublicKey.getECKeyPair().getPublic().encode('hex', true));
  });

  it('sign should throw', function () {
    const sign = aliceSecretKey.sign.bind(aliceSecretKey, digestOid, Buffer.from([0x1, 0x1, 0x1, 0x1]));
    expect(sign).to.throw;
  });

  it('ECDH 1', function () {
    const secretA = aliceSecretKey.dhComputeSecret(bobSecretKey.toPublicKey());
    const secretB = bobSecretKey.dhComputeSecret(aliceSecretKey.toPublicKey());
    if (USE_CONSOLE_OUTPUT) {
      console.log(`secretA = ${secretA.toString('hex')}`);
      console.log(`secretB = ${secretB.toString('hex')}`);
      console.log(`expectedValue = ${expectedSsharedKey.toString('hex')}`);
    }
    expect(secretA.compare(secretB)).to.equal(0);
    expect(secretA.compare(expectedSsharedKey)).to.equal(0);
  });

  it('ECDH 2', function () {
    const secretA = aliceSecretKey.dhComputeSecret(bobPublicKey);
    const secretB = bobSecretKey.dhComputeSecret(alicePublicKey);
    if (USE_CONSOLE_OUTPUT) {
      console.log(`secretA = ${secretA.toString('hex')}`);
      console.log(`secretB = ${secretB.toString('hex')}`);
      console.log(`expectedValue = ${expectedSsharedKey.toString('hex')}`);
    }
    expect(secretA.compare(secretB)).to.equal(0);
    expect(secretA.compare(expectedSsharedKey)).to.equal(0);
  });

  it('ECDH with generated key', function () {
    const algorithm = createAsymmetricAlgorithm(AsymmetricAlgorithmType.x25519);

    type OutType = {
      privateKey: cc.EllipticKeyObject;
      publicKey: cc.EllipticKeyObject;
    };

    const { privateKey: priKeyA, publicKey: pubKeyA } = algorithm.generateKeyPair() as OutType;
    const { privateKey: priKeyB, publicKey: pubKeyB } = algorithm.generateKeyPair() as OutType;

    const secretA = priKeyA.dhComputeSecret(pubKeyB);
    const secretB = priKeyB.dhComputeSecret(pubKeyA);

    if (USE_CONSOLE_OUTPUT) {
      console.log('priv key : ', priKeyA.getECKeyPair().getPrivate().toString('hex'));
      console.log(`A: private key: ${priKeyA.export({format: 'pem', type: 'pkcs8'})}`);
      console.log(`A: public key: ${pubKeyA.export({format: 'pem', type: 'spki'})}`);
      console.log(`B: private key: ${priKeyB.export({format: 'pem', type: 'pkcs8'})}`);
      console.log(`B: public key: ${pubKeyB.export({format: 'pem', type: 'spki'})}`);
      console.log(`secretA = ${secretA.toString('hex')}`);
      console.log(`secretB = ${secretB.toString('hex')}`);
    }
    expect(secretA.compare(secretB)).to.equal(0);
  });

  it('Export spki public key', function () {
    const exceptValue = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VuAyEAhSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=
-----END PUBLIC KEY-----`;

    const output = alicePublicKey.export({
      type: 'spki',
      format: 'pem'
    });

    if (USE_CONSOLE_OUTPUT) {
      console.log(`output : ${output}`);
    }

    expect(output.trim()).to.equal(exceptValue.trim());
  });

  it('Export pkcs8 private key', function () {
    const exceptValue = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIHAHbQpzGKV9PBbBclGyZkXfTC+H68CZKrF3+6UduSxq
-----END PRIVATE KEY-----`;

    const output = aliceSecretKey.export({
      type: 'pkcs8',
      format: 'pem'
    });

    if (USE_CONSOLE_OUTPUT) {
      console.log(`output : ${output}`);
    }

    expect(output.trim()).to.equal(exceptValue.trim());
  });

  it('Key generate 1', function () {
    const algorithm = aliceSecretKey.getKeyAlgorithm();

    const { privateKey, publicKey } = algorithm.generateKeyPair();

    const privateKeyPem = privateKey.export({
      type: 'pkcs8',
      format: 'pem'
    });
    const publicKeyPem = publicKey.export({
      type: 'specific',
      format: 'pem'
    });

    expect(privateKeyPem.startsWith('-----BEGIN PRIVATE KEY-----')).to.equal(true);
    expect(publicKeyPem.startsWith('-----BEGIN PUBLIC KEY-----')).to.equal(true);

    if (USE_CONSOLE_OUTPUT) {
      console.log('generated private key :', privateKeyPem);
      console.log('generated public key :', publicKeyPem);
    }
  });

  it('Key generate by name', function () {
    const algorithm = createAsymmetricAlgorithm(AsymmetricAlgorithmType.x25519);

    const { privateKey, publicKey } = algorithm.generateKeyPair();

    const privateKeyPem = privateKey.export({
      type: 'pkcs8',
      format: 'pem'
    });
    const publicKeyPem = publicKey.export({
      type: 'specific',
      format: 'pem'
    });

    expect(privateKeyPem.startsWith('-----BEGIN PRIVATE KEY-----')).to.equal(true);
    expect(publicKeyPem.startsWith('-----BEGIN PUBLIC KEY-----')).to.equal(true);

    if (USE_CONSOLE_OUTPUT) {
      console.log('generated private key :', privateKeyPem);
      console.log('generated public key :', publicKeyPem);
    }
  });
});
