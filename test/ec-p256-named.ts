const chai = require('chai');
const expect = chai.expect;
const assert = chai.assert;
const should = chai.should();

import * as crypto from 'crypto';
import * as asn1js from 'asn1js';

import * as cc from '../src';

const USE_CONSOLE_OUTPUT = process.env.USE_CONSOLE_OUTPUT || false;

const digestOid = new asn1js.ObjectIdentifier({
  value: '2.16.840.1.101.3.4.2.1'
});

describe('EC SECP-256K1 Named Curve', function () {
  const nodePrivKeyA = crypto.createPrivateKey(`-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgfs82+aZk5zFjAGhT4tO1
q4Mg7Lw3Y3okG1JQzR5Q9wKhRANCAASdmnZ/+ISGZIAPxduEQR/MxzW6epL9zH8/
k0Yn7DPLJiFa5rYZhA62+9jVqGiORPvWWvLvzG7RsjItUFEh8KnI
-----END PRIVATE KEY-----`);
  const nodePubKeyA = crypto.createPublicKey(`-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEnZp2f/iEhmSAD8XbhEEfzMc1unqS/cx/
P5NGJ+wzyyYhWua2GYQOtvvY1ahojkT71lry78xu0bIyLVBRIfCpyA==
-----END PUBLIC KEY-----`);

  const pubKeyA = cc.createAsymmetricKeyFromNode(nodePubKeyA);
  const priKeyA = cc.createAsymmetricKeyFromNode(nodePrivKeyA);

  const nodePrivKeyB = crypto.createPrivateKey(`-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgsaNyOzkvjTjGbUm/YrPR
AStWNros7EfBh/CmyEb7k2mhRANCAASSkcQ4d8u4mBn+zBoEScZ57tPI3C1WNQ9v
nYdvN1tg8CPzwBBXZ+loWHF4qIBMoQVu6BQ+xEmZwYxYmwKub9Vx
-----END PRIVATE KEY-----`);
  const nodePubKeyB = crypto.createPublicKey(`-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEkpHEOHfLuJgZ/swaBEnGee7TyNwtVjUP
b52HbzdbYPAj88AQV2fpaFhxeKiATKEFbugUPsRJmcGMWJsCrm/VcQ==
-----END PUBLIC KEY-----`);

  const pubKeyB = cc.createAsymmetricKeyFromNode(nodePubKeyB);
  const priKeyB = cc.createAsymmetricKeyFromNode(nodePrivKeyB);

  it('signature and verify', function () {
    const signature = priKeyA.sign(digestOid, Buffer.from([0x1, 0x1, 0x1, 0x1]));
    const verifySuccess = pubKeyA.verify(digestOid, Buffer.from([0x1, 0x1, 0x1, 0x1]), signature);
    const verifyFailure = pubKeyA.verify(digestOid, Buffer.from([0x1, 0x1, 0x1, 0x2]), signature);

    if(USE_CONSOLE_OUTPUT) {
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

  it('ECDH', function () {
    const secretA = priKeyA.dhComputeSecret(pubKeyB);
    const secretB = priKeyB.dhComputeSecret(pubKeyA);
    const expectedValue = Buffer.from('91d453f97f586c9ab52bf29a0688856ab6bc236cc9be116e1792dbf13b1037df', 'hex');
    if(USE_CONSOLE_OUTPUT) {
      console.log(`secretA = ${secretA.toString('hex')}`);
      console.log(`secretB = ${secretB.toString('hex')}`);
      console.log(`expectedValue = ${expectedValue.toString('hex')}`);
    }
    expect(secretA.compare(secretB)).to.equal(0);
    expect(secretA.compare(expectedValue)).to.equal(0);
  });

  it('Export sec1 private key', function () {
    const exceptValue = `-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIH7PNvmmZOcxYwBoU+LTtauDIOy8N2N6JBtSUM0eUPcCoAcGBSuBBAAK
oUQDQgAEnZp2f/iEhmSAD8XbhEEfzMc1unqS/cx/P5NGJ+wzyyYhWua2GYQOtvvY
1ahojkT71lry78xu0bIyLVBRIfCpyA==
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
    const exceptValue = `-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEnZp2f/iEhmSAD8XbhEEfzMc1unqS/cx/
P5NGJ+wzyyYhWua2GYQOtvvY1ahojkT71lry78xu0bIyLVBRIfCpyA==
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
    const exceptValue = `-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgfs82+aZk5zFjAGhT4tO1
q4Mg7Lw3Y3okG1JQzR5Q9wKhRANCAASdmnZ/+ISGZIAPxduEQR/MxzW6epL9zH8/
k0Yn7DPLJiFa5rYZhA62+9jVqGiORPvWWvLvzG7RsjItUFEh8KnI
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

  it('Import sec1 private key - same - pem', function () {
    const algorithm = priKeyA.getKeyAlgorithm();

    const importedKey = algorithm.keyImport(`-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIH7PNvmmZOcxYwBoU+LTtauDIOy8N2N6JBtSUM0eUPcCoAcGBSuBBAAK
oUQDQgAEnZp2f/iEhmSAD8XbhEEfzMc1unqS/cx/P5NGJ+wzyyYhWua2GYQOtvvY
1ahojkT71lry78xu0bIyLVBRIfCpyA==
-----END EC PRIVATE KEY-----`, { format: 'pem' });

    expect(importedKey.equals(priKeyA)).to.equal(true);
  });

  it('Import sec1 private key - same - der', function () {
    const algorithm = priKeyA.getKeyAlgorithm();

    const importedKey = algorithm.keyImport(
      Buffer.from(`MHQCAQEEIH7PNvmmZOcxYwBoU+LTtauDIOy8N2N6JBtSUM0eUPcCoAcGBSuBBAAKoUQDQgAEnZp2f/iEhmSAD8XbhEEfzMc1unqS/cx/P5NGJ+wzyyYhWua2GYQOtvvY1ahojkT71lry78xu0bIyLVBRIfCpyA==`, 'base64')
      , { format: 'der' });

    expect(importedKey.equals(priKeyA)).to.equal(true);
  });

  it('Import sec1 private key - diff - pem', function () {
    const algorithm = priKeyA.getKeyAlgorithm();

    const importedKey = algorithm.keyImport(`-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIH7PNvmmZOcxYwBoU+LTtauDIOy8N2N6JBtSUM0eUPcCoAcGBSuBBAAK
oUQDQgAEnZp2f/iEhmSAD8XbhEEfzMc1unqS/cx/P5NGJ+wzyyYhWua2GYQOtvvY
1ahojkT71lry78xu0bIyLVBRIfCpyA==
-----END EC PRIVATE KEY-----`, { format: 'pem' });

    expect(importedKey.equals(priKeyB)).to.not.equals(true);
  });

  it('Import pkcs8 private key - same - pem', function () {
    const algorithm = priKeyA.getKeyAlgorithm();

    const importedKey = algorithm.keyImport(`-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgfs82+aZk5zFjAGhT4tO1
q4Mg7Lw3Y3okG1JQzR5Q9wKhRANCAASdmnZ/+ISGZIAPxduEQR/MxzW6epL9zH8/
k0Yn7DPLJiFa5rYZhA62+9jVqGiORPvWWvLvzG7RsjItUFEh8KnI
-----END PRIVATE KEY-----`, { format: 'pem' });

    expect(importedKey.equals(priKeyA)).to.equals(true);
  });

  it('Import pkcs8 private key - same - der', function () {
    const algorithm = priKeyA.getKeyAlgorithm();

    const importedKey = algorithm.keyImport(
      Buffer.from(`MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgfs82+aZk5zFjAGhT4tO1q4Mg7Lw3Y3okG1JQzR5Q9wKhRANCAASdmnZ/+ISGZIAPxduEQR/MxzW6epL9zH8/k0Yn7DPLJiFa5rYZhA62+9jVqGiORPvWWvLvzG7RsjItUFEh8KnI`, 'base64')
      , { format: 'der' });

    expect(importedKey.equals(priKeyA)).to.equals(true);
  });

  it('Import pkcs8 private key - diff - pem', function () {
    const algorithm = priKeyA.getKeyAlgorithm();

    const importedKey = algorithm.keyImport(`-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgfs82+aZk5zFjAGhT4tO1
q4Mg7Lw3Y3okG1JQzR5Q9wKhRANCAASdmnZ/+ISGZIAPxduEQR/MxzW6epL9zH8/
k0Yn7DPLJiFa5rYZhA62+9jVqGiORPvWWvLvzG7RsjItUFEh8KnI
-----END PRIVATE KEY-----`, { format: 'pem' });

    expect(importedKey.equals(priKeyB)).to.not.equals(true);
  });

  it('Import spki public key - same - pem', function () {
    const algorithm = priKeyA.getKeyAlgorithm();

    const importedKey = algorithm.keyImport(`-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEnZp2f/iEhmSAD8XbhEEfzMc1unqS/cx/
P5NGJ+wzyyYhWua2GYQOtvvY1ahojkT71lry78xu0bIyLVBRIfCpyA==
-----END PUBLIC KEY-----`, { format: 'pem' });

    expect(importedKey.equals(priKeyA)).to.equal(true);
  });

  it('Import spki public key - same - der', function () {
    const algorithm = priKeyA.getKeyAlgorithm();

    const importedKey = algorithm.keyImport(
      Buffer.from(`MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEnZp2f/iEhmSAD8XbhEEfzMc1unqS/cx/P5NGJ+wzyyYhWua2GYQOtvvY1ahojkT71lry78xu0bIyLVBRIfCpyA==`, 'base64')
      , { format: 'der' });

    expect(importedKey.equals(priKeyA)).to.equal(true);
  });

  it('Import spki public key - diff - pem', function () {
    const algorithm = priKeyA.getKeyAlgorithm();

    const importedKey = algorithm.keyImport(`-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEnZp2f/iEhmSAD8XbhEEfzMc1unqS/cx/
P5NGJ+wzyyYhWua2GYQOtvvY1ahojkT71lry78xu0bIyLVBRIfCpyA==
-----END PUBLIC KEY-----`, { format: 'pem' });

    expect(importedKey.equals(priKeyB)).to.equal(false);
  });

  it('Key generate', function () {
    const algorithm = priKeyA.getKeyAlgorithm();

    const { privateKey, publicKey } = algorithm.generateKeyPair();

    const privateKeyPem = privateKey.export({
      type: 'specific',
      format: 'pem'
    });
    const publicKeyPem = publicKey.export({
      type: 'specific',
      format: 'pem'
    });

    expect(privateKeyPem.startsWith('-----BEGIN EC PRIVATE KEY-----')).to.equal(true);
    expect(publicKeyPem.startsWith('-----BEGIN PUBLIC KEY-----')).to.equal(true);

    if(USE_CONSOLE_OUTPUT) {
      console.log('generated private key :', privateKeyPem);
      console.log('generated public key :', publicKeyPem);
    }
  });
});
