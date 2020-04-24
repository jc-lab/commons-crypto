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

  it('Export private key', function () {
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
      console.log(`tqoutput : ${output}`);
    }

    expect(output.trim()).to.equal(exceptValue.trim());
  });

  it('Export public key', function () {
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

describe('EC SECP-256K1 Explicit Curve', function () {
  const nodePrivKeyA = crypto.createPrivateKey(`-----BEGIN EC PRIVATE KEY-----
MIIBEwIBAQQgMPsNvVk3fgbiUKwiYpF4xPGvSd2mi73DSgxf+G+JxzqggaUwgaIC
AQEwLAYHKoZIzj0BAQIhAP////////////////////////////////////7///wv
MAYEAQAEAQcEQQR5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmEg62ncm
o8RlXaT7/A4RCKj9F7RIpoVUGZxH0I/7ENS4AiEA/////////////////////rqu
3OavSKA7v9JejNA2QUECAQGhRANCAARBoVYgWd1v1QXFgJbmS5ars6Rs/FHeF/s8
dM4/1jdqOPd6cAAA4v4qIepH8Ds46ED3Cm3DFFe/z8Sg74/1Rmbw
-----END EC PRIVATE KEY-----`);
  const nodePubKeyA = crypto.createPublicKey(`-----BEGIN PUBLIC KEY-----
MIH1MIGuBgcqhkjOPQIBMIGiAgEBMCwGByqGSM49AQECIQD/////////////////
///////////////////+///8LzAGBAEABAEHBEEEeb5mfvncu6xVoGKVzocLBwKb
/NstzijZWfKBWxb4F5hIOtp3JqPEZV2k+/wOEQio/Re0SKaFVBmcR9CP+xDUuAIh
AP////////////////////66rtzmr0igO7/SXozQNkFBAgEBA0IABEGhViBZ3W/V
BcWAluZLlquzpGz8Ud4X+zx0zj/WN2o493pwAADi/ioh6kfwOzjoQPcKbcMUV7/P
xKDvj/VGZvA=
-----END PUBLIC KEY-----`);

  const pubKeyA = cc.createAsymmetricKeyFromNode(nodePubKeyA);
  const priKeyA = cc.createAsymmetricKeyFromNode(nodePrivKeyA);

  const nodePrivKeyB = crypto.createPrivateKey(`-----BEGIN EC PRIVATE KEY-----
MIIBEwIBAQQgmYQ6wvQjNAMpbcXVbjxxIeQzll/tVja8Pu3S5Cs/oX2ggaUwgaIC
AQEwLAYHKoZIzj0BAQIhAP////////////////////////////////////7///wv
MAYEAQAEAQcEQQR5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmEg62ncm
o8RlXaT7/A4RCKj9F7RIpoVUGZxH0I/7ENS4AiEA/////////////////////rqu
3OavSKA7v9JejNA2QUECAQGhRANCAARo8jkeK16DrigqwwCm9EImjB6xGN7AQJHx
TBy95IhHPy7PcJGCAb+9GglT4sQIPjV/VB1srsYpB5FTn0iYeg1L
-----END EC PRIVATE KEY-----`);
  const nodePubKeyB = crypto.createPublicKey(`-----BEGIN PUBLIC KEY-----
MIH1MIGuBgcqhkjOPQIBMIGiAgEBMCwGByqGSM49AQECIQD/////////////////
///////////////////+///8LzAGBAEABAEHBEEEeb5mfvncu6xVoGKVzocLBwKb
/NstzijZWfKBWxb4F5hIOtp3JqPEZV2k+/wOEQio/Re0SKaFVBmcR9CP+xDUuAIh
AP////////////////////66rtzmr0igO7/SXozQNkFBAgEBA0IABGjyOR4rXoOu
KCrDAKb0QiaMHrEY3sBAkfFMHL3kiEc/Ls9wkYIBv70aCVPixAg+NX9UHWyuxikH
kVOfSJh6DUs=
-----END PUBLIC KEY-----`);

  const pubKeyB = cc.createAsymmetricKeyFromNode(nodePubKeyB);
  const priKeyB = cc.createAsymmetricKeyFromNode(nodePrivKeyB);

  it('signature and verify', function () {
    const presigned = Buffer.from('30450221008C50962AE3210AB6A497C041A20834BFDE93CD4F829863A48490C551223014BE0220652D0A443E96A15A2A6FCC584A15F1BC13B137A868414A6C9B4686AC0410B81F', 'hex');

    const signature = priKeyA.sign(digestOid, Buffer.from([0x1, 0x1, 0x1, 0x1]));
    const verifySuccess = pubKeyA.verify(digestOid, Buffer.from([0x1, 0x1, 0x1, 0x1]), signature);
    const verifyFailure = pubKeyA.verify(digestOid, Buffer.from([0x1, 0x1, 0x1, 0x2]), signature);
    const verifyPresigned = pubKeyA.verify(digestOid, Buffer.from([0x1, 0x1, 0x1, 0x1]), presigned);

    if(USE_CONSOLE_OUTPUT) {
      console.log(`signature = ${signature.toString('hex')}`);
      console.log(`verifyPresigned = ${verifyPresigned}`);
      console.log(`verifySuccess = ${verifySuccess}`);
      console.log(`verifyFailure = ${verifyFailure}`);
    }

    expect(
      verifyPresigned
    ).to.equal(true);

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
    const expectedValue = Buffer.from('1531b52ac674ca0af7dea5af190d65f86b4a6c67bfa0b07b3884d563ba5acdc2', 'hex');
    if(USE_CONSOLE_OUTPUT) {
      console.log(`secretA = ${secretA.toString('hex')}`);
      console.log(`secretB = ${secretB.toString('hex')}`);
      console.log(`expectedValue = ${expectedValue.toString('hex')}`);
    }
    expect(secretA.compare(secretB)).to.equal(0);
    expect(secretA.compare(expectedValue)).to.equal(0);
  });

  it('Export private key', function () {
    const exceptValue = `-----BEGIN EC PRIVATE KEY-----
MIIBUQIBAQQgMPsNvVk3fgbiUKwiYpF4xPGvSd2mi73DSgxf+G+JxzqggeMwgeAC
AQEwLAYHKoZIzj0BAQIhAP////////////////////////////////////7///wv
MEQEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAABwRBBHm+Zn753LusVaBilc6HCwcCm/zbLc4o
2VnygVsW+BeYSDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj/sQ1LgCIQD/////
///////////////+uq7c5q9IoDu/0l6M0DZBQQIBAaFEA0IABEGhViBZ3W/VBcWA
luZLlquzpGz8Ud4X+zx0zj/WN2o493pwAADi/ioh6kfwOzjoQPcKbcMUV7/PxKDv
j/VGZvA=
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

  it('Export public key', function () {
    const exceptValue = `-----BEGIN PUBLIC KEY-----
MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA////////////////
/////////////////////v///C8wRAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHBEEEeb5m
fvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5hIOtp3JqPEZV2k+/wOEQio/Re0
SKaFVBmcR9CP+xDUuAIhAP////////////////////66rtzmr0igO7/SXozQNkFB
AgEBA0IABEGhViBZ3W/VBcWAluZLlquzpGz8Ud4X+zx0zj/WN2o493pwAADi/ioh
6kfwOzjoQPcKbcMUV7/PxKDvj/VGZvA=
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
