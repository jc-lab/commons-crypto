import * as crypto from 'crypto';

const chai = require('chai');
const expect = chai.expect;
const assert = chai.assert;
const should = chai.should();

import * as cc from '../../src/index';

const USE_CONSOLE_OUTPUT = process.env.USE_CONSOLE_OUTPUT || false;

describe('EC Explicit Create Key', function () {
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

  const pubKey = cc.createAsymmetricKeyFromNode(nodePubKeyA);
  const priKey = cc.createAsymmetricKeyFromNode(nodePrivKeyA);

  it('SEC1 PEM Private Key', function () {
    const experimentalKey = cc.createAsymmetricKey({
      key: `-----BEGIN EC PRIVATE KEY-----
MIIBUQIBAQQgMPsNvVk3fgbiUKwiYpF4xPGvSd2mi73DSgxf+G+JxzqggeMwgeAC
AQEwLAYHKoZIzj0BAQIhAP////////////////////////////////////7///wv
MEQEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAABwRBBHm+Zn753LusVaBilc6HCwcCm/zbLc4o
2VnygVsW+BeYSDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj/sQ1LgCIQD/////
///////////////+uq7c5q9IoDu/0l6M0DZBQQIBAaFEA0IABEGhViBZ3W/VBcWA
luZLlquzpGz8Ud4X+zx0zj/WN2o493pwAADi/ioh6kfwOzjoQPcKbcMUV7/PxKDv
j/VGZvA=
-----END EC PRIVATE KEY-----`
    });
    expect(priKey.equals(experimentalKey)).to.equals(true);
  });

  it('SEC1 DER Private Key', function () {
    const experimentalKey = cc.createAsymmetricKey({
      key: Buffer.from(`MIIBUQIBAQQgMPsNvVk3fgbiUKwiYpF4xPGvSd2mi73DSgxf+G+JxzqggeMwgeAC
AQEwLAYHKoZIzj0BAQIhAP////////////////////////////////////7///wv
MEQEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAABwRBBHm+Zn753LusVaBilc6HCwcCm/zbLc4o
2VnygVsW+BeYSDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj/sQ1LgCIQD/////
///////////////+uq7c5q9IoDu/0l6M0DZBQQIBAaFEA0IABEGhViBZ3W/VBcWA
luZLlquzpGz8Ud4X+zx0zj/WN2o493pwAADi/ioh6kfwOzjoQPcKbcMUV7/PxKDv
j/VGZvA=`, 'base64')
    });
    expect(priKey.equals(experimentalKey)).to.equals(true);
  });

  it('PKCS8 PEM Private Key', function () {
    const experimentalKey = cc.createAsymmetricKey({
      key: `-----BEGIN PRIVATE KEY-----
MIIBYQIBADCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA////////////
/////////////////////////v///C8wRAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHBEEE
eb5mfvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5hIOtp3JqPEZV2k+/wOEQio
/Re0SKaFVBmcR9CP+xDUuAIhAP////////////////////66rtzmr0igO7/SXozQ
NkFBAgEBBG0wawIBAQQgMPsNvVk3fgbiUKwiYpF4xPGvSd2mi73DSgxf+G+Jxzqh
RANCAARBoVYgWd1v1QXFgJbmS5ars6Rs/FHeF/s8dM4/1jdqOPd6cAAA4v4qIepH
8Ds46ED3Cm3DFFe/z8Sg74/1Rmbw
-----END PRIVATE KEY-----`
    });
    expect(priKey.equals(experimentalKey)).to.equals(true);
  });

  it('PKCS8 DER Private Key', function () {
    const experimentalKey = cc.createAsymmetricKey({
      key: Buffer.from(`MIIBYQIBADCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA////////////
/////////////////////////v///C8wRAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHBEEE
eb5mfvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5hIOtp3JqPEZV2k+/wOEQio
/Re0SKaFVBmcR9CP+xDUuAIhAP////////////////////66rtzmr0igO7/SXozQ
NkFBAgEBBG0wawIBAQQgMPsNvVk3fgbiUKwiYpF4xPGvSd2mi73DSgxf+G+Jxzqh
RANCAARBoVYgWd1v1QXFgJbmS5ars6Rs/FHeF/s8dM4/1jdqOPd6cAAA4v4qIepH
8Ds46ED3Cm3DFFe/z8Sg74/1Rmbw`, 'base64')
    });
    expect(priKey.equals(experimentalKey)).to.equals(true);
  });

  it('SPKI PEM Public Key', function () {
    const experimentalKey = cc.createAsymmetricKey({
      key: `-----BEGIN PUBLIC KEY-----
MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA////////////////
/////////////////////v///C8wRAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHBEEEeb5m
fvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5hIOtp3JqPEZV2k+/wOEQio/Re0
SKaFVBmcR9CP+xDUuAIhAP////////////////////66rtzmr0igO7/SXozQNkFB
AgEBA0IABEGhViBZ3W/VBcWAluZLlquzpGz8Ud4X+zx0zj/WN2o493pwAADi/ioh
6kfwOzjoQPcKbcMUV7/PxKDvj/VGZvA=
-----END PUBLIC KEY-----`
    });
    expect(pubKey.equals(experimentalKey)).to.equals(true);
  });

  it('SPKI DER Public Key', function () {
    const experimentalKey = cc.createAsymmetricKey({
      key: Buffer.from(`MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA////////////////
/////////////////////v///C8wRAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHBEEEeb5m
fvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5hIOtp3JqPEZV2k+/wOEQio/Re0
SKaFVBmcR9CP+xDUuAIhAP////////////////////66rtzmr0igO7/SXozQNkFB
AgEBA0IABEGhViBZ3W/VBcWAluZLlquzpGz8Ud4X+zx0zj/WN2o493pwAADi/ioh
6kfwOzjoQPcKbcMUV7/PxKDvj/VGZvA=`, 'base64')
    });
    expect(pubKey.equals(experimentalKey)).to.equals(true);
  });
});
