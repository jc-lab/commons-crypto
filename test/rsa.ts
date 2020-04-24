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

describe('RSA', function () {
  const nodePrivKey = crypto.createPrivateKey(`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCz764g9Dr4ZXQDEw8+Il2mbWQ5ACInIBklISsqBmAh5SbnZkqv
cuZ6aj69AHV7IhrDujm730daSH8+wZjHV011V8/sSdK4qvvX0bRql3YUTNQbsBDj
PaV8RRHqHEw/NobbeqtX8QIRvF4eeRyjmLodI1G0N1JinKuM1XYpyKvqlQIDAQAB
AoGAO0CI+acTKCrYag7DrTVJ230YTMDjfjjOrvBeM2eIDoFUL0z6+Q2AIf2MjVZy
WUrgv2U6j8g1yeAnrrW3pqT0B0tQGYYAtAELNe2VZbBBVYQOUS53kq3VowYYMM3z
8R2rEmZTsreFT6uq9+9RMtm5W9ugti//BMte5T8JP5o0l10CQQDntf/ieUmndkGr
t55ROUZZOZJmjr5CTELvjbwnFDx50qh6b1Tzld6l/Gps2b+KxcVswM86Q25PAnbx
VP/rmWoTAkEAxsxMcIcvuDes5A2UcVU7TiyYAsO9vVEfqtDDff50PXd/xNa7ICe0
VtJmVazm8B5K6fVh0Z3EUNff+lRyz61ttwJATmI5D8nr6qSMjqRtABkZ/TEGn38G
SbM2qYcO8UFdO/DRYamr2UMHsKr07aGztCQ3JxUKhTEubbftuLICaRba1QJAfxYL
p8REVVgCRqgHxYvfJdKMOvg3S9eYjvJ2hw0r8j96hrNfXOcE+pv2n76ww8AZ1Aby
Sba50ZSvsrBZ1TnhcQJBAK/jKY+AXaACpoPrradRA80S+WEq8L10o7UYFPxgDdcN
s2QyKSJ2+ZiRXRFpd7L3j6REj+YELpq+10s5lvkgbyU=
-----END RSA PRIVATE KEY-----`);
  const nodePubKey = crypto.createPublicKey(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCz764g9Dr4ZXQDEw8+Il2mbWQ5
ACInIBklISsqBmAh5SbnZkqvcuZ6aj69AHV7IhrDujm730daSH8+wZjHV011V8/s
SdK4qvvX0bRql3YUTNQbsBDjPaV8RRHqHEw/NobbeqtX8QIRvF4eeRyjmLodI1G0
N1JinKuM1XYpyKvqlQIDAQAB
-----END PUBLIC KEY-----`);

  const pubKey = cc.createAsymmetricKeyFromNode(nodePubKey);
  const priKey = cc.createAsymmetricKeyFromNode(nodePrivKey);

  it('signature and verify', function () {
    const signature = priKey.sign(digestOid, Buffer.from([0x1, 0x1, 0x1, 0x1]));
    const verifySuccess = pubKey.verify(digestOid, Buffer.from([0x1, 0x1, 0x1, 0x1]), signature);
    const verifyFailure = pubKey.verify(digestOid, Buffer.from([0x1, 0x1, 0x1, 0x2]), signature);

    if(USE_CONSOLE_OUTPUT) {
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

  it('public encrypt', function () {
    const cipherText = pubKey.publicEncrypt(Buffer.from('test'));
    if(USE_CONSOLE_OUTPUT) {
      console.log(`cipherText = ${cipherText.toString('hex')}`);
    }
    const decryptedText = priKey.privateDecrypt(cipherText).toString('ascii');
    if(USE_CONSOLE_OUTPUT) {
      console.log(`decryptedText = ${decryptedText}`);
    }
    expect(decryptedText).to.equal('test');
  });
});
