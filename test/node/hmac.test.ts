import chai from 'chai';
const expect = chai.expect;
const assert = chai.assert;
const should = chai.should();

import * as cc from '../../src/index';

const USE_CONSOLE_OUTPUT = process.env.USE_CONSOLE_OUTPUT || false;

interface TestVector {
  key: Buffer;
  message: Buffer;
}

describe('HMAC', function () {
  // https://tools.ietf.org/html/rfc4231
  const testVectors: TestVector[] = [
    {
      key: Buffer.from('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'hex'),
      message: Buffer.from('4869205468657265', 'hex')
    },
    {
      key: Buffer.from('4a656665', 'hex'),
      message: Buffer.from('7768617420646f2079612077616e7420666f72206e6f7468696e673f', 'hex')
    },
    {
      key: Buffer.from('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'hex'),
      message: Buffer.from('dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', 'hex')
    },
    {
      key: Buffer.from('0102030405060708090a0b0c0d0e0f10111213141516171819', 'hex'),
      message: Buffer.from('cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd', 'hex')
    }
  ];

  it('HMAC-SHA-224 Test Cases', () => {
    const algo = 'hmac-with-sha-224';
    const expectedValues: Buffer[] = [
      Buffer.from('896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22', 'hex'),
      Buffer.from('a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44', 'hex'),
      Buffer.from('7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea', 'hex'),
      Buffer.from('6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a', 'hex')
    ];
    testVectors.forEach((item, index) => {
      const hmac = cc.createHmac(algo);
      if (!hmac) {
        throw new Error('hmac is null');
      }
      hmac.init(item.key);
      hmac.update(item.message);
      const output = hmac.digest();
      expect(output, `Test Case ${index + 1}`).eql(expectedValues[index]);
    });
  });
  it('HMAC-SHA-256 Test Cases', () => {
    const algo = 'hmac-with-sha-256';
    const expectedValues: Buffer[] = [
      Buffer.from('b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7', 'hex'),
      Buffer.from('5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843', 'hex'),
      Buffer.from('773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe', 'hex'),
      Buffer.from('82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b', 'hex')
    ];
    testVectors.forEach((item, index) => {
      const hmac = cc.createHmac(algo);
      if (!hmac) {
        throw new Error('hmac is null');
      }
      hmac.init(item.key);
      hmac.update(item.message);
      const output = hmac.digest();
      expect(output, `Test Case ${index + 1}`).eql(expectedValues[index]);
    });
  });
});
