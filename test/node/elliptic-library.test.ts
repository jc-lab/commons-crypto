import * as chai from 'chai';
const expect = chai.expect;
const assert = chai.assert;
const should = chai.should();

import * as crypto from 'crypto';
import * as elliptic from 'elliptic';

import * as cc from '../../src/index';

const USE_CONSOLE_OUTPUT = process.env.USE_CONSOLE_OUTPUT || false;

describe('from elliptic', function () {
  it('p192', function () {
    const ec = new elliptic.ec('p192');
    const kp = ec.genKeyPair();
    const ee = kp.getPrivate().toString('hex');

  });
});
