import * as randomBytes from 'randombytes';
import * as createHash from 'create-hash';
import * as crt from 'browserify-rsa';

import * as BN from 'bn.js';

import {
  mgf
} from './mgf';
import {
  xor
} from './xor';
import {
  withPublic
} from './with-public';

import {arrayBufferToBuffer} from '../../../utils';
import {BNRSAPublicKey} from '../../asym-key/rsa';

export function publicEncrypt (publicKey: BNRSAPublicKey, msg: Buffer, reverse?: boolean, padding?: number): Buffer {
  let _padding;
  if (padding) {
    _padding = padding;
  } else if (reverse) {
    _padding = 1;
  } else {
    _padding = 4;
  }
  const key = publicKey;
  let paddedMsg;
  if (_padding === 4) {
    paddedMsg = oaep(key, msg);
  } else if (_padding === 1) {
    paddedMsg = pkcs1(key, msg, reverse);
  } else if (_padding === 3) {
    paddedMsg = new BN(msg);
    if (paddedMsg.cmp(key.modulus) >= 0) {
      throw new Error('data too long for modulus');
    }
  } else {
    throw new Error('unknown padding');
  }
  if (reverse) {
    return crt(paddedMsg, key);
  } else {
    return withPublic(paddedMsg, key);
  }
}

function oaep (key, msg) {
  const k = key.modulus.byteLength();
  const mLen = msg.length;
  const iHash = createHash('sha1').update(Buffer.alloc(0)).digest();
  const hLen = iHash.length;
  const hLen2 = 2 * hLen;
  if (mLen > k - hLen2 - 2) {
    throw new Error('message too long');
  }
  const ps = Buffer.alloc(k - mLen - hLen2 - 2);
  const dblen = k - hLen - 1;
  const seed = randomBytes(hLen);
  const maskedDb = xor(Buffer.concat([iHash, ps, Buffer.alloc(1, 1), msg], dblen), mgf(seed, dblen));
  const maskedSeed = xor(seed, mgf(maskedDb, hLen));
  return new BN(Buffer.concat([Buffer.alloc(1), maskedSeed, maskedDb], k));
}
function pkcs1 (key: BNRSAPublicKey, msg: Buffer, reverse?: boolean): BN {
  const mLen = msg.length;
  const modulus = new BN(arrayBufferToBuffer(key.modulus));
  const k = modulus.byteLength();
  if (mLen > k - 11) {
    throw new Error('message too long');
  }
  let ps;
  if (reverse) {
    ps = Buffer.alloc(k - mLen - 3, 0xff);
  } else {
    ps = nonZero(k - mLen - 3);
  }
  return new BN(Buffer.concat([Buffer.from([0, reverse ? 1 : 2]), ps, Buffer.alloc(1), msg], k));
}
function nonZero (len: number): Buffer {
  const out = Buffer.allocUnsafe(len);
  let i = 0;
  let cache = randomBytes(len * 2);
  let cur = 0;
  let num;
  while (i < len) {
    if (cur === cache.length) {
      cache = randomBytes(len * 2);
      cur = 0;
    }
    num = cache[cur++];
    if (num) {
      out[i++] = num;
    }
  }
  return out;
}
