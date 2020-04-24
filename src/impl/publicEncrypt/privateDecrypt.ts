import createHash from 'create-hash';
import crt from 'browserify-rsa';

import BN from 'bn.js';

import {
  mgf
} from './mgf';
import {
  xor
} from './xor';
import {
  withPublic
} from './withPublic';

import * as asymInterfaces from '../asymmetric-interface';

export function privateDecrypt (privateKey: asymInterfaces.RSAPrivateKey, enc: Buffer, reverse?: boolean, padding?: number): Buffer {
  let _padding;
  if (padding) {
    _padding = padding;
  } else if (reverse) {
    _padding = 1;
  } else {
    _padding = 4;
  }

  let key = privateKey;
  let k = key.modulus.byteLength();
  if (enc.length > k || new BN(enc).cmp(key.modulus) >= 0) {
    throw new Error('decryption error');
  }
  let msg;
  if (reverse) {
    msg = withPublic(new BN(enc), key);
  } else {
    msg = crt(enc, key);
  }
  let zBuffer = Buffer.alloc(k - msg.length);
  msg = Buffer.concat([zBuffer, msg], k);
  if (_padding === 4) {
    return oaep(key, msg);
  } else if (_padding === 1) {
    return pkcs1(key, msg, reverse);
  } else if (_padding === 3) {
    return msg;
  } else {
    throw new Error('unknown padding');
  }
}

function oaep (key: asymInterfaces.RSAPrivateKey, msg: Buffer): Buffer {
  let k = key.modulus.byteLength();
  let iHash = createHash('sha1').update(Buffer.alloc(0)).digest();
  let hLen = iHash.length;
  if (msg[0] !== 0) {
    throw new Error('decryption error');
  }
  let maskedSeed = msg.slice(1, hLen + 1);
  let maskedDb = msg.slice(hLen + 1);
  let seed = xor(maskedSeed, mgf(maskedDb, hLen));
  let db = xor(maskedDb, mgf(seed, k - hLen - 1));
  if (compare(iHash, db.slice(0, hLen))) {
    throw new Error('decryption error');
  }
  let i = hLen;
  while (db[i] === 0) {
    i++;
  }
  if (db[i++] !== 1) {
    throw new Error('decryption error');
  }
  return db.slice(i);
}

function pkcs1 (key: asymInterfaces.RSAPrivateKey, msg: Buffer, reverse?: boolean): Buffer {
  let p1 = msg.slice(0, 2);
  let i = 2;
  let status = 0;
  while (msg[i++] !== 0) {
    if (i >= msg.length) {
      status++;
      break;
    }
  }
  let ps = msg.slice(2, i - 1);

  if ((p1.toString('hex') !== '0002' && !reverse) || (p1.toString('hex') !== '0001' && reverse)) {
    status++;
  }
  if (ps.length < 8) {
    status++;
  }
  if (status) {
    throw new Error('decryption error');
  }
  return msg.slice(i);
}
function compare (a, b): number {
  let _a = Buffer.from(a);
  let _b = Buffer.from(b);
  let dif = 0;
  let len = _a.length;
  if (_a.length !== _b.length) {
    dif++;
    len = Math.min(_a.length, _b.length);
  }
  let i = -1;
  while (++i < len) {
    dif += (_a[i] ^ _b[i]);
  }
  return dif;
}
