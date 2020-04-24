// much of this based on https://github.com/indutny/self-signed/blob/gh-pages/lib/rsa.js
import createHmac from 'create-hmac';
import crt from 'browserify-rsa';

import BN from 'bn.js';

import {
  RSAPrivateKey,
  RSAPublicKey,
  DSAPrivateKey,
  DSAPublicKey
} from './asymmetric-interface';

function fromDER (sig: Buffer): { r: BN, s: BN } {
  let position = 0;
  if (sig[position++] !== 0x30) {
    throw new Error('Unknown Signature');
  }
  let totalLength = sig[position++] - 4;
  let halfLength = totalLength / 2;
  if (sig[position++] !== 0x02) {
    throw new Error('Unknown Signature');
  }
  if (sig[position++] !== halfLength) {
    throw new Error('Unknown Signature');
  }
  let r = sig.slice(position, position + halfLength);
  position += halfLength;
  if (sig[position++] !== 0x02) {
    throw new Error('Unknown Signature');
  }
  if (sig[position++] !== halfLength) {
    throw new Error('Unknown Signature');
  }
  let s = sig.slice(position, position + halfLength);
  if (r[0] === 0x00 && (r[1] & 0x80)) {
    r = r.slice(1);
  }
  if (s[0] === 0x00 && (s[1] & 0x80)) {
    s = s.slice(1);
  }
  return {
    r: new BN(r),
    s: new BN(s)
  };
}

function toDER (_r: BN, _s: BN): Buffer {
  let r = _r.toArray();
  let s = _s.toArray();

  // Pad values
  if (r[0] & 0x80) r = [ 0 ].concat(r);
  if (s[0] & 0x80) s = [ 0 ].concat(s);

  let total = r.length + s.length + 4;
  let res = [ 0x30, total, 0x02, r.length ];
  res = res.concat(r, [ 0x02, s.length ], s);
  return Buffer.from(res);
}

function getKey (x, q, hash, algo) {
  x = Buffer.from(x.toArray());
  if (x.length < q.byteLength()) {
    const zeros = Buffer.alloc(q.byteLength() - x.length);
    zeros.fill(0);
    x = Buffer.concat([ zeros, x ]);
  }
  const hlen = hash.length;
  const hbits = bits2octets(hash, q);
  let v = Buffer.from(hlen);
  v.fill(1);
  let k = Buffer.from(hlen);
  k.fill(0);
  k = createHmac(algo, k).update(v).update(Buffer.from([ 0 ])).update(x).update(hbits).digest();
  v = createHmac(algo, k).update(v).digest();
  k = createHmac(algo, k).update(v).update(Buffer.from([ 1 ])).update(x).update(hbits).digest();
  v = createHmac(algo, k).update(v).digest();
  return { k: k, v: v };
}

function bits2int (obits: Buffer, q: BN): BN {
  let bits = new BN(obits);
  let shift = (obits.length << 3) - q.bitLength();
  if (shift > 0) bits.ishrn(shift);
  return bits;
}

function bits2octets (_bits: Buffer, q: BN) {
  let bits = bits2int(_bits, q);
  bits = bits.mod(q);
  let out = Buffer.from(bits.toArray());
  if (out.length < q.byteLength()) {
    const zeros = Buffer.alloc(q.byteLength() - out.length);
    zeros.fill(0);
    out = Buffer.concat([ zeros, out ]);
  }
  return out;
}

function makeKey (q: BN, kv, algo): BN {
  let t: Buffer;
  let k: BN;

  do {
    t = Buffer.alloc(0);

    while (t.length * 8 < q.bitLength()) {
      kv.v = createHmac(algo, kv.k).update(kv.v).digest();
      t = Buffer.concat([ t, kv.v ]);
    }

    k = bits2int(t, q);
    kv.k = createHmac(algo, kv.k).update(kv.v).update(Buffer.from([ 0 ])).digest();
    kv.v = createHmac(algo, kv.k).update(kv.v).digest();
  } while (k.cmp(q) !== -1);

  return k;
}

function makeR (g: BN, k: BN, p: BN, q: BN): BN {
  return g.toRed(BN.mont(p)).redPow(k).fromRed().mod(q);
}

export function rsaSign (priv: RSAPrivateKey, payload: Buffer) {
  const len = priv.modulus.byteLength();
  const pad = [ 0, 1 ];
  while (payload.length + pad.length + 1 < len) pad.push(0xff);
  pad.push(0x00);
  let i = -1;
  while (++i < payload.length) pad.push(payload[i]);

  return crt(pad, priv);
}

export function dsaSign (hash, priv: DSAPrivateKey, algo) {
  let x = priv.priv_key;
  let p = priv.p;
  let q = priv.q;
  let g = priv.g;
  let r = new BN(0);
  let k: BN;
  let H = bits2int(hash, q).mod(q);
  let s: boolean | BN = false;
  let kv = getKey(x, q, hash, algo);
  while (s === false) {
    k = makeKey(q, kv, algo);
    r = makeR(g, k, p, q);
    s = k.invm(q).imul(H.add(x.mul(r))).mod(q);
    if (s.cmpn(0) === 0) {
      s = false;
      r = new BN(0);
    }
  }
  return toDER(r, s);
}

function checkValue (b: BN, q) {
  if (b.cmpn(0) <= 0) throw new Error('invalid sig');
  if (b.cmp(q) >= q) throw new Error('invalid sig');
}

export function rsaVerify (pub: RSAPublicKey, sig: Buffer, payload: Buffer): boolean {
  let len = pub.modulus.byteLength();
  const padArray = [ 1 ];
  let padNum = 0;
  while (payload.length + padArray.length + 2 < len) {
    padArray.push(0xff);
    padNum++;
  }
  padArray.push(0x00);
  let i = -1;
  while (++i < payload.length) {
    padArray.push(payload[i]);
  }
  const padBuffer = Buffer.from(padArray);
  const red = BN.mont(pub.modulus);
  let sigT1 = new BN(sig).toRed(red);
  sigT1 = sigT1.redPow(new BN(pub.publicExponent));
  const sigT2 = Buffer.from(sigT1.fromRed().toArray());
  let out = padNum < 8 ? 1 : 0;
  len = Math.min(sigT2.length, padBuffer.length);
  if (sigT2.length !== padBuffer.length) out = 1;

  i = -1;
  while (++i < len) out |= sigT2[i] ^ padBuffer[i];
  return out === 0;
}


export function dsaVerify (sig: Buffer, hash: Buffer, pub: DSAPublicKey) {
  const p = pub.p;
  const q = pub.q;
  const g = pub.g;
  const y = pub.pub_key;
  const { s, r } = fromDER(sig);
  checkValue(s, q);
  checkValue(r, q);
  const montp = BN.mont(p);
  const w = s.invm(q);
  const v = g.toRed(montp)
    .redPow(new BN(hash).mul(w).mod(q))
    .fromRed()
    .mul(y.toRed(montp).redPow(r.mul(w).mod(q)).fromRed())
    .mod(p)
    .mod(q);
  return v.cmp(r) === 0;
}
