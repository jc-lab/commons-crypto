import * as createHash from 'create-hash';

export function mgf(seed: Buffer, len: number): Buffer {
  let t = Buffer.alloc(0);
  let i = 0;
  while (t.length < len) {
    const c = i2ops(i++);
    t = Buffer.concat([t, createHash('sha1').update(seed).update(c).digest()]);
  }
  return t.slice(0, len);
}

function i2ops (c: number): Buffer {
  const out = Buffer.allocUnsafe(4);
  out.writeUInt32BE(c, 0);
  return out;
}
