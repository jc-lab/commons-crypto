import * as elliptic from 'elliptic';
import * as BN from 'bn.js';

function formatReturnValue (bn): Buffer;
function formatReturnValue (bn, enc, len?): string;
function formatReturnValue (bn, enc?, len?): Buffer | string {
  if (!Array.isArray(bn)) {
    bn = bn.toArray();
  }
  let buf = Buffer.from(bn);
  if (len && buf.length < len) {
    const zeros = Buffer.alloc(len - buf.length);
    zeros.fill(0);
    buf = Buffer.concat([zeros, buf]);
  }
  if (!enc) {
    return buf;
  } else {
    return buf.toString(enc);
  }
}

export default class ECDH {
  private _ec: elliptic.ec;
  private _curveByteLength: number;
  private _keys!: elliptic.ec.KeyPair;

  constructor(ec: elliptic.ec, curveByteLength: number) {
    this._ec = ec;
    this._curveByteLength = curveByteLength;
  }

  setKeyPair(kp: elliptic.ec.KeyPair): this {
    this._keys = kp;
    return this;
  }

  generateKeys(enc, format) {
    this._keys = this._ec.genKeyPair();
    return this.getPublicKey(enc, format);
  }

  computeSecret(other: elliptic.ec.KeyPair | string | Buffer, inputEncode?: BufferEncoding, enc?): string | Buffer {
    const _inputEncode: BufferEncoding = inputEncode || 'utf8';
    let otherKey;
    if (typeof other === 'string') {
      otherKey = this._ec.keyFromPublic(Buffer.from(other, _inputEncode));
    } else if (Buffer.isBuffer(other)) {
      otherKey = this._ec.keyFromPublic(other);
    } else {
      otherKey = other;
    }
    const otherPub = otherKey.getPublic();
    const out = otherPub.mul(this._keys.getPrivate()).getX();
    return formatReturnValue(out, enc, this._curveByteLength);
  }

  getPublicKey(enc, format: 'compressed' | 'uncompressed' | 'hybrid'): string | Buffer {
    const key = this._keys.getPublic(format === 'compressed', 'array');
    if (format === 'hybrid') {
      if (key[key.length - 1] % 2) {
        key[0] = 7;
      } else {
        key[0] = 6;
      }
    }
    return formatReturnValue(key, enc);
  }

  getPrivateKey(): Buffer;
  getPrivateKey(enc): string;
  getPrivateKey(enc?: string): Buffer | string {
    return formatReturnValue(this._keys.getPrivate(), enc);
  }

  setPublicKey(pub: Buffer | string, enc?: BufferEncoding): this {
    const _enc: BufferEncoding = enc || 'utf8';
    if (!Buffer.isBuffer(pub)) {
      pub = Buffer.from(pub, _enc);
    }
    //@ts-ignore
    this._keys._importPublic(pub);
    return this;
  }

  setPrivateKey(priv: Buffer | string, enc?: BufferEncoding): this {
    const _enc: BufferEncoding = enc || 'utf8';
    const binaryPrivate: Buffer = Buffer.isBuffer(priv) ? priv : Buffer.from(priv, enc);
    const _priv = new BN(binaryPrivate);
    const privText = _priv.toString(16);
    this._keys = this._ec.genKeyPair();
    //@ts-ignore
    this._keys._importPrivate(privText);
    return this;
  }
}
