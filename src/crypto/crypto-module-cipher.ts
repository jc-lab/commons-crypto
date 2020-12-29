import * as crypto from 'crypto';
import * as stream from 'stream';
import {BinaryLike} from '../interface';
import {Cipher, CipherOptions, Decipher} from './interface';

function xorTest (a: Buffer, b: Buffer, l?: number | undefined): number {
  let out: number = 0;
  const _l = l || b.length;
  if (_l > a.length || _l > b.length) out++;
  for (let i = 0; i < _l; ++i) {
    out += (a[i] ^ b[i]);
  }
  return out;
}

function xor (a: Buffer, b: Buffer) {
  const length = Math.min(a.length, b.length);
  const buffer = Buffer.alloc(length);
  for (let i = 0; i < length; ++i) {
    buffer[i] = a[i] ^ b[i];
  }
  return buffer;
}

// authTagLength is not implemented in crypto-browserify
function fixedFinal (this: any) {
  if (this._decrypt && !this._authTag) throw new Error('11 Unsupported state or unable to authenticate data');

  const tag = xor(this._ghash.final(this._alen * 8, this._len * 8), this._cipher.encryptBlock(this._finID));
  if (this._decrypt && xorTest(tag, this._authTag, this._authTagLength)) throw new Error('22 Unsupported state or unable to authenticate data');

  this._authTag = tag;
  this._cipher.scrub();
}

export class CryptoModuleCipher extends stream.Transform implements Cipher {
  public readonly isStreamMode: boolean;
  public readonly isAEAD: boolean;
  public readonly keySize: number;
  public readonly blockSize: number;
  private readonly _algo: string;
  private _cipher!: crypto.CipherGCM;
  private _authTagLength: number = 0;

  constructor(algo: string, isStreamMode: boolean, isAEAD: boolean, keySize: number, blockSize: number, opts?: stream.TransformOptions | undefined) {
    super(opts);
    this._algo = algo;
    this.isStreamMode = isStreamMode;
    this.isAEAD = isAEAD;
    this.keySize = keySize;
    this.blockSize = blockSize;
  }

  init(opts: CipherOptions): this {
    const iv = opts.iv || null;
    const cipher: any = crypto.createCipheriv(this._algo as any, opts.key, iv, opts);
    if (!cipher) {
      throw new Error(`${this._algo} algorithm not supported`);
    }
    this._cipher = cipher;
    this._authTagLength = opts.authTagLength || 16;
    return this;
  }

  final(): Buffer {
    return this._cipher.final();
  }

  getAuthTag(): Buffer {
    const tag = this._cipher.getAuthTag();
    if (this._authTagLength) {
      // Bug in crypto-browserify
      return tag.slice(0, this._authTagLength);
    }
    return tag;
  }

  setAAD(buffer: Buffer, options: { plaintextLength: number }): this {
    this._cipher.setAAD(buffer, options);
    return this;
  }

  setAutoPadding(auto_padding?: boolean): this {
    this._cipher.setAutoPadding(auto_padding);
    return this;
  }

  update(data: BinaryLike): Buffer {
    return this._cipher.update(data);
  }

  _transform(chunk: any, encoding: string, callback: stream.TransformCallback) {
    const output = this._cipher.update(chunk);
    callback(null, output);
  }

  _final(callback: (error?: (Error | null)) => void) {
    const output = this._cipher.final();
    this.push(output);
    callback(null);
  }
}

export class CryptoModuleDecipher extends stream.Transform implements Decipher {
  public readonly isStreamMode: boolean;
  public readonly isAEAD: boolean;
  public readonly keySize: number;
  public readonly blockSize: number;
  private readonly _algo: string;
  private _cipher!: crypto.DecipherGCM;
  private _authTagLength: number = 0;

  constructor(algo: string, isStreamMode: boolean, isAEAD: boolean, keySize: number, blockSize: number, opts?: stream.TransformOptions | undefined) {
    super(opts);
    this._algo = algo;
    this.isStreamMode = isStreamMode;
    this.isAEAD = isAEAD;
    this.keySize = keySize;
    this.blockSize = blockSize;
  }

  init(opts: CipherOptions): this {
    const iv = opts.iv || null;
    const cipher: any = crypto.createDecipheriv(this._algo as any, opts.key, iv, opts);
    if (!cipher) {
      throw new Error(`${this._algo} algorithm not supported`);
    }
    this._cipher = cipher;
    this._authTagLength = opts.authTagLength || 16;
    if (cipher.setAuthTag && cipher._ghash) {
      cipher._authTagLength = this._authTagLength;
      cipher.final = fixedFinal;
    }
    return this;
  }

  final(): Buffer {
    return this._cipher.final();
  }

  setAuthTag(buffer: BinaryLike): this {
    this._cipher.setAuthTag(buffer);
    return this;
  }

  setAAD(buffer: BinaryLike, options?: { plaintextLength: number }): this {
    this._cipher.setAAD(buffer, options);
    return this;
  }

  setAutoPadding(auto_padding?: boolean): this {
    this._cipher.setAutoPadding(auto_padding);
    return this;
  }

  update(data: BinaryLike): Buffer {
    return this._cipher.update(data);
  }

  _transform(chunk: any, encoding: string, callback: stream.TransformCallback) {
    const output = this._cipher.update(chunk);
    callback(null, output);
  }

  _final(callback: (error?: (Error | null)) => void) {
    const output = this._cipher.final();
    this.push(output);
    callback(null);
  }
}

