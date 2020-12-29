import * as stream from 'stream';
import {BinaryLike} from '../interface';
import {Hmac} from './interface';
import {Hash} from '../hash';

function xorWithByte(input: Buffer, value: number): Buffer {
  const temp = Buffer.alloc(input.byteLength);
  input.copy(temp);
  for (let i=0; i < input.byteLength; i++) {
    temp[i] ^= value;
  }
  return temp;
}

export class HmacImpl extends stream.Transform implements Hmac {
  public readonly macOid: string;
  public readonly digestOid: string;

  private _baseHash: Hash;
  private _outputHash!: Hash;
  private _messageHash!: Hash;

  constructor(macOid: string, hash: Hash) {
    super();
    this.macOid = macOid;
    this.digestOid = hash.digestOid;
    this._baseHash = hash;
  }

  init(key: Buffer): this {
    const hash = this._baseHash;

    const blockSizeBytes = hash.blockSize / 8;

    let _key: Buffer = key;
    if (key.byteLength > blockSizeBytes) {
      _key = hash.clone().update(key).digest();
    }
    if (_key.byteLength < blockSizeBytes) {
      const temp = Buffer.alloc(blockSizeBytes);
      _key.copy(temp);
      _key = temp;
    }

    const oKeyPad = xorWithByte(_key, 0x5c);
    const iKeyPad = xorWithByte(_key, 0x36);

    this._outputHash = hash.clone()
      .update(oKeyPad);
    this._messageHash = hash.clone()
      .update(iKeyPad);

    return this;
  }

  digest(): Buffer {
    return this._outputHash
      .update(this._messageHash.digest())
      .digest();
  }

  update(data: BinaryLike): this {
    this._messageHash.update(data);
    return this;
  }

  _transform(chunk: any, encoding: string, callback: stream.TransformCallback) {
    const output = this._messageHash.update(chunk);
    callback(null, output);
  }

  _final(callback: (error?: (Error | null)) => void) {
    callback();
  }
}
