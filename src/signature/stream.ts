import * as stream from 'stream';
import {createHash, Hash} from '../hash';
import {Signature} from './interface';
import {AsymmetricKeyObject} from '../key';

export class SignatureImpl extends stream.Writable implements Signature {
  private _digestOid: string;
  private _hash: Hash;
  private _digest!: Buffer;
  private _key: AsymmetricKeyObject;

  constructor(digestOid: string, key: AsymmetricKeyObject, opts?: stream.WritableOptions) {
    super(opts);
    this._digestOid = digestOid;
    const hash = createHash(digestOid);
    if (!hash) {
      throw new Error(`${digestOid} algorithm not supported`);
    }
    this._hash = hash;
    this._key = key;
  }

  _write(chunk: any, encoding: string, callback: (error?: (Error | null)) => void) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding as any);
    this._hash.update(buf);
    callback();
  }

  _final(callback: (error?: (Error | null)) => void) {
    this._digest = this._hash.digest();
    callback();
  }

  sign(): Buffer {
    return this._key.sign(this._digestOid, this._digest);
  }

  verify(signature: Buffer): boolean {
    return this._key.verify(this._digestOid, this._digest, signature);
  }
}
