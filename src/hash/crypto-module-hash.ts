import * as crypto from 'crypto';
import * as stream from 'stream';
import {BinaryLike} from '../interface';
import {Hash} from './interface';

export class CryptoModuleHash extends stream.Transform implements Hash {
  public readonly blockSize: number;
  public readonly outputSize: number;
  private readonly _algo: string;
  private _hash: crypto.Hash;

  constructor(algo: string, blockSize: number, outputSize: number) {
    super();
    this._algo = algo;
    this._hash = crypto.createHash(algo);
    this.blockSize = blockSize;
    this.outputSize = outputSize;
  }

  clone(): Hash {
    return new CryptoModuleHash(this._algo, this.blockSize, this.outputSize);
  }

  update(data: BinaryLike): this {
    this._hash.update(data);
    return this;
  }

  digest(): Buffer {
    return this._hash.digest();
  }

  _transform(chunk: any, encoding: string, callback: stream.TransformCallback) {
    const output = this._hash.update(chunk);
    callback(null, output);
  }

  _final(callback: (error?: (Error | null)) => void) {
    callback();
  }
}
