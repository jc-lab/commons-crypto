import * as stream from 'stream';
import {BinaryLike} from '../interface';

export interface Hash extends stream.Transform {
  readonly blockSize: number;
  readonly outputSize: number;
  update(data: BinaryLike): this;
  digest(): Buffer;
  clone(): Hash;
}
