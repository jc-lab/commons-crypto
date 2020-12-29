import * as stream from 'stream';
import {BinaryLike} from '../interface';

export interface Hash extends stream.Transform {
  /**
   * block size bits
   */
  readonly blockSize: number;
  /**
   * output size bits
   */
  readonly outputSize: number;
  update(data: BinaryLike): this;
  digest(): Buffer;
  clone(): Hash;
}
