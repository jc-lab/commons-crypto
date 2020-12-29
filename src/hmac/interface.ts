import * as stream from 'stream';
import {BinaryLike} from '../interface';

export interface Hmac extends stream.Transform {
  readonly macOid: string;
  readonly digestOid: string;

  init(key: Buffer): this;
  update(data: BinaryLike): this;
  digest(): Buffer;
}
