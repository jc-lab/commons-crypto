import * as stream from 'stream';
import {BinaryLike} from '../interface';

export interface Hmac extends stream.Transform {
  update(data: BinaryLike): Hmac;
  digest(): Buffer;
}
