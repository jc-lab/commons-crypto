import * as stream from 'stream';
import {BinaryLike} from '../interface';

export interface Hash extends stream.Transform {
  update(data: BinaryLike): this;
  digest(): Buffer;
}
