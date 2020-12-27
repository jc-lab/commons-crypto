import * as stream from 'stream';
import {BinaryLike} from '../interface';

export interface CipherOptions extends stream.TransformOptions {
  key: BinaryLike;
  iv?: BinaryLike | null;
  authTagLength?: number;
}

export interface Cipher extends stream.Transform {
  update(data: BinaryLike): Buffer;
  final(): Buffer;
  setAutoPadding(auto_padding?: boolean): this;

  /**
   * set add
   *
   * @param buffer Additional Authenticated Data
   * @param options Required in CCM mode
   */
  setAAD(buffer: Buffer, options?: { plaintextLength: number }): this;
  getAuthTag(): Buffer;
}

export interface Decipher extends stream.Transform {
  update(data: BinaryLike): Buffer;
  final(): Buffer;
  setAutoPadding(auto_padding?: boolean): this;
  setAuthTag(tag: BinaryLike): this;
  setAAD(buffer: BinaryLike): this;
}
