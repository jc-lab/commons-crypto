import * as stream from 'stream';
import {AsymmetricKeyObject} from '../key';

export interface Signature extends stream.Writable {
  readonly signatureOid: string;
  readonly digestOid: string;

  init(key: AsymmetricKeyObject): this;
  sign(): Buffer;
  verify(signature: Buffer): boolean;
}
