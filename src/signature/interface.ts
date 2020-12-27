import * as stream from 'stream';

export interface Signature extends stream.Writable {
  sign(): Buffer;
  verify(signature: Buffer): boolean;
}
