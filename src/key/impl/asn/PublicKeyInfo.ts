import {AsnParser, AsnProp, AsnPropTypes } from '@peculiar/asn1-schema';

import {
  AlgorithmIdentifier
} from '@peculiar/asn1-x509';
import {
  RSAPublicKey
} from '@peculiar/asn1-rsa';
import {
  ECPublicKey
} from './ECPublicKey';

export class PublicKeyInfo {
  @AsnProp({ type: AlgorithmIdentifier })
  public algorithm = new AlgorithmIdentifier();

  @AsnProp({ type: AsnPropTypes.BitString })
  public subjectPublicKey = new ArrayBuffer(0);

  @AsnProp({ type: AsnPropTypes.BitString, context: 1, optional: true })
  public seed?: ArrayBuffer;

  constructor(params: Partial<PublicKeyInfo> = {}) {
    Object.assign(this, params);
  }

  public getParsedKey(): ECPublicKey | RSAPublicKey | null {
    switch (this.algorithm.algorithm)
    {
    case '1.2.840.10045.2.1': // ECDSA
      return new ECPublicKey({
        bitstream: this.subjectPublicKey
      });
    case '1.2.840.113549.1.1.1': // RSA
      return AsnParser.parse(this.subjectPublicKey, RSAPublicKey);
    default:
    }
    return null;
  }
}
