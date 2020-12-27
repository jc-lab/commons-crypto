import {AsnProp, AsnPropTypes} from '@peculiar/asn1-schema';
import {
  ECParametersChoice
} from './ECParameters';

/**
 * ```
 * ECPrivateKey ::= SEQUENCE {
 *   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 *   privateKey     OCTET STRING,
 *   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
 *   publicKey  [1] BIT STRING OPTIONAL
 * }
 * ```
 */
export class ECPrivateKey {

  @AsnProp({ type: AsnPropTypes.Integer })
  public version = 1;

  @AsnProp({ type: AsnPropTypes.OctetString })
  public privateKey: ArrayBuffer = new ArrayBuffer(0);

  @AsnProp({ type: ECParametersChoice, context: 0, optional: true })
  public parameters?: ECParametersChoice;

  @AsnProp({ type: AsnPropTypes.BitString, context: 1, optional: true })
  public publicKey?: ArrayBuffer;

  constructor(params: Partial<ECPrivateKey> = {}) {
    Object.assign(this, params);
  }
}
