import { AsnProp, AsnPropTypes, OctetString } from '@peculiar/asn1-schema';

export class ECCurve {
  @AsnProp({ type: OctetString })
  public a = new OctetString();

  @AsnProp({ type: OctetString })
  public b = new OctetString();

  @AsnProp({ type: AsnPropTypes.BitString, context: 1, optional: true })
  public seed?: ArrayBuffer;

  constructor(params: Partial<ECCurve> = {}) {
    Object.assign(this, params);
  }
}
