import * as asn1js from 'asn1js';

export default class ECCurve {
  public a!: asn1js.OctetString;
  public b!: asn1js.OctetString;
  public seed!: asn1js.BitString;

  public constructor(params?: {
    schema?: any,
    a?: asn1js.OctetString,
    b?: asn1js.OctetString,
    seed?: asn1js.BitString
  }) {
    if (params) {
      if (params.schema) {
        this.fromSchema(params.schema);
        return;
      }

      this.a = params.a as asn1js.OctetString;
      this.b = params.b as asn1js.OctetString;
      this.seed = params.seed as asn1js.BitString;
    }
  }

  public static schema (opts?: { name?: string}): asn1js.Sequence {
    const schemaParameters: any = {
      value: [
        new asn1js.OctetString({
          name: 'a'
        } as any),
        new asn1js.OctetString({
          name: 'b'
        } as any),
        new asn1js.BitString({
          name: 'seed',
          optional: true
        } as any)
      ]
    };
    if (opts && opts.name) {
      schemaParameters['name'] = opts && opts.name;
    }
    return new asn1js.Sequence(schemaParameters);
  }

  public fromSchema(seq: any) {
    const schema = ECCurve.schema();
    const asn1 = asn1js.compareSchema(seq, seq, schema);
    if (!asn1.verified) {
      throw new Error('Not verified input data');
    }
    this.a = asn1.result.a;
    this.b = asn1.result.b;
    this.seed = asn1.result.seed;
  }
}
