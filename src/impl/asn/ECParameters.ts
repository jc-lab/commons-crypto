import * as asn1js from 'asn1js';

import ECCurve from './ECCurve';

export default class ECParameters {
  public version!: asn1js.Integer;
  public fieldID!: asn1js.Sequence;
  public curve!: ECCurve;
  public base!: asn1js.OctetString;
  public order!: asn1js.Integer;
  public cofactor!: asn1js.Integer;

  public constructor(params?: {
    schema?: any,
    version?: asn1js.Integer,
    fieldID?: asn1js.Sequence,
    curve?: ECCurve,
    base?: asn1js.OctetString,
    order?: asn1js.Integer,
    cofactor?: asn1js.Integer
  }) {
    if (params) {
      if (params.schema) {
        this.fromSchema(params.schema);
        return;
      }

      this.version = params.version as asn1js.Integer;
      this.fieldID = params.fieldID as asn1js.Sequence;
      this.curve = params.curve as ECCurve;
      this.base = params.base as asn1js.OctetString;
      this.order = params.order as asn1js.Integer;
      this.cofactor = params.cofactor as asn1js.Integer;
    }
  }

  public static schema (opts?: { name?: string}): asn1js.Sequence {
    const schemaParameters: any = {
      value: [
        new asn1js.Integer({
          name: 'version'
        } as any),
        new asn1js.Sequence({
          name: 'fieldID',
          value: [
            new asn1js.ObjectIdentifier({
              name: 'fieldType'
            } as any),
            new asn1js.Any({
              name: 'parameters'
            })
          ]
        } as any),
        ECCurve.schema({
          name: 'curve'
        }),
        new asn1js.OctetString({
          name: 'base'
        } as any),
        new asn1js.Integer({
          name: 'order'
        } as any),
        new asn1js.Integer({
          name: 'cofactor',
          optional: true
        } as any),
      ]
    };
    if (opts && opts.name) {
      schemaParameters['name'] = opts && opts.name;
    }
    return new asn1js.Sequence(schemaParameters);
  }

  public fromSchema(seq: any) {
    const schema = ECParameters.schema();
    const asn1 = asn1js.compareSchema(seq, seq, schema);
    if (!asn1.verified) {
      throw new Error('Not verified input data');
    }
    this.version = asn1.result.version;
    this.base = asn1.result.base;
    this.order = asn1.result.order;
    this.cofactor = asn1.result.cofactor;
    this.fieldID = asn1.result.fieldID;
    this.curve = new ECCurve({
      schema: asn1.result.curve
    });
  }
}
