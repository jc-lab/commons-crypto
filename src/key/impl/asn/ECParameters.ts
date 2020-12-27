import {AsnIntegerArrayBufferConverter, AsnProp, AsnType, AsnPropTypes, AsnTypeTypes} from '@peculiar/asn1-schema';

import {ECCurve} from './ECCurve';

export class FieldID {
  @AsnProp({type: AsnPropTypes.ObjectIdentifier})
  public fieldType!: string;

  @AsnProp({type: AsnPropTypes.Any})
  public parameters: any;

  constructor(params: Partial<FieldID> = {}) {
    Object.assign(this, params);
  }
}

export class ECParameters {
  @AsnProp({type: AsnPropTypes.Integer})
  public version!: number;

  @AsnProp({type: FieldID})
  public fieldID: FieldID = new FieldID();

  @AsnProp({type: ECCurve})
  public curve: ECCurve = new ECCurve();

  @AsnProp({type: AsnPropTypes.OctetString})
  public base: ArrayBuffer = new ArrayBuffer(0);

  @AsnProp({type: AsnPropTypes.Integer, converter: AsnIntegerArrayBufferConverter})
  public order: ArrayBuffer = new ArrayBuffer(0);

  @AsnProp({type: AsnPropTypes.Integer, converter: AsnIntegerArrayBufferConverter})
  public cofactor: ArrayBuffer = new ArrayBuffer(0);

  constructor(params: Partial<ECParameters> = {}) {
    Object.assign(this, params);
  }
}

/**
 * ```
 * Parameters{CURVES:IOSet} ::= CHOICE {
 * ecParameters ECParameters,
 * namedCurve CURVES.&id({IOSet}),
 * implicitCA NULL
 * }
 * ```
 */
@AsnType({ type: AsnTypeTypes.Choice })
export class ECParametersChoice {
  @AsnProp({ type: AsnPropTypes.ObjectIdentifier })
  public namedCurve!: string;

  @AsnProp({ type: ECParameters })
  public ecParameters = new ECParameters();

  @AsnProp({ type: AsnPropTypes.Null })
  public implicitCA!: null;

  constructor(params: Partial<ECParametersChoice> = {}) {
    Object.assign(this, params);
  }
}
