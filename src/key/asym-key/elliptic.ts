import * as elliptic from 'elliptic';
import * as asn1js from 'asn1js';
import * as hashjs from 'hash.js';
import {AsnParser} from '@peculiar/asn1-schema';
import {AsymmetricKeyAlgorithm, AsymmetricKeyObject} from '../interfaces';
import {arrayBufferToBuffer} from '../../utils';
import {EllipticAlgorithm} from '../asym-algorithm/elliptic';
import {ECParametersChoice} from '../impl/asn/ECParameters';
import {compileCurve, Curve, CurveOptions, getCurveByOid} from '../impl/curves';
import {KeyParams} from '../intl';

export class EllipticKeyObject extends AsymmetricKeyObject {
  private _algo: EllipticAlgorithm;
  private _keyPair!: elliptic.ec.KeyPair;

  getECKeyPair(): elliptic.ec.KeyPair {
    return this._keyPair;
  }

  constructor(algo: EllipticAlgorithm, keyPair: elliptic.ec.KeyPair) {
    super();
    this._algo = algo;
    this._keyPair = keyPair;
  }

  equals(o: EllipticKeyObject): boolean {
    if (!o) {
      return false;
    }
    if (!(
      (this.isPrivate() && o.isPrivate()) || (this.isPublic() && o.isPublic())
    )) {
      return false;
    }
    if (this.isPrivate()) {
      return this._keyPair.getPrivate().eq(o._keyPair.getPrivate());
    } else {
      return this._keyPair.getPublic().eq(o._keyPair.getPublic());
    }
  }

  public static fromEllipticKeyPair(algo: EllipticAlgorithm, keyPair: elliptic.ec.KeyPair): EllipticKeyObject {
    return new EllipticKeyObject(algo, keyPair);
  }

  public static fromBinary(algo: EllipticAlgorithm, type: 'private' | 'public', keyObject: ArrayBuffer): EllipticKeyObject {
    let keyPair;
    const asn = asn1js.fromBER(keyObject);
    if (type === 'private') {
      keyPair = algo.getElliptic().keyFromPrivate(
        (asn.result as any) instanceof asn1js.Sequence ?
          arrayBufferToBuffer((asn.result as any).valueBlock.value[1].valueBlock.valueHex) :
          arrayBufferToBuffer(keyObject)
      );
    } else {
      keyPair = algo.getElliptic().keyFromPublic(
        arrayBufferToBuffer(keyObject)
      );
    }
    return new EllipticKeyObject(algo, keyPair);
  }

  getKeyAlgorithm(): AsymmetricKeyAlgorithm {
    return this._algo;
  }

  isPrivate(): boolean {
    return !!(this._keyPair.getPrivate());
  }

  isPublic(): boolean {
    return !!(this._keyPair.getPublic());
  }

  isSecret(): boolean {
    return false;
  }
}

export interface CurveKeyParams extends KeyParams<ECParametersChoice | ArrayBuffer, ArrayBuffer> {
  algorithmOid: string;
}

export function fromCurve(options: CurveKeyParams): EllipticKeyObject {
  let ec: Curve | undefined;
  let namedOid: string | undefined = undefined;
  // asn1js.ObjectIdentifier | null = null;

  const ecParameterChoice = (options.asn1KeyParams instanceof ECParametersChoice)
    ? options.asn1KeyParams : AsnParser.parse(options.asn1KeyParams as ArrayBuffer, ECParametersChoice);

  if (ecParameterChoice.namedCurve) {
    namedOid = ecParameterChoice.namedCurve;
    ec = getCurveByOid(ecParameterChoice.namedCurve);
  } else {
    const ecParameters = ecParameterChoice.ecParameters;
    const fieldIDParamParseResult = asn1js.fromBER(ecParameters.fieldID.parameters);
    const p = fieldIDParamParseResult.result as asn1js.Integer;
    const gLength = Math.floor(ecParameters.base.byteLength - 1) / 2;
    const g = [
      arrayBufferToBuffer(ecParameters.base.slice(1, 1 + gLength)).toString('hex'),
      arrayBufferToBuffer(ecParameters.base.slice(1 + gLength, 1 + gLength + gLength)).toString('hex')
    ];
    const curveOptions: CurveOptions = {
      type: 'short',
      prime: null,
      p: arrayBufferToBuffer(p.valueBlock.valueHex).toString('hex'),
      a: arrayBufferToBuffer(ecParameters.curve.a.buffer).toString('hex'),
      b: arrayBufferToBuffer(ecParameters.curve.b.buffer).toString('hex'),
      n: arrayBufferToBuffer(ecParameters.order).toString('hex'),
      hash: hashjs.sha256, //TODO: Auto find fitted hash algorithm
      gRed: false,
      g: g,
      byteLength: 0,
      signable: options.signable,
      keyAgreementable: options.keyAgreementable,
      cryptable: options.cryptable
    };
    ec = {
      preset: new elliptic.curves.PresetCurve(curveOptions),
      options: curveOptions,
      compiled: compileCurve(curveOptions as CurveOptions)
    };
    ec.options.byteLength = ec.compiled.p.bitLength() / 8;
  }
  if (!ec) {
    throw new Error('Not supported Key: ' + (namedOid ? namedOid : 'null'));
  }
  const algo = new EllipticAlgorithm(
    options.type,
    new elliptic.ec(ec.preset), ec.options,
    options.algorithmOid,
    ecParameterChoice
  );
  return EllipticKeyObject.fromBinary(algo, options.keyType, options.asn1KeyObject);
}
