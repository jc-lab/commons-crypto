import * as asn1js from 'asn1js';
import * as elliptic from 'elliptic';
import * as hashjs from 'hash.js';
import {ECParametersChoice} from './impl/asn/ECParameters';
import {compileCurve, Curve, CurveOptions, getCurveByName, getCurveByOid} from './impl/curves';
import {arrayBufferToBuffer} from '../utils';
import {EllipticAlgorithm} from './asym-algorithm/elliptic';
import {AsymmetricAlgorithmType} from './interfaces';
import {RSAKeyAlgorithm} from './asym-algorithm/rsa';
import {getOidFromAsymmetricAlgorithmType} from './util';

/**
 * createAsymmetricAlgorithm
 *
 * @param type x448
 */
export function createAsymmetricAlgorithm(type: AsymmetricAlgorithmType.x448): EllipticAlgorithm;
/**
 * createAsymmetricAlgorithm
 *
 * @param type x25519
 */
export function createAsymmetricAlgorithm(type: AsymmetricAlgorithmType.x25519): EllipticAlgorithm;
/**
 * createAsymmetricAlgorithm
 *
 * @param type edwards
 * @param curve curve name or oid
 */
export function createAsymmetricAlgorithm(type: AsymmetricAlgorithmType.edwards, curve: string): EllipticAlgorithm;
/**
 * createAsymmetricAlgorithm
 *
 * @param type ec
 * @param curve curve name, oid, or parameter
 */
export function createAsymmetricAlgorithm(type: AsymmetricAlgorithmType.ec, curve: string | ECParametersChoice): EllipticAlgorithm;
/**
 * createAsymmetricAlgorithm
 *
 * @param type rsa
 * @param keySize key bits
 */
export function createAsymmetricAlgorithm(type: AsymmetricAlgorithmType.rsa, keySize: number): RSAKeyAlgorithm;
export function createAsymmetricAlgorithm(type: AsymmetricAlgorithmType, options?: any): EllipticAlgorithm | RSAKeyAlgorithm | undefined {
  switch (type) {
  case AsymmetricAlgorithmType.x448:
    return createEllipticAsymmetricAlgorithm(type, 'x448');
  case AsymmetricAlgorithmType.x25519:
    return createEllipticAsymmetricAlgorithm(type, 'x25519');
  case AsymmetricAlgorithmType.edwards:
  case AsymmetricAlgorithmType.ec:
    return createEllipticAsymmetricAlgorithm(type, options);
  case AsymmetricAlgorithmType.rsa:
    return new RSAKeyAlgorithm(type, true, true, true, options);
  }
  return undefined;
}

function createEllipticAsymmetricAlgorithm(type: AsymmetricAlgorithmType, keySpec: string | ECParametersChoice): EllipticAlgorithm {
  let ec: Curve | undefined;
  let oid = getOidFromAsymmetricAlgorithmType(type);
  let ecParam: ECParametersChoice | undefined = undefined;
  if (typeof keySpec === 'string') {
    ec = getCurveByOid(keySpec);
    if (!ec) {
      ec = getCurveByName(keySpec);
    }
    if (ec) ecParam = new ECParametersChoice({namedCurve: ec.oid});
  } else if (keySpec.namedCurve) {
    ec = getCurveByOid(keySpec.namedCurve);
    if (ec) ecParam = new ECParametersChoice({namedCurve: ec.oid});
  } else {
    const ecParameters = keySpec.ecParameters;
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
      signable: true,
      keyAgreementable: true,
      cryptable: false
    };
    ec = {
      preset: new elliptic.curves.PresetCurve(curveOptions),
      options: curveOptions,
      compiled: compileCurve(curveOptions as CurveOptions)
    };
    ec.options.byteLength = ec.compiled.p.bitLength() / 8;
    ecParam = new ECParametersChoice({ecParameters: ecParameters});
  }
  if (!ec || !ecParam) {
    throw new Error('Could not find algorithm: ' + keySpec);
  }
  return new EllipticAlgorithm(AsymmetricAlgorithmType.ec, new elliptic.ec(ec.preset), ec.options, oid, ecParam);
}

