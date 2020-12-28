import {ECParametersChoice} from './impl/asn/ECParameters';
import {Curve, getCurveByName, getCurveByOid} from './impl/curves';
import {EllipticAlgorithm, fromCurve} from './asym-algorithm/elliptic';
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
  const oid = getOidFromAsymmetricAlgorithmType(type);
  switch (type) {
  case AsymmetricAlgorithmType.x448:
  case AsymmetricAlgorithmType.x25519:
    return fromCurve({
      algorithmOid: oid,
      type: type,
      asn1KeyParams: null,
      signable: false,
      keyAgreementable: true,
      cryptable: false
    }, true);
  case AsymmetricAlgorithmType.edwards:
    return createECDSAAlgorithm(options);
  case AsymmetricAlgorithmType.ec:
    return createEllipticAsymmetricAlgorithm(type, options);
  case AsymmetricAlgorithmType.rsa:
    return new RSAKeyAlgorithm(type, true, true, true, options);
  }
  return undefined;
}

function createECDSAAlgorithm(keySpec: string): EllipticAlgorithm {
  let ec: Curve | undefined;
  ec = getCurveByOid(keySpec);
  if (!ec) {
    ec = getCurveByName(keySpec);
  }
  if (!ec) {
    throw new Error('Could not find algorithm: ' + keySpec);
  }
  return fromCurve({
    algorithmOid: ec.oid as string,
    type: AsymmetricAlgorithmType.edwards,
    asn1KeyParams: null,
    signable: true,
    keyAgreementable: false,
    cryptable: false
  }, true);
}

function createEllipticAsymmetricAlgorithm(type: AsymmetricAlgorithmType, keySpec: string | ECParametersChoice): EllipticAlgorithm {
  let oid = getOidFromAsymmetricAlgorithmType(type);
  let ecParam: ECParametersChoice | undefined = undefined;
  if (typeof keySpec === 'string') {
    let ec: Curve | undefined;
    ec = getCurveByOid(keySpec);
    if (!ec) {
      ec = getCurveByName(keySpec);
    }
    if (ec) ecParam = new ECParametersChoice({namedCurve: ec.oid});
  } else {
    ecParam = keySpec;
  }
  if (!ecParam) {
    throw new Error('Could not find algorithm: ' + keySpec);
  }
  return fromCurve({
    algorithmOid: oid,
    type: AsymmetricAlgorithmType.edwards,
    asn1KeyParams: ecParam,
    signable: true,
    keyAgreementable: false,
    cryptable: false
  });
}

