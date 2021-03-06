import {PrivateKeyInfo} from '@peculiar/asn1-pkcs8';
import {AsymmetricAlgorithmType, AsymmetricKeyObject} from './interfaces';
import {KeyType} from './intl';
import {ParametersType} from '@peculiar/asn1-x509';
import {fromRSAKey} from './asym-key/rsa';
import {fromCurve} from './asym-algorithm/elliptic';

export function fromKeyObjectAndOid(oid: string, keyType: KeyType, asn1KeyParams: ParametersType | undefined, asn1KeyObject: ArrayBuffer): AsymmetricKeyObject {
  switch (oid) {
  case '1.2.840.113549.1.1.1':
    // RSAPrivateKey
    return fromRSAKey({
      type: AsymmetricAlgorithmType.rsa,
      keyType: keyType,
      asn1KeyParams: asn1KeyParams,
      asn1KeyObject: asn1KeyObject,
      signable: true,
      keyAgreementable: true,
      cryptable: true
    });
  case '1.2.840.10040.4.1':
    // DSAparam;
    return fromRSAKey({
      type: AsymmetricAlgorithmType.dsa,
      keyType: keyType,
      asn1KeyParams: asn1KeyParams,
      asn1KeyObject: asn1KeyObject,
      signable: true,
      keyAgreementable: true,
      cryptable: true
    });
  case '1.2.840.10045.2.1':
    // Curve
    return fromCurve({
      algorithmOid: oid,
      type: AsymmetricAlgorithmType.ec,
      asn1KeyParams: asn1KeyParams as ArrayBuffer,
      signable: true,
      keyAgreementable: true,
      cryptable: false
    }).asnKeyObjectToKey(keyType, asn1KeyObject);
  case '1.3.101.110':
    // X25519
    return fromCurve({
      algorithmOid: oid,
      type: AsymmetricAlgorithmType.x25519,
      asn1KeyParams: null,
      signable: false,
      keyAgreementable: true,
      cryptable: false
    }, true).asnKeyObjectToKey(keyType, asn1KeyObject);
  case '1.3.101.111':
    // X448
    return fromCurve({
      algorithmOid: oid,
      type: AsymmetricAlgorithmType.x448,
      asn1KeyParams: null,
      signable: false,
      keyAgreementable: true,
      cryptable: false
    }, true).asnKeyObjectToKey(keyType, asn1KeyObject);
  case '1.3.101.112':
    // EdDSA25519
    return fromCurve({
      algorithmOid: oid,
      type: AsymmetricAlgorithmType.edwards,
      asn1KeyParams: null,
      signable: true,
      keyAgreementable: false,
      cryptable: false
    }, true).asnKeyObjectToKey(keyType, asn1KeyObject);
  case '1.3.101.113':
    // EdDSA448
    return fromCurve({
      algorithmOid: oid,
      type: AsymmetricAlgorithmType.edwards,
      asn1KeyParams: null,
      signable: true,
      keyAgreementable: false,
      cryptable: false
    }, true).asnKeyObjectToKey(keyType, asn1KeyObject);
  }
  throw new Error('Not supported key');
}

export function createAsymmetricKeyFromPrivateKeyInfo(privateKeyInfo: PrivateKeyInfo): AsymmetricKeyObject {
  const algorithmIdentifier = privateKeyInfo.privateKeyAlgorithm;
  return fromKeyObjectAndOid(
    algorithmIdentifier.algorithm,
    'private',
    algorithmIdentifier.parameters,
    privateKeyInfo.privateKey.buffer
  );
}
