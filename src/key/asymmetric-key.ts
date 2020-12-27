import * as crypto from 'crypto';
import { AsnParser } from '@peculiar/asn1-schema';

import {
  RSAPrivateKey,
  RSAPublicKey
} from '@peculiar/asn1-rsa';
import {
  AlgorithmIdentifier,
  Certificate
} from '@peculiar/asn1-x509';
import {
  PrivateKeyInfo
} from '@peculiar/asn1-pkcs8';

import { ECPrivateKey } from './impl/asn/ECPrivateKey';
import { PublicKeyInfo } from './impl/asn/PublicKeyInfo';

import {
  AsymmetricAlgorithmType,
  AsymmetricKeyObject,
} from './interfaces';

import {
  bufferToArrayBuffer,
} from '../utils';

import {ECParametersChoice} from './impl/asn/ECParameters';
import {fromRSAKey} from './asym-key/rsa';
import {fromCurve} from './asym-key/elliptic';

import { createAsymmetricKeyFromPrivateKeyInfo, fromKeyObjectAndOid } from './key-parse';

export function createAsymmetricKeyFromNode(key: crypto.KeyObject): AsymmetricKeyObject {
  let privateKeyInfo: PrivateKeyInfo | null = null;
  let publicKeyInfo: PublicKeyInfo | null = null;

  if (key.type === 'private') {
    const ber = bufferToArrayBuffer(key.export({
      type: 'pkcs8',
      format: 'der'
    }));
    privateKeyInfo = AsnParser.parse(ber, PrivateKeyInfo);

    return createAsymmetricKeyFromPrivateKeyInfo(privateKeyInfo);
  }
  else if (key.type === 'public') {
    const ber = bufferToArrayBuffer(key.export({
      type: 'spki',
      format: 'der'
    }));
    publicKeyInfo = AsnParser.parse(ber, PublicKeyInfo);

    const algorithmIdentifier = publicKeyInfo.algorithm;

    return fromKeyObjectAndOid(
      algorithmIdentifier.algorithm,
      'public',
      algorithmIdentifier.parameters,
      publicKeyInfo.subjectPublicKey
    );
  }

  throw new Error('Not supported key');
}

export type PEMTitle = 'PRIVATE KEY' | 'PUBLIC KEY' | 'EC PRIVATE KEY' | 'RSA PRIVATE KEY' | 'RSA PUBLIC KEY' | 'CERTIFICATE';
export function createAsymmetricKeyFromAsn(pemTitle: 'PRIVATE KEY', asn: PrivateKeyInfo): AsymmetricKeyObject;
export function createAsymmetricKeyFromAsn(pemTitle: 'PUBLIC KEY', asn: PublicKeyInfo): AsymmetricKeyObject;
export function createAsymmetricKeyFromAsn(pemTitle: 'EC PRIVATE KEY', asn: ECPrivateKey): AsymmetricKeyObject;
export function createAsymmetricKeyFromAsn(pemTitle: 'RSA PRIVATE KEY', asn: RSAPrivateKey): AsymmetricKeyObject;
export function createAsymmetricKeyFromAsn(pemTitle: 'RSA PUBLIC KEY', asn: RSAPublicKey): AsymmetricKeyObject;
export function createAsymmetricKeyFromAsn(pemTitle: 'CERTIFICATE', asn: Certificate): AsymmetricKeyObject;
export function createAsymmetricKeyFromAsn(pemTitle: PEMTitle, asn: any): AsymmetricKeyObject {
  if (pemTitle === 'PRIVATE KEY') {
    return createAsymmetricKeyFromPrivateKeyInfo(asn as PrivateKeyInfo);
  } else if (pemTitle === 'EC PRIVATE KEY') {
    const ecPrivateKey = asn as ECPrivateKey;
    return fromCurve({
      curveOid: '1.2.840.10045.2.1',
      type: AsymmetricAlgorithmType.ec,
      keyType: 'private',
      asn1KeyParams: ecPrivateKey.parameters as ECParametersChoice,
      asn1KeyObject: ecPrivateKey.privateKey,
      signable: true,
      keyAgreementable: true,
      cryptable: false
    });
  } else if (pemTitle === 'RSA PRIVATE KEY') {
    const rsaPrivateKey = asn as RSAPrivateKey;
    return fromRSAKey({
      type: AsymmetricAlgorithmType.rsa,
      keyType: 'private',
      asn1KeyParams: null,
      asn1KeyObject: rsaPrivateKey,
      signable: true,
      keyAgreementable: true,
      cryptable: true
    }, true);
  } else if (pemTitle === 'RSA PUBLIC KEY') {
    const rsaPublicKey = asn as RSAPublicKey;
    return fromRSAKey({
      type: AsymmetricAlgorithmType.rsa,
      keyType: 'public',
      asn1KeyParams: null,
      asn1KeyObject: rsaPublicKey,
      signable: true,
      keyAgreementable: true,
      cryptable: true
    }, true);
  } else if (pemTitle === 'PUBLIC KEY') {
    const publicKeyInfo = asn as PublicKeyInfo;
    const algorithmIdentifier = publicKeyInfo.algorithm as AlgorithmIdentifier;
    return fromKeyObjectAndOid(
      algorithmIdentifier.algorithm,
      'public',
      algorithmIdentifier.parameters,
      publicKeyInfo.subjectPublicKey
    );
  } else if (pemTitle === 'CERTIFICATE') {
    const certificate = asn as Certificate;
    const publicKeyInfo = certificate.tbsCertificate.subjectPublicKeyInfo;
    const algorithmIdentifier = publicKeyInfo.algorithm as AlgorithmIdentifier;
    return fromKeyObjectAndOid(
      algorithmIdentifier.algorithm,
      'public',
      algorithmIdentifier.parameters,
      publicKeyInfo.subjectPublicKey
    );
  }
  throw new Error('Unknown error');
}

