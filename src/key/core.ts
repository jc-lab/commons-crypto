import * as crypto from 'crypto';
import * as asn1js from 'asn1js';
import { AsnParser } from '@peculiar/asn1-schema';

import {
  RSAPrivateKey,
  RSAPublicKey
} from '@peculiar/asn1-rsa';
import {
  Certificate
} from '@peculiar/asn1-x509';
import {
  PrivateKeyInfo
} from '@peculiar/asn1-pkcs8';

import {
  AsymmetricKeyObject,
  PublicKeyInput,
  PrivateKeyInput,
  CertificateInput
} from './interfaces';

import {
  createAsymmetricKeyFromNode,
  createAsymmetricKeyFromAsn,
  PEMTitle
} from './asymmetric-key';
import {
  parsePem,
  bufferToArrayBuffer
} from '../utils';

import { ECPrivateKey } from './impl/asn/ECPrivateKey';
import { PublicKeyInfo } from './impl/asn/PublicKeyInfo';
import {
  CertificateObject,
  createCertificateFromAsn
} from '../cert/certificate';

function createAsymmetricKeyWithType(
  pemTitle: PEMTitle,
  asn: { offset: number, result: asn1js.AsnType }): AsymmetricKeyObject {
  if (pemTitle === 'PRIVATE KEY') {
    const privateKeyInfo = AsnParser.fromASN(asn.result, PrivateKeyInfo);
    return createAsymmetricKeyFromAsn(pemTitle, privateKeyInfo);
  } else if (pemTitle === 'PUBLIC KEY') {
    const publicKeyInfo = AsnParser.fromASN(asn.result, PublicKeyInfo);
    return createAsymmetricKeyFromAsn(pemTitle, publicKeyInfo);
  } else if (pemTitle === 'EC PRIVATE KEY') {
    const ecPrivateKey = AsnParser.fromASN(asn.result, ECPrivateKey);
    return createAsymmetricKeyFromAsn(pemTitle, ecPrivateKey);
  } else if (pemTitle === 'RSA PRIVATE KEY') {
    const rsaPrivateKey = AsnParser.fromASN(asn.result, RSAPrivateKey);
    return createAsymmetricKeyFromAsn(pemTitle, rsaPrivateKey);
  } else if (pemTitle === 'RSA PUBLIC KEY') {
    const rsaPublicKey = AsnParser.fromASN(asn.result, RSAPublicKey);
    return createAsymmetricKeyFromAsn(pemTitle, rsaPublicKey);
  } else if (pemTitle === 'CERTIFICATE') {
    const certificate = AsnParser.fromASN(asn.result, Certificate);
    return createAsymmetricKeyFromAsn(pemTitle, certificate);
  }
  throw new Error('Unknown pem title: ' + pemTitle);
}

/**
 * Create AsymmetricKeyObject with PrivateKey from der, pem or nodejs KeyObject.
 *
 * @param key input
 * @return AsymmetricKeyObject
 */
export function createPrivateKey(key: PrivateKeyInput | string | Buffer | crypto.KeyObject): AsymmetricKeyObject {
  if (typeof key === 'string') {
    return createAsymmetricKey({
      format: 'pem',
      key: key
    });
  } else if (key instanceof crypto.KeyObject) {
    return createAsymmetricKeyFromNode(key);
  } else {
    return createAsymmetricKeyFromNode(
      crypto.createPrivateKey(key)
    );
  }
}

/**
 * Create AsymmetricKeyObject with PublicKey from der, pem or nodejs KeyObject.
 *
 * @param key input
 * @return AsymmetricKeyObject
 */
export function createPublicKey(key: PublicKeyInput | string | Buffer | crypto.KeyObject): AsymmetricKeyObject  {
  if (typeof key === 'string') {
    return createAsymmetricKey({
      format: 'pem',
      key: key
    });
  } else if (key instanceof crypto.KeyObject) {
    return createAsymmetricKeyFromNode(key);
  } else {
    return createAsymmetricKeyFromNode(
      crypto.createPublicKey(key as any)
    );
  }
}

/**
 * Create AsymmetricKeyObject with PublicKey from der or pem
 *
 * @param key Public Key or Private Key
 */
export function createAsymmetricKey(key: PrivateKeyInput | PublicKeyInput): AsymmetricKeyObject {
  const format = key.format || (Buffer.isBuffer(key.key) ? 'der' : 'pem');
  let pemTitle: PEMTitle | null = null;
  let der: Buffer;

  if (key.type) {
    switch (key.type) {
    case 'pkcs8':
      pemTitle = 'PRIVATE KEY';
      break;
    case 'spki':
      pemTitle = 'PUBLIC KEY';
      break;
    case 'sec1':
      pemTitle = 'EC PRIVATE KEY';
      break;
    case 'x509':
      pemTitle = 'CERTIFICATE';
      break;
    }
  }

  if (format === 'pem') {
    const pemResult = parsePem(key.key as string);
    if (pemTitle && (pemTitle != pemResult.pemTitle)) {
      throw new Error(`Not matched PEM: need=${pemTitle}, input=${pemResult.pemTitle}`);
    }
    pemTitle = pemResult.pemTitle as PEMTitle;
    der = pemResult.der;
  } else {
    der = key.key as Buffer;
  }

  const asn = asn1js.fromBER(bufferToArrayBuffer(der));
  if (pemTitle) {
    return createAsymmetricKeyWithType(pemTitle, asn);
  }

  do {
    if (!key.type || (key.type === 'pkcs1')) {
      if (asn.result instanceof asn1js.Sequence) {
        const seqLength = asn.result.valueBlock.value.length;
        if (seqLength === 2) {
          try {
            AsnParser.fromASN(asn.result, RSAPublicKey);
            return createAsymmetricKeyWithType('RSA PUBLIC KEY', asn);
          } catch (e) {
            // Ignore error
          }
        } else {
          try {
            AsnParser.fromASN(asn.result, RSAPrivateKey);
            return createAsymmetricKeyWithType('RSA PRIVATE KEY', asn);
          } catch (e) {
            // Ignore error
          }
        }
      }
      if (key.type === 'pkcs1') {
        break;
      }
    }

    if (!key.type || (key.type === 'sec1')) {
      try {
        AsnParser.fromASN(asn.result, ECPrivateKey);
        return createAsymmetricKeyWithType('EC PRIVATE KEY', asn);
      } catch (e) {
        // Ignore error
      }
      if (key.type === 'sec1') {
        break;
      }
    }

    if (!key.type || (key.type === 'x509')) {
      try {
        AsnParser.fromASN(asn.result, Certificate);
        return createAsymmetricKeyWithType('CERTIFICATE', asn);
      } catch (e) {
        // Ignore error
      }
      if (key.type === 'x509') {
        break;
      }
    }

    try {
      AsnParser.fromASN(asn.result, PrivateKeyInfo);
      return createAsymmetricKeyWithType('PRIVATE KEY', asn);
    } catch (e) {
      // Ignore error
    }

    try {
      AsnParser.fromASN(asn.result, PublicKeyInfo);
      return createAsymmetricKeyWithType('PUBLIC KEY', asn);
    } catch (e) {
      // Ignore error
    }
  } while (0);

  throw new Error('Unknown type');
}

export function createCertificate(cert: CertificateInput | string | Buffer): CertificateObject {
  if (typeof cert === 'string') {
    return createCertificate({
      format: 'pem',
      key: cert
    });
  } else if (Buffer.isBuffer(cert)) {
    return createCertificate({
      format: 'der',
      key: cert
    });
  } else {
    const format = cert.format || (Buffer.isBuffer(cert.key) ? 'der' : 'pem');
    let der: Buffer;

    if (format === 'pem') {
      const pemResult = parsePem(cert.key as string);
      der = pemResult.der;
    } else {
      der = cert.key as Buffer;
    }

    const asn = asn1js.fromBER(bufferToArrayBuffer(der));
    const certificate = AsnParser.fromASN(asn.result, Certificate);
    return createCertificateFromAsn(certificate);
  }
}
