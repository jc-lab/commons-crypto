import * as crypto from 'crypto';

import * as utils from './utils';
import * as rdsaSignature from './impl/rdsa-signature';
import * as curves from './impl/curves';
import * as ecdh from './impl/ecdh';

import * as asn1js from 'asn1js';

import {
  AsymmetricKeyObject,
  PublicKeyInput,
  PrivateKeyInput
} from './interfaces';

export * from './interfaces';
export * from './asymmetric-key';

import {
  EllipticAlgorithm,
  EllipticKeyObject,
  RSAKeyAlgorithm,
  RSAKeyObject,
  createAsymmetricKeyFromNode,
  createAsymmetricKeyFromAsn, PEMTitle
} from './asymmetric-key';
import {
  parsePem,
  bufferToArrayBuffer
} from './utils';
import RSAPrivateKey from 'pkijs/build/RSAPrivateKey';
import RSAPublicKey from 'pkijs/build/RSAPublicKey';
import Certificate from 'pkijs/build/Certificate';
import PrivateKeyInfo from './impl/asn/PrivateKeyInfo';
import PublicKeyInfo from './impl/asn/PublicKeyInfo';
import ECCurve from './impl/asn/ECCurve';
import ECParameters from './impl/asn/ECParameters';
import ECPrivateKey from './impl/asn/ECPrivateKey';
import ECPublicKey from './impl/asn/ECPublicKey';

const impls = Object.freeze({
  rdsaSignature,
  curves,
  ecdh
});

const asn = Object.freeze({
  ECCurve,
  ECParameters,
  ECPrivateKey,
  ECPublicKey,
  PrivateKeyInfo,
  PublicKeyInfo
});

export {
  utils,
  impls,
  asn
};

function createAsymmetricKeyWithType(
  pemTitle: PEMTitle,
  asn: { offset: number, result: asn1js.LocalBaseBlock }): AsymmetricKeyObject {
  if (pemTitle === 'PRIVATE KEY') {
    const privateKeyInfo = new PrivateKeyInfo({
      schema: asn.result
    });
    return createAsymmetricKeyFromAsn(pemTitle, privateKeyInfo);
  } else if (pemTitle === 'PUBLIC KEY') {
    const publicKeyInfo = new PublicKeyInfo({
      schema: asn.result
    });
    return createAsymmetricKeyFromAsn(pemTitle, publicKeyInfo);
  } else if (pemTitle === 'EC PRIVATE KEY') {
    const ecPrivateKey = new ECPrivateKey({
      schema: asn.result
    });
    return createAsymmetricKeyFromAsn(pemTitle, ecPrivateKey);
  } else if (pemTitle === 'RSA PRIVATE KEY') {
    const rsaPrivateKey = new RSAPrivateKey({
      schema: asn.result
    });
    return createAsymmetricKeyFromAsn(pemTitle, rsaPrivateKey);
  } else if (pemTitle === 'RSA PUBLIC KEY') {
    const rsaPublicKey = new RSAPublicKey({
      schema: asn.result
    });
    return createAsymmetricKeyFromAsn(pemTitle, rsaPublicKey);
  } else if (pemTitle === 'CERTIFICATE') {
    const rsaPublicKey = new Certificate({
      schema: asn.result
    });
    return createAsymmetricKeyFromAsn(pemTitle, rsaPublicKey);
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
  if (key instanceof crypto.KeyObject) {
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
  if (key instanceof crypto.KeyObject) {
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
          const result = asn1js.compareSchema(asn.result, asn.result, RSAPublicKey.schema());
          if (result.verified) {
            return createAsymmetricKeyWithType('RSA PUBLIC KEY', asn);
          }
        } else {
          const result = asn1js.compareSchema(asn.result, asn.result, RSAPrivateKey.schema());
          if (result.verified) {
            return createAsymmetricKeyWithType('RSA PRIVATE KEY', asn);
          }
        }
      }
      if (key.type === 'pkcs1') {
        break;
      }
    }

    if (!key.type || (key.type === 'sec1')) {
      const result = asn1js.compareSchema(asn.result, asn.result, ECPrivateKey.schema());
      if (result.verified) {
        return createAsymmetricKeyWithType('EC PRIVATE KEY', asn);
      }
      if (key.type === 'sec1') {
        break;
      }
    }

    if (!key.type || (key.type === 'x509')) {
      const result = asn1js.compareSchema(asn.result, asn.result, Certificate.schema());
      if (result.verified) {
        return createAsymmetricKeyWithType('CERTIFICATE', asn);
      }
      if (key.type === 'x509') {
        break;
      }
    }

    let result;
    result = asn1js.compareSchema(asn.result, asn.result, PrivateKeyInfo.schema());
    if (result.verified) {
      return createAsymmetricKeyWithType('PRIVATE KEY', asn);
    }
    result = asn1js.compareSchema(asn.result, asn.result, PublicKeyInfo.schema({
      names: {
        algorithm: {
          names: {
            blockName: 'algorithm'
          }
        },
        subjectPublicKey: 'subjectPublicKey'
      }
    }));
    if (result.verified) {
      return createAsymmetricKeyWithType('PUBLIC KEY', asn);
    }
  } while (0);

  throw new Error('Unknown type');
}

