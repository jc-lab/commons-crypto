import * as asn1js from 'asn1js';
import BN from 'bn.js';
import {AsnParser, AsnSerializer, OctetString} from '@peculiar/asn1-schema';
import {PrivateKeyInfo} from '@peculiar/asn1-pkcs8';
import {DigestInfo, RSAPrivateKey, RSAPublicKey} from '@peculiar/asn1-rsa';
import {AlgorithmIdentifier, ParametersType} from '@peculiar/asn1-x509';
import {
  AlgorithmKeyImportOptions,
  AsymmetricAlgorithmType,
  AsymmetricKeyAlgorithm,
  AsymmetricKeyObject,
  KeyExportOptions
} from '../interfaces';
import * as rdsaSignature from '../impl/rdsa-signature';
import {arrayBufferToBuffer, bufferToArrayBuffer} from '../../utils';
import {PublicKeyInfo} from '../impl/asn/PublicKeyInfo';
import {RSAKeyObject} from '../asym-key/rsa';

import {
  publicEncrypt,
  privateDecrypt
} from '../impl/public-encrypt';
import {KeyParams} from '../intl';

export class RSAKeyAlgorithm extends AsymmetricKeyAlgorithm {
  private readonly _keySize: number;

  constructor(type: AsymmetricAlgorithmType, signable: boolean, keyAgreementable: boolean, cryptable: boolean, keySize: number) {
    super(type, signable, keyAgreementable, cryptable);
    this._keySize = keySize;
  }

  clone(keySize?: number): RSAKeyAlgorithm {
    const _keySize = keySize || this._keySize;
    return new RSAKeyAlgorithm(this.type, this.signable, this.keyAgreementable, this.cryptable, _keySize);
  }

  dhComputeSecret(publicKey: AsymmetricKeyObject, privateKey: AsymmetricKeyObject): Buffer {
    throw new Error('Not supported operation');
  }

  privateDecrypt(data: Buffer, privateKey: AsymmetricKeyObject): Buffer {
    const _privateKey = privateKey as RSAKeyObject;
    return privateDecrypt(_privateKey.getBNPrivateKey(), data);
  }

  publicEncrypt(data: Buffer, publicKey: AsymmetricKeyObject): Buffer {
    const _publicKey = publicKey as RSAKeyObject;
    return publicEncrypt(_publicKey.getBNPublicKey(), data);
  }

  sign(digestOid: asn1js.ObjectIdentifier | string | null, hash: Buffer, privateKey: AsymmetricKeyObject): Buffer {
    if (!this._signable) {
      throw new Error('Not supported operation');
    }
    if (!digestOid) {
      throw new Error('digestOid must not null');
    }
    const digestInfo = new DigestInfo({
      digestAlgorithm: new AlgorithmIdentifier({
        algorithm: (typeof digestOid === 'string') ? digestOid : digestOid.valueBlock.toString()
      }),
      digest: new OctetString(hash)
    });
    return rdsaSignature.rsaSign(
      (privateKey as RSAKeyObject).getBNPrivateKey(),
      arrayBufferToBuffer(AsnSerializer.serialize(digestInfo))
    );
  }

  verify(digestOid: asn1js.ObjectIdentifier | string | null, hash: Buffer, signature: Buffer, privateKey: AsymmetricKeyObject): boolean {
    if (!this._signable) {
      throw new Error('Not supported operation');
    }
    if (!digestOid) {
      throw new Error('digestOid must not null');
    }
    const digestInfo = new DigestInfo({
      digestAlgorithm: new AlgorithmIdentifier({
        algorithm: (typeof digestOid === 'string') ? digestOid : digestOid.valueBlock.toString()
      }),
      digest: new OctetString(hash)
    });
    return rdsaSignature.rsaVerify(
      (privateKey as RSAKeyObject).getBNPublicKey(),
      signature,
      arrayBufferToBuffer(AsnSerializer.serialize(digestInfo))
    );
  }

  generateKeyPair(): { privateKey: AsymmetricKeyObject; publicKey: AsymmetricKeyObject } {
    return {} as any;
  }

  _keyExport(key: AsymmetricKeyObject, options?: KeyExportOptions<'der' | 'pem'>): {
    data: Buffer,
    pemTitle: string
  } {
    throw new Error('Not implemented yet');
  }

  _keyImport(key: Buffer, pemTitle: string | null, options?: AlgorithmKeyImportOptions<'der' | 'pem'>): AsymmetricKeyObject {
    let type = pemTitle ? pemTitle : null;
    const asn = asn1js.fromBER(bufferToArrayBuffer(key));
    let privateKeyInfo!: PrivateKeyInfo;
    let asnRsaPrivateKey!: RSAPrivateKey;
    let asnRsaPublicKey!: RSAPublicKey;
    let publicKeyInfo!: PublicKeyInfo;
    if (!type) {
      do {
        try {
          privateKeyInfo = AsnParser.fromASN(asn.result, PrivateKeyInfo);
          type = 'PRIVATE KEY';
          asnRsaPrivateKey = AsnParser.parse(privateKeyInfo.privateKey, RSAPrivateKey);
          break;
        } catch (e) {
          // Ignore
        }

        try {
          publicKeyInfo = AsnParser.fromASN(asn.result, PublicKeyInfo);
          type = 'PUBLIC KEY';
          asnRsaPublicKey = AsnParser.parse(publicKeyInfo.subjectPublicKey, RSAPublicKey);
          break;
        } catch (e) {
          // Ignore
        }

        if (asn.result instanceof asn1js.Sequence) {
          const seqLength = asn.result.valueBlock.value.length;
          if (seqLength === 2) {
            try {
              asnRsaPublicKey = AsnParser.fromASN(asn.result, RSAPublicKey);
              type = 'RSA PUBLIC KEY';
              break;
            } catch (e) {
              // Ignore
            }
          }
          try {
            asnRsaPrivateKey = AsnParser.fromASN(asn.result, RSAPrivateKey);
            type = 'RSA PRIVATE KEY';
            break;
          } catch (e) {
            // Ignore
          }
        }
      } while (0);
    } else {
      if (type === 'PRIVATE KEY') {
        privateKeyInfo = AsnParser.fromASN(asn.result, PrivateKeyInfo);
        asnRsaPrivateKey = AsnParser.parse(privateKeyInfo.privateKey, RSAPrivateKey);
      } else if (type === 'RSA PRIVATE KEY') {
        asnRsaPrivateKey = AsnParser.fromASN(asn.result, RSAPrivateKey);
      } else if (type === 'RSA PUBLIC KEY') {
        asnRsaPublicKey = AsnParser.fromASN(asn.result, RSAPublicKey);
      } else if (type === 'PUBLIC KEY') {
        publicKeyInfo = AsnParser.fromASN(asn.result, PublicKeyInfo);
        asnRsaPublicKey = AsnParser.parse(publicKeyInfo.subjectPublicKey, RSAPublicKey);
      }
    }
    if (
      (type != 'PRIVATE KEY') &&
      (type != 'RSA PRIVATE KEY') &&
      (type != 'RSA PUBLIC KEY') &&
      (type != 'PUBLIC KEY')
    ) {
      throw new Error('Not supported key type: ' + type);
    }

    // if (asnRsaPrivateKey && type.startsWith('RSA')) {
    //   asnRsaPrivateKey = new RSAPrivateKey();
    //   new asn1js.OctetString({
    //     valueHex: asnRsaPrivateKey.toBER()
    //   });
    // } else if (asnRsaPublicKey && type.startsWith('RSA')) {
    //   asnRsaPublicKey = new asn1js.OctetString({
    //     valueHex: asnRsaPublicKey.toBER()
    //   });
    // }

    if (type.endsWith('PRIVATE KEY')) {
      return fromRSAKey({
        type: AsymmetricAlgorithmType.rsa,
        keyType: 'private',
        asn1KeyParams: null,
        asn1KeyObject: asnRsaPrivateKey,
        signable: true,
        keyAgreementable: true,
        cryptable: true
      }, true);
    } else if (type.endsWith('PUBLIC KEY')) {
      return fromRSAKey({
        type: AsymmetricAlgorithmType.rsa,
        keyType: 'public',
        asn1KeyParams: null,
        asn1KeyObject: asnRsaPublicKey,
        signable: true,
        keyAgreementable: true,
        cryptable: true
      }, true);
    }
    throw new Error('Unknown error');
  }
}


function fromRSAKey(options: KeyParams<ParametersType | undefined, ArrayBuffer>): AsymmetricKeyObject;
function fromRSAKey(options: KeyParams<ParametersType | undefined, RSAPrivateKey | RSAPublicKey>, decoded: true): AsymmetricKeyObject;
function fromRSAKey(options: KeyParams<ParametersType | undefined, any>, decoded?: boolean): AsymmetricKeyObject {
  const asn = decoded ? null : asn1js.fromBER(options.asn1KeyObject);
  let bnPrivateKey;
  let bnPublicKey;
  if (options.keyType === 'private') {
    const asnKey: RSAPrivateKey = asn ? AsnParser.fromASN(asn.result, RSAPrivateKey) : options.asn1KeyObject;
    bnPrivateKey = {
      privateExponent: new BN(arrayBufferToBuffer(asnKey.privateExponent)),
      publicExponent: new BN(arrayBufferToBuffer(asnKey.publicExponent)),
      modulus: new BN(arrayBufferToBuffer(asnKey.modulus)),
      prime1: new BN(arrayBufferToBuffer(asnKey.prime1)),
      prime2: new BN(arrayBufferToBuffer(asnKey.prime2)),
      exponent1: new BN(arrayBufferToBuffer(asnKey.exponent1)),
      exponent2: new BN(arrayBufferToBuffer(asnKey.exponent2)),
      coefficient: new BN(arrayBufferToBuffer(asnKey.coefficient))
    };
    bnPublicKey = {
      publicExponent: new BN(bnPrivateKey.publicExponent),
      modulus: new BN(bnPrivateKey.modulus)
    };
  } else {
    const asnPublicKey: RSAPublicKey = asn ? AsnParser.fromASN(asn.result, RSAPublicKey) : options.asn1KeyObject;
    bnPublicKey = {
      publicExponent: new BN(arrayBufferToBuffer(asnPublicKey.publicExponent)),
      modulus: new BN(arrayBufferToBuffer(asnPublicKey.modulus))
    };
  }
  const algo: RSAKeyAlgorithm = new RSAKeyAlgorithm(
    AsymmetricAlgorithmType.rsa, true, true, true, bnPublicKey.modulus.bitLength()
  );
  return new RSAKeyObject(algo, options, bnPrivateKey, bnPublicKey);
}
