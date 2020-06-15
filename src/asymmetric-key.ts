import * as crypto from 'crypto';
import * as elliptic from 'elliptic';
import * as hashjs from 'hash.js';
import * as asn1js from 'asn1js';
import BN from 'bn.js';
//@ts-ignore
import AlgorithmIdentifier from 'pkijs/build/AlgorithmIdentifier';
//@ts-ignore
import DigestInfo from 'pkijs/build/DigestInfo';
//@ts-ignore
import ECPublicKey from 'pkijs/build/ECPublicKey';
//@ts-ignore
import RSAPrivateKey from 'pkijs/build/RSAPrivateKey';
//@ts-ignore
import RSAPublicKey from 'pkijs/build/RSAPublicKey';
//@ts-ignore
import Certificate from 'pkijs/build/Certificate';
import ECPrivateKey from './impl/asn/ECPrivateKey';
import PrivateKeyInfo from './impl/asn/PrivateKeyInfo';
import PublicKeyInfo from './impl/asn/PublicKeyInfo';
import ECParameters from './impl/asn/ECParameters';

import {
  AlgorithmKeyImportOptions,
  AsymmetricAlgorithmType,
  AsymmetricKeyAlgorithm,
  AsymmetricKeyObject,
  KeyExportOptions,
  KeyExportType
} from './interfaces';

import {
  arrayBufferToBuffer,
  bufferToArrayBuffer
} from './utils';

import {
  Curve,
  CurveOptions,
  compileCurve,
  getCurveByOid
} from './impl/curves';
import ECDH from './impl/ecdh';
import * as rdsaSignature from './impl/rdsa-signature';
import * as asymInterfaces from './impl/asymmetric-interface';
import * as publicEncrypt from './impl/publicEncrypt';

type KeyType = 'private' | 'public';
interface KeyParams {
  curveOid?: string;
  keyType: KeyType;
  type: AsymmetricAlgorithmType;
  asn1KeyParams: any;
  asn1KeyObject: any;
  signable: boolean;
  keyAgreementable: boolean;
  cryptable: boolean;
}

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
    return publicEncrypt.privateDecrypt(_privateKey.getBNPrivateKey(), data);
  }

  publicEncrypt(data: Buffer, publicKey: AsymmetricKeyObject): Buffer {
    const _publicKey = publicKey as RSAKeyObject;
    return publicEncrypt.publicEncrypt(_publicKey.getBNPublicKey(), data);
  }

  sign(digestOid: asn1js.ObjectIdentifier | null, hash: Buffer, privateKey: AsymmetricKeyObject): Buffer {
    if (!this._signable) {
      throw new Error('Not supported operation');
    }
    if (!digestOid) {
      throw new Error('digestOid must not null');
    }
    const digestInfo = new DigestInfo({
      digestAlgorithm: new AlgorithmIdentifier({
        algorithmId: digestOid.valueBlock.toString()
      }),
      digest: new asn1js.OctetString({
        valueHex: hash
      })
    });
    return rdsaSignature.rsaSign(
      (privateKey as RSAKeyObject).getBNPrivateKey(),
      arrayBufferToBuffer(digestInfo.toSchema().toBER())
    );
  }

  verify(digestOid: asn1js.ObjectIdentifier | null, hash: Buffer, signature: Buffer, privateKey: AsymmetricKeyObject): boolean {
    if (!this._signable) {
      throw new Error('Not supported operation');
    }
    if (!digestOid) {
      throw new Error('digestOid must not null');
    }
    const digestInfo = new DigestInfo({
      digestAlgorithm: new AlgorithmIdentifier({
        algorithmId: digestOid.valueBlock.toString()
      }),
      digest: new asn1js.OctetString({
        valueHex: hash
      })
    });
    return rdsaSignature.rsaVerify(
      (privateKey as RSAKeyObject).getBNPublicKey(),
      signature,
      arrayBufferToBuffer(digestInfo.toSchema().toBER())
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
    let privateKeyInfo;
    let asnRsaPrivateKey;
    let asnRsaPublicKey;
    let publicKeyInfo;
    if (!type) {
      do {
        let result;
        result = asn1js.compareSchema(asn.result, asn.result, PrivateKeyInfo.schema());
        if (result.verified) {
          privateKeyInfo = new PrivateKeyInfo({
            schema: result.result
          });
          type = 'PRIVATE KEY';
          asnRsaPrivateKey = privateKeyInfo.privateKey;
          break;
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
          publicKeyInfo = new PublicKeyInfo({
            schema: result.result
          });
          type = 'PUBLIC KEY';
          asnRsaPublicKey = publicKeyInfo.subjectPublicKey;
          break;
        }

        if (asn.result instanceof asn1js.Sequence) {
          const seqLength = asn.result.valueBlock.value.length;
          if (seqLength === 2) {
            result = asn1js.compareSchema(asn.result, asn.result, RSAPublicKey.schema());
            if (result.verified) {
              asnRsaPublicKey = result.result;
              type = 'RSA PUBLIC KEY';
              break;
            }
          } else {
            result = asn1js.compareSchema(asn.result, asn.result, RSAPrivateKey.schema());
            if (result.verified) {
              asnRsaPrivateKey = result.result;
              type = 'RSA PRIVATE KEY';
              break;
            }
          }
        }
      } while (0);
    } else {
      if (type === 'PRIVATE KEY') {
        privateKeyInfo = new PrivateKeyInfo({
          schema: asn.result
        });
        asnRsaPrivateKey = privateKeyInfo.privateKey;
      } else if (type === 'RSA PRIVATE KEY') {
        asnRsaPrivateKey = new RSAPrivateKey({
          schema: asn.result
        }).toSchema();
      } else if (type === 'RSA PUBLIC KEY') {
        asnRsaPublicKey = new RSAPublicKey({
          schema: asn.result
        }).toSchema();
      } else if (type === 'PUBLIC KEY') {
        publicKeyInfo = new PublicKeyInfo({
          schema: asn.result
        });
        asnRsaPublicKey = publicKeyInfo.subjectPublicKey;
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

    if (asnRsaPrivateKey && type.startsWith('RSA')) {
      asnRsaPrivateKey = new asn1js.OctetString({
        valueHex: asnRsaPrivateKey.toBER()
      });
    } else if (asnRsaPublicKey && type.startsWith('RSA')) {
      asnRsaPublicKey = new asn1js.OctetString({
        valueHex: asnRsaPublicKey.toBER()
      });
    }

    if (type.endsWith('PRIVATE KEY')) {
      return fromRSAKey({
        type: AsymmetricAlgorithmType.rsa,
        keyType: 'private',
        asn1KeyParams: null,
        asn1KeyObject: asnRsaPrivateKey,
        signable: true,
        keyAgreementable: true,
        cryptable: true
      });
    } else if (type.endsWith('PUBLIC KEY')) {
      return fromRSAKey({
        type: AsymmetricAlgorithmType.rsa,
        keyType: 'public',
        asn1KeyParams: null,
        asn1KeyObject: asnRsaPublicKey,
        signable: true,
        keyAgreementable: true,
        cryptable: true
      });
    }
    throw new Error('Unknown error');
  }
}

export class EllipticAlgorithm extends AsymmetricKeyAlgorithm {
  private _algorithmOid: asn1js.ObjectIdentifier;
  private _namedCurveOid: asn1js.ObjectIdentifier | null = null;
  private _algorithmParams: asn1js.Any;
  private _ec: elliptic.ec;
  private _curveOptions: CurveOptions;

  constructor(
    type: AsymmetricAlgorithmType, signable: boolean, keyAgreementable: boolean, cryptable: boolean,
    ec: elliptic.ec, curveOptions: CurveOptions,
    algorithmOid: asn1js.ObjectIdentifier, namedCurveOid: asn1js.ObjectIdentifier | null,
    algorithmParams: asn1js.Any
  ) {
    super(type, signable, keyAgreementable, cryptable);
    this._ec = ec;
    this._curveOptions = curveOptions;
    this._algorithmOid = algorithmOid;
    this._algorithmParams = algorithmParams;
    this._namedCurveOid = namedCurveOid;
  }

  public isShortCurve() {
    return this._curveOptions.type === 'short';
  }

  public isEdwardsCurve() {
    return this._curveOptions.type === 'edwards';
  }

  public isMontCurve() {
    return this._curveOptions.type === 'mont';
  }

  public getElliptic(): elliptic.ec {
    return this._ec;
  }

  dhComputeSecret(publicKey: AsymmetricKeyObject, privateKey: AsymmetricKeyObject): Buffer {
    const ecdh = new ECDH(this._ec, this._curveOptions.byteLength);
    const _publicKey: EllipticKeyObject = publicKey as EllipticKeyObject;
    const _privateKey: EllipticKeyObject = privateKey as EllipticKeyObject;
    ecdh.setKeyPair(_privateKey.getECKeyPair());
    return ecdh.computeSecret(_publicKey.getECKeyPair()) as Buffer;
  }

  privateDecrypt(data: Buffer, privateKey: AsymmetricKeyObject): Buffer {
    throw new Error('Not supported operation');
  }

  publicEncrypt(data: Buffer, publicKey: AsymmetricKeyObject): Buffer {
    throw new Error('Not supported operation');
  }

  sign(digestOid: asn1js.ObjectIdentifier | null, hash: Buffer, privateKey: AsymmetricKeyObject): Buffer {
    if (!this._signable) {
      throw new Error('Not supported operation');
    }
    const _privateKey = privateKey as EllipticKeyObject;
    const signature = this._ec.sign(hash, _privateKey.getECKeyPair());
    return arrayBufferToBuffer(signature.toDER());
  }

  verify(digestOid: asn1js.ObjectIdentifier | null, hash: Buffer, signature: Buffer, publicKey: AsymmetricKeyObject): boolean {
    if (!this._signable) {
      throw new Error('Not supported operation');
    }
    const _publicKey = publicKey as EllipticKeyObject;
    return this._ec.verify(hash, signature.toString('hex'), _publicKey.getECKeyPair());
  }

  generateKeyPair(): { privateKey: AsymmetricKeyObject; publicKey: AsymmetricKeyObject } {
    const keyPair = this._ec.genKeyPair();
    const publicKp = this._ec.keyPair({
      pub: {
        x: keyPair.getPublic().getX(),
        y: keyPair.getPublic().getY()
      } as any
    });
    const privateKp = this._ec.keyPair({
      priv: keyPair.getPrivate().toArrayLike(Buffer)
    });
    const privateKey = EllipticKeyObject.fromEllipticKeyPair(
      this,
      privateKp
    );
    const publicKey = EllipticKeyObject.fromEllipticKeyPair(
      this,
      publicKp
    );
    return {
      privateKey,
      publicKey
    };
  }

  private _exportECPrivateKey(key: EllipticKeyObject, addAlgorithmParams?: boolean): ECPrivateKey {
    const publicKey = key.getECKeyPair().getPublic();
    const _addAlgorithmParams = (typeof addAlgorithmParams === 'undefined') ? true : addAlgorithmParams;
    const options: any = {
      version: 1,
      privateKey: new asn1js.OctetString({
        valueHex: key.getECKeyPair().getPrivate().toBuffer()
      })
    };
    if (_addAlgorithmParams) {
      options['algorithmParams'] = this._algorithmParams;
    }
    if (publicKey) {
      options['publicKey'] = this._exportECPublicKey(key);
    }
    return new ECPrivateKey(options);
  }

  private _exportECPublicKey(key: EllipticKeyObject): ECPublicKey {
    const publicKey = key.getECKeyPair().getPublic();
    return new ECPublicKey({
      x: publicKey.getX().toArrayLike(Buffer),
      y: publicKey.getY().toArrayLike(Buffer)
    });
  }

  _keyExport(key: AsymmetricKeyObject, options?: KeyExportOptions<'der' | 'pem'>): {
    data: Buffer,
    pemTitle: string
  } {
    const _key = key as EllipticKeyObject;
    let type: KeyExportType = options && options.type || 'specific';
    if (type === 'specific') {
      type = _key.isPrivate() ? 'specific-private' : 'specific-public';
    }
    switch (type) {
    case 'pkcs8':
    {
      const ecKey = this._exportECPrivateKey(_key, false);
      const privateKeyInfo = new PrivateKeyInfo({
        version: 0,
        privateKeyAlgorithm: new AlgorithmIdentifier({
          algorithmId: this._algorithmOid.valueBlock.toString(),
          algorithmParams: this._algorithmParams
        }),
        privateKey: new asn1js.OctetString({
          valueHex: ecKey.toSchema().toBER()
        })
      });
      return {
        data: arrayBufferToBuffer(privateKeyInfo.toSchema().toBER()),
        pemTitle: 'PRIVATE KEY'
      };
    }
    case 'specific-private':
    {
      const ecKey = this._exportECPrivateKey(_key);
      return {
        data: arrayBufferToBuffer(ecKey.toSchema().toBER()),
        pemTitle: 'EC PRIVATE KEY'
      };
    }
    case 'specific-public':
    case 'spki':
    {
      const ecPublicKey = this._exportECPublicKey(_key);
      const asnPublicKey = new PublicKeyInfo({
        algorithm: new AlgorithmIdentifier({
          algorithmId: this._algorithmOid.valueBlock.toString(),
          algorithmParams: this._algorithmParams
        }),
        subjectPublicKey: new asn1js.BitString({ valueHex: ecPublicKey.toSchema().toBER(false) })
      });
      return {
        data: arrayBufferToBuffer(asnPublicKey.toSchema().toBER()),
        pemTitle: 'PUBLIC KEY'
      };
    }
    }
    throw new Error('Not implemented yet');
  }

  _keyImport(key: Buffer, pemTitle: string | null, options?: AlgorithmKeyImportOptions<'der' | 'pem'>): AsymmetricKeyObject {
    let type = pemTitle ? pemTitle : null;
    const asn = asn1js.fromBER(bufferToArrayBuffer(key));
    let privateKeyInfo;
    let asnEcPrivateKey;
    let publicKeyInfo;
    if (!type) {
      do {
        let result;
        result = asn1js.compareSchema(asn.result, asn.result, PrivateKeyInfo.schema());
        if (result.verified) {
          privateKeyInfo = new PrivateKeyInfo({
            schema: result.result
          });
          type = 'PRIVATE KEY';
          break;
        }
        result = asn1js.compareSchema(asn.result, asn.result, ECPrivateKey.schema());
        if (result.verified) {
          asnEcPrivateKey = result.result;
          type = 'EC PRIVATE KEY';
          break;
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
          publicKeyInfo = new PublicKeyInfo({
            schema: result.result
          });
          type = 'PUBLIC KEY';
          break;
        }
      } while (0);
    } else {
      if (type === 'PRIVATE KEY') {
        privateKeyInfo = new PrivateKeyInfo({
          schema: asn.result
        });
      } else if (type === 'EC PRIVATE KEY') {
        asnEcPrivateKey = new ECPrivateKey({
          coordinateLength: this._curveOptions.byteLength,
          schema: asn.result
        }).toSchema();
      } else if (type === 'PUBLIC KEY') {
        publicKeyInfo = new PublicKeyInfo({
          schema: asn.result
        });
      }
    }
    if (
      (type != 'PRIVATE KEY') &&
      (type != 'EC PRIVATE KEY') &&
      (type != 'PUBLIC KEY')
    ) {
      throw new Error('Not supported key type: ' + type);
    }

    if (type === 'EC PRIVATE KEY') {
      return EllipticKeyObject.fromBinary(this, 'private', asnEcPrivateKey.toBER());
    } else if (type == 'PRIVATE KEY') {
      return createAsymmetricKeyFromPrivateKeyInfo(privateKeyInfo);
    } else if (type == 'PUBLIC KEY') {
      const algorithmIdentifier = new AlgorithmIdentifier({
        schema: publicKeyInfo.algorithm.toSchema()
      });
      return fromKeyObjectAndOid(
        algorithmIdentifier.algorithmId,
        'public',
        algorithmIdentifier.algorithmParams,
        publicKeyInfo.subjectPublicKey
      );
    }
    throw new Error('Unknown error');
  }
}

export class RSAKeyObject extends AsymmetricKeyObject {
  private _algo: RSAKeyAlgorithm;
  private _signPrivateKey: asymInterfaces.RSAPrivateKey | null;
  private _signPublicKey: asymInterfaces.RSAPublicKey;

  constructor(algo: RSAKeyAlgorithm, options: KeyParams, bnPrivateKey: asymInterfaces.RSAPrivateKey | null, bnPublicKey: asymInterfaces.RSAPublicKey) {
    super();

    this._algo = algo;
    this._signPrivateKey = bnPrivateKey;
    this._signPublicKey = bnPublicKey;
  }

  equals(o: RSAKeyObject): boolean {
    if (!o) {
      return false;
    }
    if (!(
      (this.isPrivate() && o.isPrivate()) || (this.isPublic() && o.isPublic())
    )) {
      return false;
    }
    if (this.isPrivate() && o.isPrivate()) {
      const thisBnKey = this._signPrivateKey as asymInterfaces.RSAPrivateKey;
      const otherBnKey = o._signPrivateKey as asymInterfaces.RSAPrivateKey;
      return (
        thisBnKey.publicExponent.eq(otherBnKey.publicExponent) &&
        thisBnKey.modulus.eq(otherBnKey.modulus) &&
        thisBnKey.privateExponent.eq(otherBnKey.privateExponent)
      );
    } else {
      const thisBnKey = this._signPublicKey as asymInterfaces.RSAPublicKey;
      const otherBnKey = o._signPublicKey as asymInterfaces.RSAPublicKey;
      return (
        thisBnKey.publicExponent.eq(otherBnKey.publicExponent) &&
        thisBnKey.modulus.eq(otherBnKey.modulus)
      );
    }
  }

  isPrivate(): boolean {
    return !!this._signPrivateKey;
  }

  isPublic(): boolean {
    return !!this._signPublicKey;
  }

  isSecret(): boolean {
    return false;
  }

  getKeyAlgorithm(): AsymmetricKeyAlgorithm {
    return this._algo;
  }

  public getBNPrivateKey(): RSAPrivateKey {
    return this._signPrivateKey as RSAPrivateKey;
  }

  public getBNPublicKey(): RSAPublicKey {
    return this._signPublicKey;
  }
}

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

function fromRSAKey(options: KeyParams, decoded?: boolean): AsymmetricKeyObject {
  const asn = decoded ? null : asn1js.fromBER(options.asn1KeyObject.valueBlock.valueHex);
  let bnPrivateKey;
  let bnPublicKey;
  if (options.keyType === 'private') {
    const asnKey = asn ? new RSAPrivateKey({
      schema: asn.result
    }) : options.asn1KeyObject;
    bnPrivateKey = {
      privateExponent: new BN(arrayBufferToBuffer(asnKey.privateExponent.valueBlock.valueHex)),
      publicExponent: new BN(arrayBufferToBuffer(asnKey.publicExponent.valueBlock.valueHex)),
      modulus: new BN(arrayBufferToBuffer(asnKey.modulus.valueBlock.valueHex)),
      prime1: new BN(arrayBufferToBuffer(asnKey.prime1.valueBlock.valueHex)),
      prime2: new BN(arrayBufferToBuffer(asnKey.prime2.valueBlock.valueHex)),
      exponent1: new BN(arrayBufferToBuffer(asnKey.exponent1.valueBlock.valueHex)),
      exponent2: new BN(arrayBufferToBuffer(asnKey.exponent2.valueBlock.valueHex)),
      coefficient: new BN(arrayBufferToBuffer(asnKey.coefficient.valueBlock.valueHex))
    };
    bnPublicKey = {
      publicExponent: new BN(bnPrivateKey.publicExponent),
      modulus: new BN(bnPrivateKey.modulus)
    };
  } else {
    const asnPublicKey = asn ? new RSAPublicKey({
      schema: asn.result
    }) : options.asn1KeyObject;
    bnPublicKey = {
      publicExponent: new BN(arrayBufferToBuffer(asnPublicKey.publicExponent.valueBlock.valueHex)),
      modulus: new BN(arrayBufferToBuffer(asnPublicKey.modulus.valueBlock.valueHex))
    };
  }
  const algo: RSAKeyAlgorithm = new RSAKeyAlgorithm(
    AsymmetricAlgorithmType.rsa, true, true, true, bnPublicKey.modulus.bitLength()
  );
  return new RSAKeyObject(algo, options, bnPrivateKey, bnPublicKey);
}

function fromCurve(options: KeyParams): EllipticKeyObject {
  let ec: Curve | undefined;
  let namedOid: asn1js.ObjectIdentifier | null = null;
  if (options.asn1KeyParams instanceof asn1js.ObjectIdentifier) {
    namedOid = options.asn1KeyParams;
    ec = getCurveByOid(namedOid.valueBlock.toString());
  } else {
    const ecParameters = new ECParameters({
      schema: options.asn1KeyParams
    });
    const p = ecParameters.fieldID.valueBlock.value[1] as asn1js.Integer;
    const gLength = (ecParameters.base.valueBlock.valueHex.byteLength - 1) / 2;
    const g = [
      arrayBufferToBuffer(ecParameters.base.valueBlock.valueHex.slice(1, 1 + gLength)).toString('hex'),
      arrayBufferToBuffer(ecParameters.base.valueBlock.valueHex.slice(1 + gLength, 1 + gLength + gLength)).toString('hex')
    ];
    const curveOptions: CurveOptions = {
      type: 'short',
      prime: null,
      p: arrayBufferToBuffer(p.valueBlock.valueHex).toString('hex'),
      a: arrayBufferToBuffer(ecParameters.curve.a.valueBlock.valueHex).toString('hex'),
      b: arrayBufferToBuffer(ecParameters.curve.b.valueBlock.valueHex).toString('hex'),
      n: arrayBufferToBuffer(ecParameters.order.valueBlock.valueHex).toString('hex'),
      hash: hashjs.sha256,
      gRed: false,
      g: g,
      byteLength: 0
    };
    ec = {
      preset: new elliptic.curves.PresetCurve(curveOptions),
      options: curveOptions,
      compiled: compileCurve(curveOptions as CurveOptions)
    };
    ec.options.byteLength = ec.compiled.p.bitLength() / 8;
  }
  if (!ec) {
    throw new Error('Not supported Key: ' + (namedOid ? namedOid.valueBlock.toString() : 'null'));
  }
  const algo = new EllipticAlgorithm(
    options.type, options.signable, options.keyAgreementable, options.cryptable,
    new elliptic.ec(ec.preset), ec.options,
    new asn1js.ObjectIdentifier({
      value: options.curveOid
    }),
    namedOid, options.asn1KeyParams
  );
  return EllipticKeyObject.fromBinary(algo, options.keyType, options.asn1KeyObject.valueBlock.valueHex);
}

function fromKeyObjectAndOid(oid: string, keyType: KeyType, asn1KeyParams, asn1KeyObject): AsymmetricKeyObject {
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
      curveOid: oid,
      type: AsymmetricAlgorithmType.ec,
      keyType: keyType,
      asn1KeyParams: asn1KeyParams,
      asn1KeyObject: asn1KeyObject,
      signable: true,
      keyAgreementable: true,
      cryptable: false
    });
  case '1.3.101.110':
    // X25519
    return fromCurve({
      curveOid: oid,
      type: AsymmetricAlgorithmType.x25519,
      keyType: keyType,
      asn1KeyParams: asn1KeyParams,
      asn1KeyObject: asn1KeyObject,
      signable: false,
      keyAgreementable: true,
      cryptable: false
    });
  case '1.3.101.111':
    // X448
    return fromCurve({
      curveOid: oid,
      type: AsymmetricAlgorithmType.x448,
      keyType: keyType,
      asn1KeyParams: asn1KeyParams,
      asn1KeyObject: asn1KeyObject,
      signable: false,
      keyAgreementable: true,
      cryptable: false
    });
  case '1.3.101.112':
    // EdDSA25519
    return fromCurve({
      curveOid: oid,
      type: AsymmetricAlgorithmType.edwards,
      keyType: keyType,
      asn1KeyParams: asn1KeyParams,
      asn1KeyObject: asn1KeyObject,
      signable: true,
      keyAgreementable: false,
      cryptable: false
    });
  case '1.3.101.113':
    // EdDSA448
    return fromCurve({
      curveOid: oid,
      type: AsymmetricAlgorithmType.edwards,
      keyType: keyType,
      asn1KeyParams: asn1KeyParams,
      asn1KeyObject: asn1KeyObject,
      signable: true,
      keyAgreementable: false,
      cryptable: false
    });
  }
  throw new Error('Not supported key');
}

function createAsymmetricKeyFromPrivateKeyInfo(privateKeyInfo: PrivateKeyInfo): AsymmetricKeyObject {
  const algorithmIdentifier = privateKeyInfo.privateKeyAlgorithm;
  return fromKeyObjectAndOid(
    algorithmIdentifier.algorithmId,
    'private',
    algorithmIdentifier.algorithmParams,
    privateKeyInfo.privateKey
  );
}

export function createAsymmetricKeyFromNode(key: crypto.KeyObject): AsymmetricKeyObject {
  let privateKeyInfo: PrivateKeyInfo | null = null;
  let publicKeyInfo: PublicKeyInfo | null = null;

  if (key.type === 'private') {
    const ber = bufferToArrayBuffer(key.export({
      type: 'pkcs8',
      format: 'der'
    }));
    const {result} = asn1js.fromBER(ber);
    privateKeyInfo = new PrivateKeyInfo({
      schema: result
    });

    return createAsymmetricKeyFromPrivateKeyInfo(privateKeyInfo);
  }
  else if (key.type === 'public') {
    const ber = bufferToArrayBuffer(key.export({
      type: 'spki',
      format: 'der'
    }));
    const {result} = asn1js.fromBER(ber);
    publicKeyInfo = new PublicKeyInfo({
      schema: result
    });

    const algorithmIdentifier = publicKeyInfo.algorithm;

    return fromKeyObjectAndOid(
      algorithmIdentifier.algorithmId,
      'public',
      algorithmIdentifier.algorithmParams,
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
    return fromKeyObjectAndOid(
      '1.2.840.10045.2.1',
      'private',
      ecPrivateKey.algorithmParams,
      ecPrivateKey.privateKey
    );
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
      algorithmIdentifier.algorithmId,
      'public',
      algorithmIdentifier.algorithmParams,
      publicKeyInfo.subjectPublicKey
    );
  } else if (pemTitle === 'CERTIFICATE') {
    const certificate = asn as Certificate;
    const publicKeyInfo = certificate.subjectPublicKeyInfo;
    const algorithmIdentifier = publicKeyInfo.algorithm as AlgorithmIdentifier;
    return fromKeyObjectAndOid(
      algorithmIdentifier.algorithmId,
      'public',
      algorithmIdentifier.algorithmParams,
      publicKeyInfo.subjectPublicKey
    );
  }
  throw new Error('Unknown error');
}

