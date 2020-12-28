import * as asn1js from 'asn1js';
import * as elliptic from 'elliptic';
import * as hashjs from 'hash.js';
import {AsnParser, AsnSerializer, OctetString} from '@peculiar/asn1-schema';
import {PrivateKeyInfo} from '@peculiar/asn1-pkcs8';
import {AlgorithmIdentifier} from '@peculiar/asn1-x509';
import {
  AlgorithmKeyImportOptions,
  AsymmetricAlgorithmType,
  AsymmetricKeyAlgorithm,
  AsymmetricKeyObject,
  KeyExportOptions,
  KeyExportType
} from '../interfaces';
import {ECParametersChoice} from '../impl/asn/ECParameters';
import {compileCurve, Curve, CurveOptions, getCurveByOid} from '../impl/curves';
import ECDH from '../impl/ecdh';
import {arrayBufferToBuffer, bufferToArrayBuffer} from '../../utils';
import {ECPrivateKey} from '../impl/asn/ECPrivateKey';
import {PublicKeyInfo} from '../impl/asn/PublicKeyInfo';
import {EllipticKeyObject} from '../asym-key/elliptic';
import { createAsymmetricKeyFromPrivateKeyInfo, fromKeyObjectAndOid } from '../key-parse';
import {KeyParams} from '../intl';

export class EllipticAlgorithm extends AsymmetricKeyAlgorithm {
  protected _namedCurveOid: string | null = null;
  protected _algorithmParams: ECParametersChoice | undefined;
  protected _ec: elliptic.ec;
  protected _curveOptions: CurveOptions;

  constructor(
    type: AsymmetricAlgorithmType,
    ec: elliptic.ec, curveOptions: CurveOptions,
    algorithmOid: string,
    algorithmParams: ECParametersChoice | undefined
  ) {
    super(type, curveOptions.signable, curveOptions.keyAgreementable, curveOptions.cryptable, algorithmOid);
    this._ec = ec;
    this._curveOptions = curveOptions;
    this._algorithmParams = algorithmParams;
    this._namedCurveOid = algorithmParams && algorithmParams.namedCurve || null;
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

  sign(digestOid: asn1js.ObjectIdentifier | string | null, hash: Buffer, privateKey: AsymmetricKeyObject): Buffer {
    if (!this._signable) {
      throw new Error('Not supported operation');
    }
    const _privateKey = privateKey as EllipticKeyObject;
    const signature = this._ec.sign(hash, _privateKey.getECKeyPair());
    return arrayBufferToBuffer(signature.toDER());
  }

  verify(digestOid: asn1js.ObjectIdentifier | string | null, hash: Buffer, signature: Buffer, publicKey: AsymmetricKeyObject): boolean {
    if (!this._signable) {
      throw new Error('Not supported operation');
    }
    const _publicKey = publicKey as EllipticKeyObject;
    return this._ec.verify(hash, signature.toString('hex'), _publicKey.getECKeyPair());
  }

  generateKeyPair(): { privateKey: AsymmetricKeyObject; publicKey: AsymmetricKeyObject } {
    const keyPair = this._ec.genKeyPair();
    const publicKp = this._ec.keyFromPublic(keyPair.getPublic().encode('array', false));
    const privateKp = this._ec.keyFromPrivate(keyPair.getPrivate().toArrayLike(Buffer));
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

  protected _exportECPrivateKey(key: EllipticKeyObject, addAlgorithmParams?: boolean): any {
    const publicKey = key.getECKeyPair().getPublic();
    const _addAlgorithmParams = (typeof addAlgorithmParams === 'undefined') ? true : addAlgorithmParams;
    const options: Partial<ECPrivateKey> = {
      version: 1,
      privateKey: key.getECKeyPair().getPrivate().toBuffer()
    };
    if (_addAlgorithmParams) {
      // Not required when export with PrivateKeyInfo
      options.parameters = this._algorithmParams;
    }
    if (publicKey) {
      options.publicKey = this._exportECPublicKey(key);
    }
    return new ECPrivateKey(options);
  }

  private _exportECPublicKey(key: EllipticKeyObject): ArrayBuffer {
    const publicKey = key.getECKeyPair().getPublic();
    return Buffer.from(publicKey.encode('array', false));
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
          algorithm: this._algorithmOid,
          parameters: this._algorithmParams && AsnSerializer.serialize(this._algorithmParams)
        }),
        privateKey: new OctetString(AsnSerializer.serialize(ecKey))
      });
      return {
        data: arrayBufferToBuffer(AsnSerializer.serialize(privateKeyInfo)),
        pemTitle: 'PRIVATE KEY'
      };
    }
    case 'specific-private':
    {
      const ecKey = this._exportECPrivateKey(_key);
      return {
        data: arrayBufferToBuffer(AsnSerializer.serialize(ecKey)),
        pemTitle: 'EC PRIVATE KEY'
      };
    }
    case 'specific-public':
    case 'spki':
    {
      const ecPublicKey = this._exportECPublicKey(_key);
      const asnPublicKey = new PublicKeyInfo({
        algorithm: new AlgorithmIdentifier({
          algorithm: this._algorithmOid,
          parameters: this._algorithmParams && AsnSerializer.serialize(this._algorithmParams)
        }),
        subjectPublicKey: ecPublicKey
      });
      return {
        data: arrayBufferToBuffer(AsnSerializer.serialize(asnPublicKey)),
        pemTitle: 'PUBLIC KEY'
      };
    }
    }
    throw new Error('Not implemented yet');
  }

  _keyImport(key: Buffer, pemTitle: string | null, options?: AlgorithmKeyImportOptions<'der' | 'pem'>): AsymmetricKeyObject {
    let type = pemTitle ? pemTitle : null;
    const asn = asn1js.fromBER(bufferToArrayBuffer(key));
    let privateKeyInfo!: PrivateKeyInfo;
    let asnEcPrivateKey!: ECPrivateKey;
    let publicKeyInfo!: PublicKeyInfo;
    if (!type) {
      do {
        try {
          privateKeyInfo = AsnParser.fromASN(asn.result, PrivateKeyInfo);
          type = 'PRIVATE KEY';
          break;
        } catch (e) {
          // Ignore
        }

        try {
          asnEcPrivateKey = AsnParser.fromASN(asn.result, ECPrivateKey);
          type = 'EC PRIVATE KEY';
          break;
        } catch (e) {
          // Ignore
        }

        try {
          publicKeyInfo = AsnParser.fromASN(asn.result, PublicKeyInfo);
          type = 'PUBLIC KEY';
          break;
        } catch (e) {
          // Ignore
        }
      } while (0);
    } else {
      if (type === 'PRIVATE KEY') {
        privateKeyInfo = AsnParser.fromASN(asn.result, PrivateKeyInfo);
      } else if (type === 'EC PRIVATE KEY') {
        asnEcPrivateKey = AsnParser.fromASN(asn.result, ECPrivateKey);
      } else if (type === 'PUBLIC KEY') {
        publicKeyInfo = AsnParser.fromASN(asn.result, PublicKeyInfo);
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
      return this.asnKeyObjectToKey('private', AsnSerializer.serialize(asnEcPrivateKey));
    } else if (type == 'PRIVATE KEY') {
      return createAsymmetricKeyFromPrivateKeyInfo(privateKeyInfo);
    } else if (type == 'PUBLIC KEY') {
      return fromKeyObjectAndOid(
        publicKeyInfo.algorithm.algorithm,
        'public',
        publicKeyInfo.algorithm.parameters,
        publicKeyInfo.subjectPublicKey
      );
    }
    throw new Error('Unknown error');
  }

  public rawToKey(type: 'private' | 'public', data: Uint8Array | Buffer | number[]): EllipticKeyObject {
    let keyPair: elliptic.ec.KeyPair;
    if (type === 'private') {
      keyPair = this._ec.keyFromPrivate(data);
    } else {
      keyPair = this._ec.keyFromPublic(data);
    }
    return new EllipticKeyObject(this, keyPair);
  }

  public asnKeyObjectToKey(type: 'private' | 'public', keyObject: ArrayBuffer): EllipticKeyObject {
    const asn = asn1js.fromBER(keyObject);
    if (type === 'private') {
      const keyRaw = (asn.result as any) instanceof asn1js.Sequence ?
        arrayBufferToBuffer((asn.result as any).valueBlock.value[1].valueBlock.valueHex) :
        arrayBufferToBuffer(keyObject);
      return this.rawToKey(type, keyRaw);
    } else {
      return this.rawToKey(type, arrayBufferToBuffer(keyObject));
    }
  }
}

export class SpecialCurveAlgorithm extends EllipticAlgorithm {
  constructor(
    type: AsymmetricAlgorithmType,
    ec: elliptic.ec, curveOptions: CurveOptions,
    algorithmOid: string,
    algorithmParams: ECParametersChoice | undefined
  ) {
    super(type, ec, curveOptions, algorithmOid, algorithmParams);
  }

  protected _exportECPrivateKey(key: EllipticKeyObject, addAlgorithmParams?: boolean): any {
    return new OctetString(key.getECKeyPair().getPrivate().toArrayLike(Buffer));
  }

  public asnKeyObjectToKey(type: 'private' | 'public', keyObject: ArrayBuffer): EllipticKeyObject {
    const asn = asn1js.fromBER(keyObject);
    if (type === 'private') {
      // OctetString
      const keyRaw = arrayBufferToBuffer((asn.result as any).valueBlock.valueHex);
      return this.rawToKey(type, keyRaw);
    } else {
      return this.rawToKey(type, arrayBufferToBuffer(keyObject));
    }
  }
}

export interface CurveKeyParams<T> extends KeyParams<T> {
  algorithmOid: string;
}

export function fromCurve(options: CurveKeyParams<ECParametersChoice | ArrayBuffer>): EllipticAlgorithm;
export function fromCurve(options: CurveKeyParams<null>, specialCurve: true): EllipticAlgorithm;
export function fromCurve(options: CurveKeyParams<ECParametersChoice | ArrayBuffer | null>, specialCurve?: boolean): EllipticAlgorithm {
  let ec: Curve | undefined;
  let ecParameterChoice: ECParametersChoice | undefined = undefined;
  let namedOid: string | undefined = undefined;

  if (specialCurve) {
    namedOid = options.algorithmOid;
    ec = getCurveByOid(options.algorithmOid);
  } else {
    ecParameterChoice = (options.asn1KeyParams instanceof ECParametersChoice)
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
  }
  if (!ec) {
    throw new Error('Not supported Key: ' + (namedOid ? namedOid : 'null'));
  }
  return specialCurve ?
    new SpecialCurveAlgorithm(
      options.type,
      new elliptic.ec(ec.preset), ec.options,
      options.algorithmOid,
      ecParameterChoice
    ) :
    new EllipticAlgorithm(
      options.type,
      new elliptic.ec(ec.preset), ec.options,
      options.algorithmOid,
      ecParameterChoice
    );
}

