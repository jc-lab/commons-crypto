import * as asn1js from 'asn1js';
import * as elliptic from 'elliptic';
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
import {CurveOptions} from '../impl/curves';
import ECDH from '../impl/ecdh';
import {arrayBufferToBuffer, bufferToArrayBuffer} from '../../utils';
import {ECPrivateKey} from '../impl/asn/ECPrivateKey';
import {ECPublicKey} from '../impl/asn/ECPublicKey';
import {PublicKeyInfo} from '../impl/asn/PublicKeyInfo';
import {EllipticKeyObject} from '../asym-key/elliptic';
import { createAsymmetricKeyFromPrivateKeyInfo, fromKeyObjectAndOid } from '../key-parse';

export class EllipticAlgorithm extends AsymmetricKeyAlgorithm {
  private _algorithmOid: asn1js.ObjectIdentifier;
  private _namedCurveOid: asn1js.ObjectIdentifier | null = null;
  private _algorithmParams: ECParametersChoice;
  private _ec: elliptic.ec;
  private _curveOptions: CurveOptions;

  constructor(
    type: AsymmetricAlgorithmType,
    ec: elliptic.ec, curveOptions: CurveOptions,
    algorithmOid: asn1js.ObjectIdentifier | string,
    algorithmParams: ECParametersChoice
  ) {
    super(type, curveOptions.signable, curveOptions.keyAgreementable, curveOptions.cryptable);
    this._ec = ec;
    this._curveOptions = curveOptions;
    this._algorithmOid = (typeof algorithmOid === 'string') ? new asn1js.ObjectIdentifier({ value: algorithmOid }) : algorithmOid;
    this._algorithmParams = algorithmParams;
    this._namedCurveOid = algorithmParams.namedCurve && new asn1js.ObjectIdentifier({ value: algorithmParams.namedCurve }) || null;
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
    const options: Partial<ECPrivateKey> = {
      version: 1,
      privateKey: key.getECKeyPair().getPrivate().toBuffer()
    };
    if (_addAlgorithmParams) {
      // Not required when export with PrivateKeyInfo
      options.parameters = this._algorithmParams;
    }
    if (publicKey) {
      options.publicKey = this._exportECPublicKey(key).toBitStream();
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
          algorithm: this._algorithmOid.valueBlock.toString(),
          parameters: AsnSerializer.serialize(this._algorithmParams)
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
          algorithm: this._algorithmOid.valueBlock.toString(),
          parameters: AsnSerializer.serialize(this._algorithmParams)
        }),
        subjectPublicKey: ecPublicKey.toBitStream()
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
      return EllipticKeyObject.fromBinary(this, 'private', AsnSerializer.serialize(asnEcPrivateKey));
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
}
