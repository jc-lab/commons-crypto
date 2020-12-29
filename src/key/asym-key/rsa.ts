import * as BN from 'bn.js';
import * as asn1js from 'asn1js';
import {AsnParser} from '@peculiar/asn1-schema';
import {ParametersType} from '@peculiar/asn1-x509';
import {RSAPrivateKey, RSAPublicKey} from '@peculiar/asn1-rsa';
import {AsymmetricAlgorithmType, AsymmetricKeyAlgorithm, AsymmetricKeyObject} from '../interfaces';
import {arrayBufferToBuffer} from '../../utils';
import {KeyParams, KeyType} from '../intl';
import {RSAKeyAlgorithm} from '../asym-algorithm/rsa';

export interface BNRSAPublicKey {
  modulus: BN;
  publicExponent: BN;
}

export interface BNRSAPrivateKey extends BNRSAPublicKey {
  privateExponent: BN;
  prime1: BN;
  prime2: BN;
  coefficient: BN;
  exponent1: BN;
  exponent2:  BN;
}

export interface RSAKeyObjectParams<T> extends KeyParams<ParametersType | undefined> {
  keyType: KeyType;
  asn1KeyObject: T;
}

export class RSAKeyObject extends AsymmetricKeyObject {
  private _algo: RSAKeyAlgorithm;
  private _signPrivateKey: BNRSAPrivateKey | null;
  private _signPublicKey: BNRSAPublicKey;

  constructor(algo: RSAKeyAlgorithm, options: RSAKeyObjectParams<any>, bnPrivateKey: BNRSAPrivateKey | null, bnPublicKey: BNRSAPublicKey) {
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
      const thisBnKey = this._signPrivateKey as BNRSAPrivateKey;
      const otherBnKey = o._signPrivateKey as BNRSAPrivateKey;
      return (
        thisBnKey.publicExponent.eq(otherBnKey.publicExponent) &&
        thisBnKey.modulus.eq(otherBnKey.modulus) &&
        thisBnKey.privateExponent.eq(otherBnKey.privateExponent)
      );
    } else {
      const thisBnKey = this._signPublicKey as BNRSAPublicKey;
      const otherBnKey = o._signPublicKey as BNRSAPublicKey;
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

  public getBNPrivateKey(): BNRSAPrivateKey {
    return this._signPrivateKey as BNRSAPrivateKey;
  }

  public getBNPublicKey(): BNRSAPublicKey {
    return this._signPublicKey;
  }
}

export function fromRSAKey(options: RSAKeyObjectParams<ArrayBuffer>): AsymmetricKeyObject;
export function fromRSAKey(options: RSAKeyObjectParams<RSAPrivateKey | RSAPublicKey>, decoded: true): AsymmetricKeyObject;
export function fromRSAKey(options: RSAKeyObjectParams<any>, decoded?: boolean): AsymmetricKeyObject {
  const asn = decoded ? null : asn1js.fromBER(options.asn1KeyObject);
  let bnPrivateKey: BNRSAPrivateKey | null = null;
  let bnPublicKey: BNRSAPublicKey;
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
