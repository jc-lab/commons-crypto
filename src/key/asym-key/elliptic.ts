import * as elliptic from 'elliptic';
import {AsymmetricKeyAlgorithm, AsymmetricKeyObject} from '../interfaces';
import {EllipticAlgorithm} from '../asym-algorithm/elliptic';

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
