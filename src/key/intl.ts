import {
  AsymmetricAlgorithmType
} from './interfaces';

export type KeyType = 'private' | 'public';
export interface KeyParams<TKeyParams, TKeyObject> {
  curveOid?: string;
  keyType: KeyType;
  type: AsymmetricAlgorithmType;
  asn1KeyParams: TKeyParams;
  asn1KeyObject: TKeyObject;
  signable: boolean;
  keyAgreementable: boolean;
  cryptable: boolean;
}
