import {
  AsymmetricAlgorithmType
} from './interfaces';

export type  KeyType = 'private' | 'public';
export interface KeyParams<TKeyParams> {
  type: AsymmetricAlgorithmType;
  asn1KeyParams: TKeyParams;
  signable: boolean;
  keyAgreementable: boolean;
  cryptable: boolean;
}
