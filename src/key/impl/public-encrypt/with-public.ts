import BN from 'bn.js';
import {BNRSAPublicKey} from '../../asym-key/rsa';

export function withPublic (paddedMsg: BN, key: BNRSAPublicKey): Buffer {
  return Buffer.from(paddedMsg
    .toRed(BN.mont(key.modulus))
    .redPow(key.publicExponent)
    .fromRed()
    .toArray());
}
