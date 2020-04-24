import BN from 'bn.js';

import {
  RSAPublicKey
} from '../asymmetric-interface';

export function withPublic (paddedMsg: BN, key: RSAPublicKey): Buffer {
  return Buffer.from(paddedMsg
    .toRed(BN.mont(key.modulus))
    .redPow(new BN(key.publicExponent))
    .fromRed()
    .toArray());
}
