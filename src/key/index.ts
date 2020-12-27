import * as curves from './impl/curves';
import * as ecdh from './impl/ecdh';
import {ECCurve} from './impl/asn/ECCurve';
import {ECParameters} from './impl/asn/ECParameters';
import {ECPrivateKey} from './impl/asn/ECPrivateKey';
import {ECPublicKey} from './impl/asn/ECPublicKey';
import {PublicKeyInfo} from './impl/asn/PublicKeyInfo';

export * from './interfaces';
export * from './asymmetric-key';
export * from './core';
export * from './algorithms';

import * as utils from '../utils';

const impls = Object.freeze({
  curves,
  ecdh
});

const asn = Object.freeze({
  ECCurve,
  ECParameters,
  ECPrivateKey,
  ECPublicKey,
  PublicKeyInfo
});

export {
  utils,
  impls,
  asn
};
