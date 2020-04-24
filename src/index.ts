import * as crypto from 'crypto';

import * as utils from './utils';
import * as rdsaSignature from './impl/rdsa-signature';
import * as curves from './impl/curves';
import * as ecdh from './impl/ecdh';

import {
  AsymmetricKeyObject,
  PublicKeyInput,
  PrivateKeyInput
} from './interfaces';

import {
  EllipticAlgorithm,
  EllipticKeyObject,
  RSAKeyAlgorithm,
  RSAKeyObject,
  createAsymmetricKeyFromNode
} from './asymmetric-key';

const impls = Object.freeze({
  rdsaSignature,
  curves,
  ecdh
});

export {
  utils,
  impls,
  AsymmetricKeyObject,
  PublicKeyInput,
  PrivateKeyInput,
  EllipticAlgorithm,
  EllipticKeyObject,
  RSAKeyAlgorithm,
  RSAKeyObject,
  createAsymmetricKeyFromNode
};

/**
 * Create AsymmetricKeyObject with PrivateKey from der, pem or nodejs KeyObject.
 *
 * @param key input
 * @return AsymmetricKeyObject
 */
export function createPrivateKey(key: crypto.PrivateKeyInput | string | Buffer | crypto.KeyObject): AsymmetricKeyObject {
  if (key instanceof crypto.KeyObject) {
    return createAsymmetricKeyFromNode(key);
  } else {
    return createAsymmetricKeyFromNode(
      crypto.createPrivateKey(key)
    );
  }
}

/**
 * Create AsymmetricKeyObject with PublicKey from der, pem or nodejs KeyObject.
 *
 * @param key input
 * @return AsymmetricKeyObject
 */
export function createPublicKey(key: crypto.PublicKeyInput | string | Buffer | crypto.KeyObject): AsymmetricKeyObject  {
  if (key instanceof crypto.KeyObject) {
    return createAsymmetricKeyFromNode(key);
  } else {
    return createAsymmetricKeyFromNode(
      crypto.createPublicKey(key)
    );
  }
}
