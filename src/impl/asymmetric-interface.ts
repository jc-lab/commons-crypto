import BN from 'bn.js';

export interface RSAPublicKey {
  modulus: BN;
  publicExponent: BN;
}

export interface RSAPrivateKey extends RSAPublicKey {
  privateExponent: BN;
  prime1: BN;
  prime2: BN;
  coefficient: BN;
  exponent1: BN;
  exponent2:  BN;
}

export interface DSAPrivateKey {
  priv_key: BN;
  p: BN;
  q: BN;
  g: BN;
}

export interface DSAPublicKey {
  p: BN;
  q: BN;
  g: BN;
  pub_key: BN;
}
