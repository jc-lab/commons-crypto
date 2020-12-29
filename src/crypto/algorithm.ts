import {
  Cipher, Decipher, CipherOptions
} from './interface';
import {CryptoModuleCipher, CryptoModuleDecipher} from './crypto-module-cipher';

export interface CipherNameOptions {
  oid: string;
  names: string[];
}
export interface CipherFactoryOptions {
  cipherSupplier: (opts: CipherOptions) => Cipher;
  decipherSupplier: (opts: CipherOptions) => Decipher;
}

export interface CipherAlgorithmInfo extends CipherNameOptions {
}

const algorithmList: CipherAlgorithmInfo[] = [];
const oidMap: Record<string, CipherFactoryOptions> = {};
const nameMap: Record<string, CipherFactoryOptions> = {};
export function defineCipher(nameOptions: CipherNameOptions, factoryOptions: CipherFactoryOptions) {
  algorithmList.push(nameOptions);
  oidMap[nameOptions.oid] = factoryOptions;
  nameOptions.names.forEach((v) => nameMap[v] = factoryOptions);
}

defineCipher({
  oid: '2.16.840.1.101.3.4.1.6',
  names: ['aes-128-gcm']
}, {
  cipherSupplier: (opts: CipherOptions) => new CryptoModuleCipher('aes-128-gcm', opts),
  decipherSupplier: (opts: CipherOptions) => new CryptoModuleDecipher('aes-128-gcm', opts)
});
defineCipher({
  oid: '2.16.840.1.101.3.4.1.7',
  names: ['aes-128-ccm']
}, {
  cipherSupplier: (opts: CipherOptions) => new CryptoModuleCipher('aes-128-ccm', opts),
  decipherSupplier: (opts: CipherOptions) => new CryptoModuleDecipher('aes-128-ccm', opts)
});
defineCipher({
  oid: '2.16.840.1.101.3.4.1.26',
  names: ['aes-192-gcm']
}, {
  cipherSupplier: (opts: CipherOptions) => new CryptoModuleCipher('aes-192-gcm', opts),
  decipherSupplier: (opts: CipherOptions) => new CryptoModuleDecipher('aes-192-gcm', opts)
});
defineCipher({
  oid: '2.16.840.1.101.3.4.1.27',
  names: ['aes-192-ccm']
}, {
  cipherSupplier: (opts: CipherOptions) => new CryptoModuleCipher('aes-192-ccm', opts),
  decipherSupplier: (opts: CipherOptions) => new CryptoModuleDecipher('aes-192-ccm', opts)
});
defineCipher({
  oid: '2.16.840.1.101.3.4.1.46',
  names: ['aes-256-gcm']
}, {
  cipherSupplier: (opts: CipherOptions) => new CryptoModuleCipher('aes-256-gcm', opts),
  decipherSupplier: (opts: CipherOptions) => new CryptoModuleDecipher('aes-256-gcm', opts)
});
defineCipher({
  oid: '2.16.840.1.101.3.4.1.47',
  names: ['aes-256-ccm']
}, {
  cipherSupplier: (opts: CipherOptions) => new CryptoModuleCipher('aes-256-ccm', opts),
  decipherSupplier: (opts: CipherOptions) => new CryptoModuleDecipher('aes-256-ccm', opts)
});

export function createCipher(
  algorithm: string,
  options: CipherOptions
): Cipher | undefined {
  const factory = oidMap[algorithm] || nameMap[algorithm];
  if (!factory) {
    return undefined;
  }
  return factory.cipherSupplier(options);
}

export function createDecipher(
  algorithm: string,
  options: CipherOptions
): Decipher | undefined {
  const factory = oidMap[algorithm] || nameMap[algorithm];
  if (!factory) {
    return undefined;
  }
  return factory.decipherSupplier(options);
}

export function getCipherAlgorithms(): readonly CipherAlgorithmInfo[] {
  return Object.freeze(algorithmList);
}
