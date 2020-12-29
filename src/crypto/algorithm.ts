import * as stream from 'stream';
import {
  Cipher, Decipher, CipherOptions
} from './interface';
import {CryptoModuleCipher, CryptoModuleDecipher} from './crypto-module-cipher';

export interface CipherNameOptions {
  oid: string;
  names: string[];
}
export interface CipherFactoryOptions {
  cipherSupplier: (streamOptions: stream.TransformOptions | undefined) => Cipher;
  decipherSupplier: (streamOptions: stream.TransformOptions | undefined) => Decipher;
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
  cipherSupplier: (opts: stream.TransformOptions | undefined) => new CryptoModuleCipher('aes-128-gcm', true, true, 128, 128, opts),
  decipherSupplier: (opts: stream.TransformOptions | undefined) => new CryptoModuleDecipher('aes-128-gcm', true, true, 128, 128, opts)
});
defineCipher({
  oid: '2.16.840.1.101.3.4.1.7',
  names: ['aes-128-ccm']
}, {
  cipherSupplier: (opts: stream.TransformOptions | undefined) => new CryptoModuleCipher('aes-128-ccm', true, true, 128, 128, opts),
  decipherSupplier: (opts: stream.TransformOptions | undefined) => new CryptoModuleDecipher('aes-128-ccm', true, true, 128, 128, opts)
});
defineCipher({
  oid: '2.16.840.1.101.3.4.1.26',
  names: ['aes-192-gcm']
}, {
  cipherSupplier: (opts: stream.TransformOptions | undefined) => new CryptoModuleCipher('aes-192-gcm', true, true, 192, 128, opts),
  decipherSupplier: (opts: stream.TransformOptions | undefined) => new CryptoModuleDecipher('aes-192-gcm', true, true, 192, 128, opts)
});
defineCipher({
  oid: '2.16.840.1.101.3.4.1.27',
  names: ['aes-192-ccm']
}, {
  cipherSupplier: (opts: stream.TransformOptions | undefined) => new CryptoModuleCipher('aes-192-ccm', true, true, 192, 128, opts),
  decipherSupplier: (opts: stream.TransformOptions | undefined) => new CryptoModuleDecipher('aes-192-ccm', true, true, 192, 128, opts)
});
defineCipher({
  oid: '2.16.840.1.101.3.4.1.46',
  names: ['aes-256-gcm']
}, {
  cipherSupplier: (opts: stream.TransformOptions | undefined) => new CryptoModuleCipher('aes-256-gcm', true, true, 256, 128, opts),
  decipherSupplier: (opts: stream.TransformOptions | undefined) => new CryptoModuleDecipher('aes-256-gcm', true, true, 256, 128, opts)
});
defineCipher({
  oid: '2.16.840.1.101.3.4.1.47',
  names: ['aes-256-ccm']
}, {
  cipherSupplier: (opts: stream.TransformOptions | undefined) => new CryptoModuleCipher('aes-256-ccm', true, true, 256, 128, opts),
  decipherSupplier: (opts: stream.TransformOptions | undefined) => new CryptoModuleDecipher('aes-256-ccm', true, true, 256, 128, opts)
});

export function createCipher(
  algorithm: string,
  streamOptions?: stream.TransformOptions | undefined
): Cipher | undefined {
  const factory = oidMap[algorithm] || nameMap[algorithm];
  if (!factory) {
    return undefined;
  }
  return factory.cipherSupplier(streamOptions);
}

export function createDecipher(
  algorithm: string,
  streamOptions?: stream.TransformOptions | undefined
): Decipher | undefined {
  const factory = oidMap[algorithm] || nameMap[algorithm];
  if (!factory) {
    return undefined;
  }
  return factory.decipherSupplier(streamOptions);
}

export function getCipherAlgorithms(): readonly CipherAlgorithmInfo[] {
  return Object.freeze(algorithmList);
}
