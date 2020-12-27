import {Hash} from './interface';
import {CryptoModuleHash} from './crypto-module-hash';

export interface HashNameOptions {
  oid: string;
  names: string[];
}
export type HashSupplier = () => Hash;

const oidMap: Record<string, HashSupplier> = {};
const nameMap: Record<string, HashSupplier> = {};
export function defineHash(nameOptions: HashNameOptions, factoryOptions: HashSupplier) {
  oidMap[nameOptions.oid] = factoryOptions;
  nameOptions.names.forEach((v) => nameMap[v.toLowerCase()] = factoryOptions);
  nameOptions.names.forEach((v) => nameMap[v.toLowerCase().replace(/-/g, '')] = factoryOptions);
}

defineHash({
  oid: '1.3.14.3.2.26',
  names: ['sha-1']
}, () => new CryptoModuleHash('sha1'));

defineHash({
  oid: '2.16.840.1.101.3.4.2.1',
  names: ['sha-256']
}, () => new CryptoModuleHash('sha256'));

defineHash({
  oid: '2.16.840.1.101.3.4.2.2',
  names: ['sha-384']
}, () => new CryptoModuleHash('sha384'));

defineHash({
  oid: '2.16.840.1.101.3.4.2.3',
  names: ['sha-512']
}, () => new CryptoModuleHash('sha512'));

defineHash({
  oid: '2.16.840.1.101.3.4.2.4',
  names: ['sha-224']
}, () => new CryptoModuleHash('sha224'));

export function createHash(
  algorithm: string
): Hash | undefined {
  const factory = oidMap[algorithm] || nameMap[algorithm];
  if (!factory) {
    return undefined;
  }
  return factory();
}
