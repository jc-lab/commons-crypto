import {Hash} from './interface';
import {CryptoModuleHash} from './crypto-module-hash';

export interface HashNameOptions {
  oid: string;
  names: string[];
}
export type HashSupplier = (digestOid: string) => Hash;

interface HashFactoryEx {
  digestOid: string;
  supplier: HashSupplier;
}

export interface HashAlgorithmInfo extends HashNameOptions {
}

const algorithmList: HashAlgorithmInfo[] = [];
const oidMap: Record<string, HashFactoryEx> = {};
const nameMap: Record<string, HashFactoryEx> = {};
export function defineHash(nameOptions: HashNameOptions, supplier: HashSupplier) {
  algorithmList.push(nameOptions);
  const _factory: HashFactoryEx = {
    supplier: supplier,
    digestOid: nameOptions.oid
  };
  oidMap[nameOptions.oid] = _factory;
  nameOptions.names.forEach((v) => nameMap[v.toLowerCase()] = _factory);
  nameOptions.names.forEach((v) => nameMap[v.toLowerCase().replace(/-/g, '')] = _factory);
}

defineHash({
  oid: '1.3.14.3.2.26',
  names: ['sha-1']
}, (digestOid) => new CryptoModuleHash(digestOid, 'sha1', 512, 160));

defineHash({
  oid: '2.16.840.1.101.3.4.2.1',
  names: ['sha-256']
}, (digestOid) => new CryptoModuleHash(digestOid, 'sha256', 512, 256));

defineHash({
  oid: '2.16.840.1.101.3.4.2.2',
  names: ['sha-384']
}, (digestOid) => new CryptoModuleHash(digestOid, 'sha384', 1024, 384));

defineHash({
  oid: '2.16.840.1.101.3.4.2.3',
  names: ['sha-512']
}, (digestOid) => new CryptoModuleHash(digestOid, 'sha384', 1024, 512));

defineHash({
  oid: '2.16.840.1.101.3.4.2.4',
  names: ['sha-224']
}, (digestOid) => new CryptoModuleHash(digestOid, 'sha224', 512, 224));

export function createHash(
  algorithm: string
): Hash | undefined {
  const factory = oidMap[algorithm] || nameMap[algorithm];
  if (!factory) {
    return undefined;
  }
  return factory.supplier(factory.digestOid);
}

export function getHashAlgorithms(): readonly HashAlgorithmInfo[] {
  return Object.freeze(algorithmList);
}
