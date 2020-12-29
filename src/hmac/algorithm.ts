import {Hmac} from './interface';
import {createHash, Hash} from '../hash';
import {HmacImpl} from './impl';

export interface HmacNameOptions {
  oid: string;
  names: string[];
}
export type HmacSupplier = (macOid: string, hash: Hash) => Hmac;
export interface HmacFactoryOptions {
  digestOid: string;
  supplier: HmacSupplier;
}
interface HmacFactoryEx extends HmacFactoryOptions {
  macOid: string;
}

export interface HmacAlgorithmInfo extends HmacNameOptions {
  digestOid: string;
}

const algorithmList: HmacAlgorithmInfo[] = [];
const oidMap: Record<string, HmacFactoryEx> = {};
const nameMap: Record<string, HmacFactoryEx> = {};
export function defineHmac(nameOptions: HmacNameOptions, factoryOptions: HmacFactoryOptions) {
  algorithmList.push({
    ...nameOptions,
    digestOid: factoryOptions.digestOid
  });
  const _factory: HmacFactoryEx = {
    ...factoryOptions,
    macOid: nameOptions.oid
  };
  oidMap[nameOptions.oid] = _factory;
  nameOptions.names.forEach((v) => nameMap[v.toLowerCase()] = _factory);
  nameOptions.names.forEach((v) => nameMap[v.toLowerCase().replace(/-/g, '')] = _factory);
}

defineHmac({
  oid: '1.2.840.113549.2.7',
  names: ['hmac-with-sha-1']
}, {
  digestOid: '1.3.14.3.2.26',
  supplier: (macOid, hash) => new HmacImpl(macOid, hash)
});

defineHmac({
  oid: '1.2.840.113549.2.8',
  names: ['hmac-with-sha-224']
}, {
  digestOid: '2.16.840.1.101.3.4.2.4',
  supplier: (macOid, hash) => new HmacImpl(macOid, hash)
});

defineHmac({
  oid: '1.2.840.113549.2.9',
  names: ['hmac-with-sha-256']
}, {
  digestOid: '2.16.840.1.101.3.4.2.1',
  supplier: (macOid, hash) => new HmacImpl(macOid, hash)
});

defineHmac({
  oid: '1.2.840.113549.2.10',
  names: ['hmac-with-sha-384']
}, {
  digestOid: '2.16.840.1.101.3.4.2.2',
  supplier: (macOid, hash) => new HmacImpl(macOid, hash)
});

defineHmac({
  oid: '1.2.840.113549.2.11',
  names: ['hmac-with-sha-512']
}, {
  digestOid: '2.16.840.1.101.3.4.2.3',
  supplier: (macOid, hash) => new HmacImpl(macOid, hash)
});

export function createHmac(
  algorithm: string
): Hmac | undefined {
  const factory = oidMap[algorithm] || nameMap[algorithm];
  if (!factory) {
    return undefined;
  }
  const hash = createHash(factory.digestOid);
  if (!hash) {
    return undefined;
  }
  return factory.supplier(factory.macOid, hash);
}

export function getHashByHmacAlgorithm(algorithm: string): Hash | undefined {
  const factory = oidMap[algorithm] || nameMap[algorithm];
  if (!factory) {
    return undefined;
  }
  return createHash(factory.digestOid);
}

export function createHmacByHash(macOid: string, hash: Hash): Hmac {
  return new HmacImpl(macOid, hash);
}

export function getHmacAlgorithms(): readonly HmacAlgorithmInfo[] {
  return Object.freeze(algorithmList);
}
