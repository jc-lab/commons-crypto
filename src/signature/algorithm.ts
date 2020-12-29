import {
  Signature
} from './interface';
import {SignatureImpl} from './stream';
import stream from 'stream';
import {AsymmetricKeyObject} from '../key';

export interface SignatureNameOptions {
  oid: string;
  names: string[];
}
export type SignatureSupplier = (digestOid: string, key: AsymmetricKeyObject, opts?: stream.WritableOptions) => Signature;
export interface SignatureFactoryOptions {
  digestOid: string;
  supplier: SignatureSupplier;
}

export interface SignatureAlgorithmInfo extends SignatureNameOptions {
  digestOid: string;
}

const algorithmList: SignatureAlgorithmInfo[] = [];
const oidMap: Record<string, SignatureFactoryOptions> = {};
const nameMap: Record<string, SignatureFactoryOptions> = {};
export function defineSignature(nameOptions: SignatureNameOptions, factoryOptions: SignatureFactoryOptions) {
  algorithmList.push({
    ...nameOptions,
    digestOid: factoryOptions.digestOid
  });
  oidMap[nameOptions.oid] = factoryOptions;
  nameOptions.names.forEach((v) => nameMap[v.toLowerCase()] = factoryOptions);
  nameOptions.names.forEach((v) => nameMap[v.toLowerCase().replace(/-/g, '')] = factoryOptions);
}

defineSignature({
  oid: '1.2.840.10045.4.1',
  names: ['ecdsa-with-sha1']
}, {
  digestOid: '1.3.14.3.2.26',
  supplier: (digestOid, key, opts) => new SignatureImpl(digestOid, key, opts)
});
defineSignature({
  oid: '1.2.840.10045.4.3.2',
  names: ['ecdsa-with-sha256']
}, {
  digestOid: '2.16.840.1.101.3.4.2.1',
  supplier: (digestOid, key, opts) => new SignatureImpl(digestOid, key, opts)
});
defineSignature({
  oid: '1.2.840.10045.4.3.3',
  names: ['ecdsa-with-sha384']
}, {
  digestOid: '2.16.840.1.101.3.4.2.2',
  supplier: (digestOid, key, opts) => new SignatureImpl(digestOid, key, opts)
});
defineSignature({
  oid: '1.2.840.10045.4.3.4',
  names: ['ecdsa-with-sha512']
}, {
  digestOid: '2.16.840.1.101.3.4.2.3',
  supplier: (digestOid, key, opts) => new SignatureImpl(digestOid, key, opts)
});
defineSignature({
  oid: '1.2.840.10045.4.3.1',
  names: ['ecdsa-with-sha224']
}, {
  digestOid: '2.16.840.1.101.3.4.2.4',
  supplier: (digestOid, key, opts) => new SignatureImpl(digestOid, key, opts)
});

defineSignature({
  oid: '1.2.840.10045.4.3.1',
  names: ['sha1-with-rsa-signature', 'sha1WithRSAEncryption']
}, {
  digestOid: '1.3.14.3.2.26',
  supplier: (digestOid, key, opts) => new SignatureImpl(digestOid, key, opts)
});
defineSignature({
  oid: '1.2.840.113549.1.1.11',
  names: ['sha256WithRSAEncryption']
}, {
  digestOid: '2.16.840.1.101.3.4.2.1',
  supplier: (digestOid, key, opts) => new SignatureImpl(digestOid, key, opts)
});
defineSignature({
  oid: '1.2.840.113549.1.1.12',
  names: ['sha384WithRSAEncryption']
}, {
  digestOid: '2.16.840.1.101.3.4.2.2',
  supplier: (digestOid, key, opts) => new SignatureImpl(digestOid, key, opts)
});
defineSignature({
  oid: '1.2.840.113549.1.1.13',
  names: ['sha512WithRSAEncryption']
}, {
  digestOid: '2.16.840.1.101.3.4.2.3',
  supplier: (digestOid, key, opts) => new SignatureImpl(digestOid, key, opts)
});
defineSignature({
  oid: '1.2.840.113549.1.1.14',
  names: ['sha224WithRSAEncryption']
}, {
  digestOid: '2.16.840.1.101.3.4.2.4',
  supplier: (digestOid, key, opts) => new SignatureImpl(digestOid, key, opts)
});

export function createSignatureByAlgorithm(
  algorithm: string,
  key: AsymmetricKeyObject,
  opts?: stream.WritableOptions
): Signature | undefined {
  const factory = oidMap[algorithm] || nameMap[algorithm];
  if (!factory) {
    return undefined;
  }
  return factory.supplier(factory.digestOid, key, opts);
}

export function getSignatureAlgorithms(): readonly SignatureAlgorithmInfo[] {
  return Object.freeze(algorithmList);
}
