import {
  Signature
} from './interface';
import {SignatureImpl} from './stream';
import * as stream from 'stream';

export interface SignatureNameOptions {
  oid: string;
  names: string[];
}
export type SignatureSupplier = (signatureOid: string, digestOid: string, opts?: stream.WritableOptions) => Signature;
export interface SignatureFactoryOptions {
  digestOid: string;
  supplier: SignatureSupplier;
}
interface SignatureFactoryEx extends SignatureFactoryOptions {
  signatureOid: string;
}

export interface SignatureAlgorithmInfo extends SignatureNameOptions {
  digestOid: string;
}

const algorithmList: SignatureAlgorithmInfo[] = [];
const oidMap: Record<string, SignatureFactoryEx> = {};
const nameMap: Record<string, SignatureFactoryEx> = {};
export function defineSignature(nameOptions: SignatureNameOptions, factoryOptions: SignatureFactoryOptions) {
  algorithmList.push({
    ...nameOptions,
    digestOid: factoryOptions.digestOid
  });
  const _factory: SignatureFactoryEx = {
    ...factoryOptions,
    signatureOid: nameOptions.oid
  };
  oidMap[nameOptions.oid] = _factory;
  nameOptions.names.forEach((v) => nameMap[v.toLowerCase()] = _factory);
  nameOptions.names.forEach((v) => nameMap[v.toLowerCase().replace(/-/g, '')] = _factory);
}

defineSignature({
  oid: '1.2.840.10045.4.1',
  names: ['ecdsa-with-sha1']
}, {
  digestOid: '1.3.14.3.2.26',
  supplier: (signatureOid, digestOid, opts) => new SignatureImpl(signatureOid, digestOid, opts)
});
defineSignature({
  oid: '1.2.840.10045.4.3.2',
  names: ['ecdsa-with-sha256']
}, {
  digestOid: '2.16.840.1.101.3.4.2.1',
  supplier: (signatureOid, digestOid, opts) => new SignatureImpl(signatureOid, digestOid, opts)
});
defineSignature({
  oid: '1.2.840.10045.4.3.3',
  names: ['ecdsa-with-sha384']
}, {
  digestOid: '2.16.840.1.101.3.4.2.2',
  supplier: (signatureOid, digestOid, opts) => new SignatureImpl(signatureOid, digestOid, opts)
});
defineSignature({
  oid: '1.2.840.10045.4.3.4',
  names: ['ecdsa-with-sha512']
}, {
  digestOid: '2.16.840.1.101.3.4.2.3',
  supplier: (signatureOid, digestOid, opts) => new SignatureImpl(signatureOid, digestOid, opts)
});
defineSignature({
  oid: '1.2.840.10045.4.3.1',
  names: ['ecdsa-with-sha224']
}, {
  digestOid: '2.16.840.1.101.3.4.2.4',
  supplier: (signatureOid, digestOid, opts) => new SignatureImpl(signatureOid, digestOid, opts)
});

defineSignature({
  oid: '1.2.840.10045.4.3.1',
  names: ['sha1-with-rsa-signature', 'sha1WithRSAEncryption']
}, {
  digestOid: '1.3.14.3.2.26',
  supplier: (signatureOid, digestOid, opts) => new SignatureImpl(signatureOid, digestOid, opts)
});
defineSignature({
  oid: '1.2.840.113549.1.1.11',
  names: ['sha256WithRSAEncryption']
}, {
  digestOid: '2.16.840.1.101.3.4.2.1',
  supplier: (signatureOid, digestOid, opts) => new SignatureImpl(signatureOid, digestOid, opts)
});
defineSignature({
  oid: '1.2.840.113549.1.1.12',
  names: ['sha384WithRSAEncryption']
}, {
  digestOid: '2.16.840.1.101.3.4.2.2',
  supplier: (signatureOid, digestOid, opts) => new SignatureImpl(signatureOid, digestOid, opts)
});
defineSignature({
  oid: '1.2.840.113549.1.1.13',
  names: ['sha512WithRSAEncryption']
}, {
  digestOid: '2.16.840.1.101.3.4.2.3',
  supplier: (signatureOid, digestOid, opts) => new SignatureImpl(signatureOid, digestOid, opts)
});
defineSignature({
  oid: '1.2.840.113549.1.1.14',
  names: ['sha224WithRSAEncryption']
}, {
  digestOid: '2.16.840.1.101.3.4.2.4',
  supplier: (signatureOid, digestOid, opts) => new SignatureImpl(signatureOid, digestOid, opts)
});

export function createSignatureByAlgorithm(
  algorithm: string,
  streamOptions?: stream.WritableOptions
): Signature | undefined {
  const factory = oidMap[algorithm] || nameMap[algorithm];
  if (!factory) {
    return undefined;
  }
  return factory.supplier(factory.signatureOid, factory.digestOid, streamOptions);
}

export function getSignatureAlgorithms(): readonly SignatureAlgorithmInfo[] {
  return Object.freeze(algorithmList);
}
