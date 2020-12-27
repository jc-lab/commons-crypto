import {AsymmetricAlgorithmType} from './interfaces';

export function findAsymmetricAlgorithmTypeFromOid(oid: string): AsymmetricAlgorithmType | undefined {
  switch (oid) {
  case '1.2.840.113549.1.1.1':
    return AsymmetricAlgorithmType.rsa;
  case '1.2.840.10040.4.1':
    return AsymmetricAlgorithmType.dsa;
  case '1.2.840.10045.2.1':
  case '1.2.840.10045.3.1.1':
  case '1.3.132.0.33':
  case '1.2.840.10045.3.1.7':
  case '1.3.132.0.34':
  case '1.3.132.0.35':
    return AsymmetricAlgorithmType.ec;
  case '1.3.101.110':
    return AsymmetricAlgorithmType.x25519;
  case '1.3.101.111':
    return AsymmetricAlgorithmType.x448;
  case '1.3.101.112':
  case '1.3.101.113':
    return AsymmetricAlgorithmType.edwards;
  }
  return undefined;
}

export function getOidFromAsymmetricAlgorithmType(type: AsymmetricAlgorithmType.edwards): undefined;
export function getOidFromAsymmetricAlgorithmType(type: AsymmetricAlgorithmType): string;
export function getOidFromAsymmetricAlgorithmType(type: AsymmetricAlgorithmType): string | undefined {
  switch (type) {
  case AsymmetricAlgorithmType.rsa:
    return '1.2.840.113549.1.1.1';
  case AsymmetricAlgorithmType.dsa:
    return '1.2.840.10040.4.1';
  case AsymmetricAlgorithmType.ec:
    return '1.2.840.10045.2.1';
  case AsymmetricAlgorithmType.x25519:
    return '1.3.101.110';
  case AsymmetricAlgorithmType.x448:
    return '1.3.101.111';
  }
  return undefined;
}
