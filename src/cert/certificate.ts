import {
  AsymmetricAlgorithmType,
  AsymmetricKeyAlgorithm,
  AsymmetricKeyObject, KeyExportOptions
} from '../key';
import {AlgorithmIdentifier, Certificate} from '@peculiar/asn1-x509';
import {fromKeyObjectAndOid} from '../key/key-parse';
import * as asn1js from 'asn1js';

export class CertificateObject extends AsymmetricKeyObject {
  public readonly publicKey: AsymmetricKeyObject;
  private readonly certificate: Certificate;

  constructor(certificate: Certificate) {
    super();
    this.certificate = certificate;
    const publicKeyInfo = certificate.tbsCertificate.subjectPublicKeyInfo;
    const algorithmIdentifier = publicKeyInfo.algorithm as AlgorithmIdentifier;
    this.publicKey = fromKeyObjectAndOid(
      algorithmIdentifier.algorithm,
      'public',
      algorithmIdentifier.parameters,
      publicKeyInfo.subjectPublicKey
    );
  }

  public getCertificateAsn(): Certificate {
    return this.certificate;
  }

  equals(o: CertificateObject): boolean {
    if (!o) return false;
    if (!this.publicKey.equals(o.publicKey)) return false;
    //TODO: Check certificate object
    return true;
  }

  getKeyAlgorithm(): AsymmetricKeyAlgorithm {
    return this.publicKey.getKeyAlgorithm();
  }

  isPrivate(): boolean {
    return false;
  }

  isPublic(): boolean {
    return true;
  }

  isSecret(): boolean {
    return false;
  }

  public publicEncrypt(data: Buffer): Buffer {
    return this.getKeyAlgorithm().publicEncrypt(data, this.publicKey);
  }
  public verify(digestOid: asn1js.ObjectIdentifier | string | null, hash: Buffer, signature: Buffer): boolean {
    return this.getKeyAlgorithm().verify(digestOid, hash, signature, this.publicKey);
  }
  public export(options: KeyExportOptions<'pem'>): string;
  public export(options?: KeyExportOptions<'der'>): Buffer;
  public export(options?: KeyExportOptions<any>): string | Buffer {
    throw Error('NOT IMPLEMENTED');
  }
  public toPublicKey(): AsymmetricKeyObject {
    return this.getKeyAlgorithm().toPublicKey(this.publicKey);
  }
}

export function createCertificateFromAsn(certificate: Certificate): CertificateObject {
  return new CertificateObject(certificate);
}
