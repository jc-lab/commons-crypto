import {
  AsymmetricKeyAlgorithm,
  AsymmetricKeyObject
} from '../key';
import {AlgorithmIdentifier, Certificate} from '@peculiar/asn1-x509';
import {fromKeyObjectAndOid} from '../key/key-parse';

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
}

export function createCertificateFromAsn(certificate: Certificate): CertificateObject {
  return new CertificateObject(certificate);
}
