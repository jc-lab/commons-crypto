import * as asn1js from 'asn1js';

export type KeyFormat = 'pem' | 'der';

export interface PublicKeyInput {
  key: string | Buffer;
  format?: KeyFormat;
  type?: 'pkcs1' | 'spki';
}

export interface PrivateKeyInput {
  key: string | Buffer;
  format?: KeyFormat;
  type?: 'pkcs1' | 'pkcs8' | 'sec1';
  passphrase?: string | Buffer;
}

export enum AsymmetricAlgorithmType {
  rsa = 0x01,
  ec = 0x02,

  dsa = 0x11,
  edwards = 0x12,

  dh = 0x21,
  x448 = 0x22,
  x25519 = 0x23,
}

export type KeyExportType = 'spki' | 'pkcs8' | 'specific' | 'specific-private' | 'specific-public';
export interface AlgorithmKeyImportOptions<T extends KeyFormat> {
  format: T;
  cipher?: string;
  passphrase?: string | Buffer;
}
export interface KeyExportOptions<T extends KeyFormat> {
  type: KeyExportType;
  format: T;
  cipher?: string;
  passphrase?: string | Buffer;
}

const S_KeyObject = Symbol('KeyObject');
export abstract class KeyObject {
  protected constructor() {
    Object.defineProperty(this, S_KeyObject, {
      get(): any {
        return true;
      },
      configurable: false
    });
  }

  public static isKeyObject(o: any): boolean {
    return !!(this as any)[S_KeyObject];
  }

  public abstract isPrivate(): boolean;
  public abstract isPublic(): boolean;
  public abstract isSecret(): boolean;
}

function encodePemLines(input: string): string[] {
  let remaining = input.length;
  let position = 0;
  const lines: string[] = [];
  while (remaining > 0) {
    const avail = Math.min(remaining, 64);
    lines.push(input.substr(position, avail));
    position += avail;
    remaining -= avail;
  }
  return lines;
}

const PEM_REGEX_BEGIN = /^-----BEGIN (.*)-----$/;
const PEM_REGEX_END = /^-----END (.*)-----$/;
function parsePem(input: string): {
  pemTitle: string;
  der: Buffer
} {
  const lines: string[] = input.trim().split(/\n/);
  const beginLine = lines.shift();
  const endLine = (lines.length > 0) && lines[lines.length - 1];
  if (!beginLine || !endLine) {
    throw new Error('Unknown PEM Format');
  }
  lines.pop();
  const beginMatchers = beginLine.match(PEM_REGEX_BEGIN);
  const endMatchers = endLine.match(PEM_REGEX_END);
  if (!beginMatchers || !endMatchers) {
    throw new Error('Unknown PEM Format');
  }
  if (endMatchers[1] !== beginMatchers[1]) {
    throw new Error('Unknown PEM Format');
  }
  return {
    pemTitle: beginMatchers[1],
    der: Buffer.from(lines.join(''), 'base64')
  };
}

const S_AsymmetricKeyAlgorithm = Symbol('AsymmetricKeyObject');
export abstract class AsymmetricKeyAlgorithm {
  protected _type: AsymmetricAlgorithmType;
  protected _signable: boolean;
  protected _keyAgreementable: boolean;
  protected _cryptable: boolean;

  protected constructor(
    type: AsymmetricAlgorithmType, signable: boolean, keyAgreementable: boolean, cryptable: boolean
  ) {
    Object.defineProperty(this, S_AsymmetricKeyAlgorithm, {
      get(): any {
        return true;
      },
      configurable: false
    });
    this._type = type;
    this._signable = signable;
    this._keyAgreementable = keyAgreementable;
    this._cryptable = cryptable;
  }

  public static isAsymmetricKeyAlgorithm(o: any) {
    return !!(this as any)[S_AsymmetricKeyAlgorithm];
  }

  public get type(): AsymmetricAlgorithmType {
    return this._type;
  }

  public get signable(): boolean {
    return this._signable;
  }

  public get keyAgreementable(): boolean {
    return this._keyAgreementable;
  }

  public get cryptable(): boolean {
    return this._cryptable;
  }

  public abstract publicEncrypt(data: Buffer, publicKey: AsymmetricKeyObject): Buffer;
  public abstract privateDecrypt(data: Buffer, privateKey: AsymmetricKeyObject): Buffer;
  public abstract sign(digestOid: asn1js.ObjectIdentifier | null, hash: Buffer, privateKey: AsymmetricKeyObject): Buffer;
  public abstract verify(digestOid: asn1js.ObjectIdentifier | null, hash: Buffer, signature: Buffer, publicKey: AsymmetricKeyObject): boolean;
  public abstract dhComputeSecret(publicKey: AsymmetricKeyObject, privateKey: AsymmetricKeyObject): Buffer;
  public abstract generateKeyPair(): {
    privateKey: AsymmetricKeyObject,
    publicKey: AsymmetricKeyObject
  };
  public keyExport(key: AsymmetricKeyObject, options: KeyExportOptions<'pem'>): string;
  public keyExport(key: AsymmetricKeyObject, options?: KeyExportOptions<'der'>): Buffer;
  public keyExport(key: AsymmetricKeyObject, options?: KeyExportOptions<'der'> | KeyExportOptions<'pem'>): Buffer | string {
    const format = options && options.format || 'der';
    const result = this._keyExport(key, options);
    if (format === 'pem') {
      return '-----BEGIN ' + result.pemTitle + '-----\n' +
        encodePemLines(result.data.toString('base64')).join('\n') + '\n' +
        '-----END ' + result.pemTitle + '-----\n';
    }
    return result.data;
  }

  public keyImport(key: string, options: AlgorithmKeyImportOptions<'pem'>): AsymmetricKeyObject;
  public keyImport(key: Buffer, options?: AlgorithmKeyImportOptions<'der'>): AsymmetricKeyObject;
  public keyImport(key: string | Buffer, options?: AlgorithmKeyImportOptions<'pem' | 'der'>): AsymmetricKeyObject {
    const format = options && options.format || 'der';
    if (format === 'pem') {
      const { pemTitle, der } = parsePem(key as string);
      return this._keyImport(der, pemTitle, options);
    }
    return this._keyImport(key as Buffer, null, options);
  }

  protected abstract _keyImport(key: Buffer, pemTitle: string | null, options?: AlgorithmKeyImportOptions<'der' | 'pem'>): AsymmetricKeyObject;

  protected abstract _keyExport(key: AsymmetricKeyObject, options?: KeyExportOptions<'der' | 'pem'>): {
    data: Buffer,
    pemTitle: string
  };
}

const S_AsymmetricKeyObject = Symbol('AsymmetricKeyObject');
export abstract class AsymmetricKeyObject extends KeyObject {
  protected constructor() {
    super();
    Object.defineProperty(this, S_AsymmetricKeyObject, {
      get(): any {
        return true;
      },
      configurable: false
    });
  }

  public static isAsymmetricKeyObject(o: any) {
    return !!(this as any)[S_AsymmetricKeyObject];
  }

  public abstract getKeyAlgorithm(): AsymmetricKeyAlgorithm;

  public abstract equals(o: AsymmetricKeyObject): boolean;

  public publicEncrypt(data: Buffer): Buffer {
    return this.getKeyAlgorithm().publicEncrypt(data, this);
  }
  public privateDecrypt(data: Buffer): Buffer {
    return this.getKeyAlgorithm().privateDecrypt(data, this);
  }
  public sign(digestOid: asn1js.ObjectIdentifier | null, hash: Buffer): Buffer {
    return this.getKeyAlgorithm().sign(digestOid, hash, this);
  }
  public verify(digestOid: asn1js.ObjectIdentifier | null, hash: Buffer, signature: Buffer): boolean {
    return this.getKeyAlgorithm().verify(digestOid, hash, signature, this);
  }
  public dhComputeSecret(publicKey: AsymmetricKeyObject): Buffer {
    return this.getKeyAlgorithm().dhComputeSecret(publicKey, this);
  }

  public export(options: KeyExportOptions<'pem'>): string;
  public export(options?: KeyExportOptions<'der'>): Buffer;
  public export(options?: KeyExportOptions<any>): string | Buffer {
    return this.getKeyAlgorithm().keyExport(this, options);
  }

  public get algorithmType(): AsymmetricAlgorithmType {
    return this.getKeyAlgorithm().type;
  }
  public get signable(): boolean {
    return this.getKeyAlgorithm().signable && this.isPrivate();
  }
  public get verifyable(): boolean {
    return this.getKeyAlgorithm().signable && this.isPublic();
  }
  public get keyAgreementable(): boolean  {
    return this.getKeyAlgorithm().keyAgreementable;
  }
  public get publicEncryptable(): boolean {
    return this.getKeyAlgorithm().cryptable && this.isPublic();
  }
  public get privateDecryptable(): boolean {
    return this.getKeyAlgorithm().cryptable && this.isPrivate();
  }
}
