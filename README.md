# commons-crypto

common-crypto is a library that implements cryptographic functions.
It basically aims to support node.js and browser.

Could be the algorithm is automatically found without specifying an algorithm for the asymmetric key.


Supports key generation, signing, verification, encryption, decryption, key agreement are possible through a common interface.

**WARNING**
It's not a complete library yet, and some parts currently rely on the node.js crypto library.

```typescript
import * as asn1js from 'asn1js';
import * as crypto from 'crypto';
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

/**
 * Create AsymmetricKeyObject with PrivateKey from der, pem or nodejs KeyObject.
 *
 * @param key input
 * @return AsymmetricKeyObject
 */
export function createPrivateKey(key: crypto.PrivateKeyInput | string | Buffer | crypto.KeyObject): AsymmetricKeyObject;

/**
 * Create AsymmetricKeyObject with PublicKey from der, pem or nodejs KeyObject.
 *
 * @param key input
 * @return AsymmetricKeyObject
 */
export function createPublicKey(key: crypto.PublicKeyInput | string | Buffer | crypto.KeyObject): AsymmetricKeyObject;

/**
 * Create AsymmetricKeyObject with PublicKey from der or pem
 *
 * @param key Public Key or Private Key
 */
export function createAsymmetricKey(key: PrivateKeyInput | PublicKeyInput): AsymmetricKeyObject;

export declare type KeyFormat = 'pem' | 'der';
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
export declare enum AsymmetricAlgorithmType {
    rsa = 1,
    ec = 2,
    dsa = 17,
    edwards = 18,
    dh = 33,
    x448 = 34,
    x25519 = 35
}
export declare type KeyExportType = 'spki' | 'pkcs8' | 'specific' | 'specific-private' | 'specific-public';
export interface KeyExportOptions<T extends KeyFormat> {
    type: KeyExportType;
    format: T;
    cipher?: string;
    passphrase?: string | Buffer;
}
export declare abstract class KeyObject {
    protected constructor();
    static isKeyObject(o: any): boolean;
    abstract isPrivate(): boolean;
    abstract isPublic(): boolean;
    abstract isSecret(): boolean;
}
export declare abstract class AsymmetricKeyAlgorithm {
    static isAsymmetricKeyAlgorithm(o: any): boolean;
    get type(): AsymmetricAlgorithmType;
    get signable(): boolean;
    get keyAgreementable(): boolean;
    get cryptable(): boolean;
    abstract publicEncrypt(data: Buffer, publicKey: AsymmetricKeyObject): Buffer;
    abstract privateDecrypt(data: Buffer, privateKey: AsymmetricKeyObject): Buffer;
    abstract sign(digestOid: asn1js.ObjectIdentifier | null, hash: Buffer, privateKey: AsymmetricKeyObject): Buffer;
    abstract verify(digestOid: asn1js.ObjectIdentifier | null, hash: Buffer, signature: Buffer, publicKey: AsymmetricKeyObject): boolean;
    abstract dhComputeSecret(publicKey: AsymmetricKeyObject, privateKey: AsymmetricKeyObject): Buffer;
    abstract generateKeyPair(): {
        privateKey: AsymmetricKeyObject;
        publicKey: AsymmetricKeyObject;
    };

  public keyExport(key: AsymmetricKeyObject, options: KeyExportOptions<'pem'>): string;
  public keyExport(key: AsymmetricKeyObject, options?: KeyExportOptions<'der'>): Buffer;
  public keyImport(key: string, options: AlgorithmKeyImportOptions<'pem'>): AsymmetricKeyObject;
  public keyImport(key: Buffer, options?: AlgorithmKeyImportOptions<'der'>): AsymmetricKeyObject;
}
export declare abstract class AsymmetricKeyObject extends KeyObject {
    static isAsymmetricKeyObject(o: any): boolean;
    getKeyAlgorithm(): AsymmetricKeyAlgorithm;
    publicEncrypt(data: Buffer): Buffer;
    privateDecrypt(data: Buffer): Buffer;
    sign(digestOid: asn1js.ObjectIdentifier | null, hash: Buffer): Buffer;
    verify(digestOid: asn1js.ObjectIdentifier | null, hash: Buffer, signature: Buffer): boolean;
    dhComputeSecret(publicKey: AsymmetricKeyObject): Buffer;
    export(options: KeyExportOptions<'pem'>): string;
    export(options?: KeyExportOptions<'der'>): Buffer;
    get algorithmType(): AsymmetricAlgorithmType;
    get signable(): boolean;
    get verifyable(): boolean;
    get keyAgreementable(): boolean;
    get publicEncryptable(): boolean;
    get privateDecryptable(): boolean;
}
```
