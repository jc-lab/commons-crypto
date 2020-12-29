import * as chai from 'chai';
const expect = chai.expect;
const assert = chai.assert;
const should = chai.should();

import * as asn1js from 'asn1js';

import * as cc from '../../src/index';

const USE_CONSOLE_OUTPUT = process.env.USE_CONSOLE_OUTPUT || false;

const digestOid = new asn1js.ObjectIdentifier({
  value: '2.16.840.1.101.3.4.2.1'
});

describe('RSA', function () {
  const priKey = cc.createPrivateKey(`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCz764g9Dr4ZXQDEw8+Il2mbWQ5ACInIBklISsqBmAh5SbnZkqv
cuZ6aj69AHV7IhrDujm730daSH8+wZjHV011V8/sSdK4qvvX0bRql3YUTNQbsBDj
PaV8RRHqHEw/NobbeqtX8QIRvF4eeRyjmLodI1G0N1JinKuM1XYpyKvqlQIDAQAB
AoGAO0CI+acTKCrYag7DrTVJ230YTMDjfjjOrvBeM2eIDoFUL0z6+Q2AIf2MjVZy
WUrgv2U6j8g1yeAnrrW3pqT0B0tQGYYAtAELNe2VZbBBVYQOUS53kq3VowYYMM3z
8R2rEmZTsreFT6uq9+9RMtm5W9ugti//BMte5T8JP5o0l10CQQDntf/ieUmndkGr
t55ROUZZOZJmjr5CTELvjbwnFDx50qh6b1Tzld6l/Gps2b+KxcVswM86Q25PAnbx
VP/rmWoTAkEAxsxMcIcvuDes5A2UcVU7TiyYAsO9vVEfqtDDff50PXd/xNa7ICe0
VtJmVazm8B5K6fVh0Z3EUNff+lRyz61ttwJATmI5D8nr6qSMjqRtABkZ/TEGn38G
SbM2qYcO8UFdO/DRYamr2UMHsKr07aGztCQ3JxUKhTEubbftuLICaRba1QJAfxYL
p8REVVgCRqgHxYvfJdKMOvg3S9eYjvJ2hw0r8j96hrNfXOcE+pv2n76ww8AZ1Aby
Sba50ZSvsrBZ1TnhcQJBAK/jKY+AXaACpoPrradRA80S+WEq8L10o7UYFPxgDdcN
s2QyKSJ2+ZiRXRFpd7L3j6REj+YELpq+10s5lvkgbyU=
-----END RSA PRIVATE KEY-----`);
  const pubKey = cc.createPublicKey(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCz764g9Dr4ZXQDEw8+Il2mbWQ5
ACInIBklISsqBmAh5SbnZkqvcuZ6aj69AHV7IhrDujm730daSH8+wZjHV011V8/s
SdK4qvvX0bRql3YUTNQbsBDjPaV8RRHqHEw/NobbeqtX8QIRvF4eeRyjmLodI1G0
N1JinKuM1XYpyKvqlQIDAQAB
-----END PUBLIC KEY-----`);

  it('Import pkcs1 private key - same - pem', function () {
    const algorithm = priKey.getKeyAlgorithm();

    const importedKey = algorithm.keyImport(`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCz764g9Dr4ZXQDEw8+Il2mbWQ5ACInIBklISsqBmAh5SbnZkqv
cuZ6aj69AHV7IhrDujm730daSH8+wZjHV011V8/sSdK4qvvX0bRql3YUTNQbsBDj
PaV8RRHqHEw/NobbeqtX8QIRvF4eeRyjmLodI1G0N1JinKuM1XYpyKvqlQIDAQAB
AoGAO0CI+acTKCrYag7DrTVJ230YTMDjfjjOrvBeM2eIDoFUL0z6+Q2AIf2MjVZy
WUrgv2U6j8g1yeAnrrW3pqT0B0tQGYYAtAELNe2VZbBBVYQOUS53kq3VowYYMM3z
8R2rEmZTsreFT6uq9+9RMtm5W9ugti//BMte5T8JP5o0l10CQQDntf/ieUmndkGr
t55ROUZZOZJmjr5CTELvjbwnFDx50qh6b1Tzld6l/Gps2b+KxcVswM86Q25PAnbx
VP/rmWoTAkEAxsxMcIcvuDes5A2UcVU7TiyYAsO9vVEfqtDDff50PXd/xNa7ICe0
VtJmVazm8B5K6fVh0Z3EUNff+lRyz61ttwJATmI5D8nr6qSMjqRtABkZ/TEGn38G
SbM2qYcO8UFdO/DRYamr2UMHsKr07aGztCQ3JxUKhTEubbftuLICaRba1QJAfxYL
p8REVVgCRqgHxYvfJdKMOvg3S9eYjvJ2hw0r8j96hrNfXOcE+pv2n76ww8AZ1Aby
Sba50ZSvsrBZ1TnhcQJBAK/jKY+AXaACpoPrradRA80S+WEq8L10o7UYFPxgDdcN
s2QyKSJ2+ZiRXRFpd7L3j6REj+YELpq+10s5lvkgbyU=
-----END RSA PRIVATE KEY-----`, {
      format: 'pem'
    });

    expect(importedKey.equals(priKey)).to.equal(true);
  });

  it('Import pkcs1 private key - same - der', function () {
    const algorithm = priKey.getKeyAlgorithm();

    const importedKey = algorithm.keyImport(
      Buffer.from(`MIICXAIBAAKBgQCz764g9Dr4ZXQDEw8+Il2mbWQ5ACInIBklISsqBmAh5SbnZkqvcuZ6aj69AHV7IhrDujm730daSH8+wZjHV011V8/sSdK4qvvX0bRql3YUTNQbsBDjPaV8RRHqHEw/NobbeqtX8QIRvF4eeRyjmLodI1G0N1JinKuM1XYpyKvqlQIDAQABAoGAO0CI+acTKCrYag7DrTVJ230YTMDjfjjOrvBeM2eIDoFUL0z6+Q2AIf2MjVZyWUrgv2U6j8g1yeAnrrW3pqT0B0tQGYYAtAELNe2VZbBBVYQOUS53kq3VowYYMM3z8R2rEmZTsreFT6uq9+9RMtm5W9ugti//BMte5T8JP5o0l10CQQDntf/ieUmndkGrt55ROUZZOZJmjr5CTELvjbwnFDx50qh6b1Tzld6l/Gps2b+KxcVswM86Q25PAnbxVP/rmWoTAkEAxsxMcIcvuDes5A2UcVU7TiyYAsO9vVEfqtDDff50PXd/xNa7ICe0VtJmVazm8B5K6fVh0Z3EUNff+lRyz61ttwJATmI5D8nr6qSMjqRtABkZ/TEGn38GSbM2qYcO8UFdO/DRYamr2UMHsKr07aGztCQ3JxUKhTEubbftuLICaRba1QJAfxYLp8REVVgCRqgHxYvfJdKMOvg3S9eYjvJ2hw0r8j96hrNfXOcE+pv2n76ww8AZ1AbySba50ZSvsrBZ1TnhcQJBAK/jKY+AXaACpoPrradRA80S+WEq8L10o7UYFPxgDdcNs2QyKSJ2+ZiRXRFpd7L3j6REj+YELpq+10s5lvkgbyU=`, 'base64'), {
      format: 'der'
    });

    expect(importedKey.equals(priKey)).to.equal(true);
  });

  it('Import pkcs8 private key - same - pem', function () {
    const algorithm = priKey.getKeyAlgorithm();

    const importedKey = algorithm.keyImport(`-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALPvriD0OvhldAMT
Dz4iXaZtZDkAIicgGSUhKyoGYCHlJudmSq9y5npqPr0AdXsiGsO6ObvfR1pIfz7B
mMdXTXVXz+xJ0riq+9fRtGqXdhRM1BuwEOM9pXxFEeocTD82htt6q1fxAhG8Xh55
HKOYuh0jUbQ3UmKcq4zVdinIq+qVAgMBAAECgYA7QIj5pxMoKthqDsOtNUnbfRhM
wON+OM6u8F4zZ4gOgVQvTPr5DYAh/YyNVnJZSuC/ZTqPyDXJ4CeutbempPQHS1AZ
hgC0AQs17ZVlsEFVhA5RLneSrdWjBhgwzfPxHasSZlOyt4VPq6r371Ey2blb26C2
L/8Ey17lPwk/mjSXXQJBAOe1/+J5Sad2Qau3nlE5Rlk5kmaOvkJMQu+NvCcUPHnS
qHpvVPOV3qX8amzZv4rFxWzAzzpDbk8CdvFU/+uZahMCQQDGzExwhy+4N6zkDZRx
VTtOLJgCw729UR+q0MN9/nQ9d3/E1rsgJ7RW0mZVrObwHkrp9WHRncRQ19/6VHLP
rW23AkBOYjkPyevqpIyOpG0AGRn9MQaffwZJszaphw7xQV078NFhqavZQwewqvTt
obO0JDcnFQqFMS5tt+24sgJpFtrVAkB/FgunxERVWAJGqAfFi98l0ow6+DdL15iO
8naHDSvyP3qGs19c5wT6m/afvrDDwBnUBvJJtrnRlK+ysFnVOeFxAkEAr+Mpj4Bd
oAKmg+utp1EDzRL5YSrwvXSjtRgU/GAN1w2zZDIpInb5mJFdEWl3svePpESP5gQu
mr7XSzmW+SBvJQ==
-----END PRIVATE KEY-----`, {
      format: 'pem'
    });

    expect(importedKey.equals(priKey)).to.equal(true);
  });

  it('Import pkcs8 private key - same - der', function () {
    const algorithm = priKey.getKeyAlgorithm();

    const importedKey = algorithm.keyImport(
      Buffer.from(`MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALPvriD0OvhldAMTDz4iXaZtZDkAIicgGSUhKyoGYCHlJudmSq9y5npqPr0AdXsiGsO6ObvfR1pIfz7BmMdXTXVXz+xJ0riq+9fRtGqXdhRM1BuwEOM9pXxFEeocTD82htt6q1fxAhG8Xh55HKOYuh0jUbQ3UmKcq4zVdinIq+qVAgMBAAECgYA7QIj5pxMoKthqDsOtNUnbfRhMwON+OM6u8F4zZ4gOgVQvTPr5DYAh/YyNVnJZSuC/ZTqPyDXJ4CeutbempPQHS1AZhgC0AQs17ZVlsEFVhA5RLneSrdWjBhgwzfPxHasSZlOyt4VPq6r371Ey2blb26C2L/8Ey17lPwk/mjSXXQJBAOe1/+J5Sad2Qau3nlE5Rlk5kmaOvkJMQu+NvCcUPHnSqHpvVPOV3qX8amzZv4rFxWzAzzpDbk8CdvFU/+uZahMCQQDGzExwhy+4N6zkDZRxVTtOLJgCw729UR+q0MN9/nQ9d3/E1rsgJ7RW0mZVrObwHkrp9WHRncRQ19/6VHLPrW23AkBOYjkPyevqpIyOpG0AGRn9MQaffwZJszaphw7xQV078NFhqavZQwewqvTtobO0JDcnFQqFMS5tt+24sgJpFtrVAkB/FgunxERVWAJGqAfFi98l0ow6+DdL15iO8naHDSvyP3qGs19c5wT6m/afvrDDwBnUBvJJtrnRlK+ysFnVOeFxAkEAr+Mpj4BdoAKmg+utp1EDzRL5YSrwvXSjtRgU/GAN1w2zZDIpInb5mJFdEWl3svePpESP5gQumr7XSzmW+SBvJQ==`, 'base64'), {
      format: 'der'
    });

    expect(importedKey.equals(priKey)).to.equal(true);
  });

  it('Import rsa public key - same - pem', function () {
    const algorithm = pubKey.getKeyAlgorithm();

    const importedKey = algorithm.keyImport(`-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALPvriD0OvhldAMTDz4iXaZtZDkAIicgGSUhKyoGYCHlJudmSq9y5npq
Pr0AdXsiGsO6ObvfR1pIfz7BmMdXTXVXz+xJ0riq+9fRtGqXdhRM1BuwEOM9pXxF
EeocTD82htt6q1fxAhG8Xh55HKOYuh0jUbQ3UmKcq4zVdinIq+qVAgMBAAE=
-----END RSA PUBLIC KEY-----`, {
      format: 'pem'
    });

    expect(importedKey.equals(pubKey)).to.equal(true);
  });

  it('Import rsa public key - same - der', function () {
    const algorithm = pubKey.getKeyAlgorithm();

    const importedKey = algorithm.keyImport(
      Buffer.from(`MIGJAoGBALPvriD0OvhldAMTDz4iXaZtZDkAIicgGSUhKyoGYCHlJudmSq9y5npqPr0AdXsiGsO6ObvfR1pIfz7BmMdXTXVXz+xJ0riq+9fRtGqXdhRM1BuwEOM9pXxFEeocTD82htt6q1fxAhG8Xh55HKOYuh0jUbQ3UmKcq4zVdinIq+qVAgMBAAE=`, 'base64'), {
      format: 'der'
    });

    expect(importedKey.equals(pubKey)).to.equal(true);
  });

  it('Import pkcs1 private key - diff - pem', function () {
    const algorithm = priKey.getKeyAlgorithm();

    const importedKey = algorithm.keyImport(`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDrVCvu91BMQ1X6g+gRUK6jI5/Q7+7wL3SBpjTGB+bgwyxPeRzp
HEYXAw7VOgRNlLVZ3fAh9ta4jrLz35+UtlcKhY0UPCIb7G7iLQI1GL15FHIw/4qz
UM9qNU8mvnmPCHB7hAo0U6uit+XILBw8cKqEtsfRPZnboU5qR8rYfq9D8wIDAQAB
AoGAXBik2PCQzEfN7iyRNbWNoureMLa1m+n2foa9QIL3KB85yCBt4AzgoUDhHTGH
XZVFI9Znk+M2RSQThL2PhnOVvBgpo7z+MueqO6sRcQ51wRIIZ2qrMEBxdcZWGpyg
gfeLXCrU1ZyVDC4ASfiCr5wU/NCOE3NevnUpWemfD8pkpQECQQD+mqVvSnA1/mQQ
Desy02d6pLhsLrGJldPYtOLAKI3aVOWCEcqSZfNdLK0PNE0EDviwGnLG5YITDXxs
3fsI7KTZAkEA7J54oqmEr+uWp3GIV42bWDsXSY0+09L/Xevc9ZTkMaXZf83tp0tY
xCki2bSXH0RC/NOoOx1BPgGJiJcDDhH/qwJAJHWu5S4KvaCtYaMsoD2n3udBxbQ2
FlbPXIQiyJPGJJLtvt+fW7Gf1SL1sWyy7rbaJBXVg+gP5XyT6d8r+M4ymQJAT8Mr
z0ltnQ/BfThcSYdGsntY4kZmw2kBBFwZ4/8I3WOW6eo1DovrpFRplxG1T6jnG+sN
br/x2kESZ6TgNsICeQJBALh6wyosRb4lReYpCPmZlyymtRMClGSlszUS1BOQjc05
VBCqtJLN9Icldt8ZZw22BfaSl7T1jRS1zGJJKufunhM=
-----END RSA PRIVATE KEY-----`, {
      format: 'pem'
    });

    expect(importedKey.equals(priKey)).to.not.equal(true);
  });

  it('Import spki public key - same - pem', function () {
    const algorithm = pubKey.getKeyAlgorithm();

    const importedKey = algorithm.keyImport(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCz764g9Dr4ZXQDEw8+Il2mbWQ5
ACInIBklISsqBmAh5SbnZkqvcuZ6aj69AHV7IhrDujm730daSH8+wZjHV011V8/s
SdK4qvvX0bRql3YUTNQbsBDjPaV8RRHqHEw/NobbeqtX8QIRvF4eeRyjmLodI1G0
N1JinKuM1XYpyKvqlQIDAQAB
-----END PUBLIC KEY-----`, {
      format: 'pem'
    });

    expect(importedKey.equals(pubKey)).to.equal(true);
  });

  it('Import spki public key - same - der', function () {
    const algorithm = pubKey.getKeyAlgorithm();

    const importedKey = algorithm.keyImport(
      Buffer.from(`MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCz764g9Dr4ZXQDEw8+Il2mbWQ5ACInIBklISsqBmAh5SbnZkqvcuZ6aj69AHV7IhrDujm730daSH8+wZjHV011V8/sSdK4qvvX0bRql3YUTNQbsBDjPaV8RRHqHEw/NobbeqtX8QIRvF4eeRyjmLodI1G0N1JinKuM1XYpyKvqlQIDAQAB`, 'base64'), {
      format: 'der'
    });

    expect(importedKey.equals(pubKey)).to.equal(true);
  });

  it('Import spki public key - diff - pem', function () {
    const algorithm = pubKey.getKeyAlgorithm();

    const importedKey = algorithm.keyImport(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDrVCvu91BMQ1X6g+gRUK6jI5/Q
7+7wL3SBpjTGB+bgwyxPeRzpHEYXAw7VOgRNlLVZ3fAh9ta4jrLz35+UtlcKhY0U
PCIb7G7iLQI1GL15FHIw/4qzUM9qNU8mvnmPCHB7hAo0U6uit+XILBw8cKqEtsfR
PZnboU5qR8rYfq9D8wIDAQAB
-----END PUBLIC KEY-----`, {
      format: 'pem'
    });

    expect(importedKey.equals(pubKey)).to.not.equal(true);
  });

  it('signature and verify by KeyObject', function () {
    const signature = priKey.sign(digestOid, Buffer.from([0x1, 0x1, 0x1, 0x1]));
    const verifySuccess = pubKey.verify(digestOid, Buffer.from([0x1, 0x1, 0x1, 0x1]), signature);
    const verifyFailure = pubKey.verify(digestOid, Buffer.from([0x1, 0x1, 0x1, 0x2]), signature);

    if(USE_CONSOLE_OUTPUT) {
      console.log(`verifySuccess = ${verifySuccess}`);
      console.log(`verifyFailure = ${verifyFailure}`);
    }

    expect(
      verifySuccess
    ).to.equal(true);

    expect(
      verifyFailure
    ).to.equal(false);
  });

  it('signature and verify: 1.2.840.113549.1.1.11', function () {
    const data = Buffer.from([0x1, 0x1, 0x1, 0x1]);

    const signer = cc.createSignatureByAlgorithm('1.2.840.113549.1.1.11');
    if (!signer) {
      throw new Error('singer is null');
    }
    signer.init(priKey);
    signer.write(data);
    signer.end();
    const signature = signer.sign();

    const verifier = cc.createSignatureByAlgorithm('1.2.840.113549.1.1.11');
    if (!verifier) {
      throw new Error('verifier is null');
    }
    verifier.init(pubKey);
    verifier.write(data);
    verifier.end();

    expect(verifier.verify(signature)).to.true;
  });

  it('public encrypt and decrypt', function () {
    const cipherText = pubKey.publicEncrypt(Buffer.from('test'));
    if(USE_CONSOLE_OUTPUT) {
      console.log(`cipherText = ${cipherText.toString('hex')}`);
    }
    const decryptedText = priKey.privateDecrypt(cipherText).toString('ascii');
    if(USE_CONSOLE_OUTPUT) {
      console.log(`decryptedText = ${decryptedText}`);
    }
    expect(decryptedText).to.equal('test');
  });
});
