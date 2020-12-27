import * as crypto from 'crypto';

const chai = require('chai');
const expect = chai.expect;
const assert = chai.assert;
const should = chai.should();

import * as cc from '../../src/index';

const USE_CONSOLE_OUTPUT = process.env.USE_CONSOLE_OUTPUT || false;

describe('EC Named Create Key', function () {
  const nodePrivKeyA = crypto.createPrivateKey(`-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgfs82+aZk5zFjAGhT4tO1
q4Mg7Lw3Y3okG1JQzR5Q9wKhRANCAASdmnZ/+ISGZIAPxduEQR/MxzW6epL9zH8/
k0Yn7DPLJiFa5rYZhA62+9jVqGiORPvWWvLvzG7RsjItUFEh8KnI
-----END PRIVATE KEY-----`);
  const nodePubKeyA = crypto.createPublicKey(`-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEnZp2f/iEhmSAD8XbhEEfzMc1unqS/cx/
P5NGJ+wzyyYhWua2GYQOtvvY1ahojkT71lry78xu0bIyLVBRIfCpyA==
-----END PUBLIC KEY-----`);

  const pubKey = cc.createAsymmetricKeyFromNode(nodePubKeyA);
  const priKey = cc.createAsymmetricKeyFromNode(nodePrivKeyA);

  it('SEC1 PEM Private Key', function () {
    const experimentalKey = cc.createAsymmetricKey({
      key: `-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIH7PNvmmZOcxYwBoU+LTtauDIOy8N2N6JBtSUM0eUPcCoAcGBSuBBAAK
oUQDQgAEnZp2f/iEhmSAD8XbhEEfzMc1unqS/cx/P5NGJ+wzyyYhWua2GYQOtvvY
1ahojkT71lry78xu0bIyLVBRIfCpyA==
-----END EC PRIVATE KEY-----`
    });
    expect(priKey.equals(experimentalKey)).to.equals(true);
  });

  it('SEC1 DER Private Key', function () {
    const experimentalKey = cc.createAsymmetricKey({
      key: Buffer.from(`MHQCAQEEIH7PNvmmZOcxYwBoU+LTtauDIOy8N2N6JBtSUM0eUPcCoAcGBSuBBAAK
oUQDQgAEnZp2f/iEhmSAD8XbhEEfzMc1unqS/cx/P5NGJ+wzyyYhWua2GYQOtvvY
1ahojkT71lry78xu0bIyLVBRIfCpyA==`, 'base64')
    });
    expect(priKey.equals(experimentalKey)).to.equals(true);
  });

  it('PKCS8 PEM Private Key', function () {
    const experimentalKey = cc.createAsymmetricKey({
      key: `-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgfs82+aZk5zFjAGhT4tO1
q4Mg7Lw3Y3okG1JQzR5Q9wKhRANCAASdmnZ/+ISGZIAPxduEQR/MxzW6epL9zH8/
k0Yn7DPLJiFa5rYZhA62+9jVqGiORPvWWvLvzG7RsjItUFEh8KnI
-----END PRIVATE KEY-----`
    });
    expect(priKey.equals(experimentalKey)).to.equals(true);
  });

  it('PKCS8 DER Private Key', function () {
    const experimentalKey = cc.createAsymmetricKey({
      key: Buffer.from(`MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgfs82+aZk5zFjAGhT4tO1
q4Mg7Lw3Y3okG1JQzR5Q9wKhRANCAASdmnZ/+ISGZIAPxduEQR/MxzW6epL9zH8/
k0Yn7DPLJiFa5rYZhA62+9jVqGiORPvWWvLvzG7RsjItUFEh8KnI`, 'base64')
    });
    expect(priKey.equals(experimentalKey)).to.equals(true);
  });

  it('SPKI PEM Public Key', function () {
    const experimentalKey = cc.createAsymmetricKey({
      key: `-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEnZp2f/iEhmSAD8XbhEEfzMc1unqS/cx/
P5NGJ+wzyyYhWua2GYQOtvvY1ahojkT71lry78xu0bIyLVBRIfCpyA==
-----END PUBLIC KEY-----`
    });
    expect(pubKey.equals(experimentalKey)).to.equals(true);
  });

  it('SPKI DER Public Key', function () {
    const experimentalKey = cc.createAsymmetricKey({
      key: Buffer.from(`MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEnZp2f/iEhmSAD8XbhEEfzMc1unqS/cx/
P5NGJ+wzyyYhWua2GYQOtvvY1ahojkT71lry78xu0bIyLVBRIfCpyA==`, 'base64')
    });
    expect(pubKey.equals(experimentalKey)).to.equals(true);
  });
});
