import chai from 'chai';
const expect = chai.expect;
const assert = chai.assert;
const should = chai.should();

//@ts-ignore
const requireFunc = typeof __non_webpack_require__ === "function" ? __non_webpack_require__ : require;
const path = requireFunc('path');
const fs = requireFunc('fs');

import * as cc from '../../src/index';

const USE_CONSOLE_OUTPUT = process.env.USE_CONSOLE_OUTPUT || false;

const GCM_TEST_VECTOR_DIR = path.resolve(__dirname, '../gcmtestvectors/');

interface TestVector {
  count: number;
  key: Buffer;
  iv: Buffer;
  ct: Buffer;
  aad: Buffer;
  tag: Buffer;
  pt: Buffer;
  fail: boolean;
}

interface TestVectorGroup {
  keyLen: number;
  ivLen: number;
  ptLen: number;
  aadLen: number;
  tagLen: number;
  vectors: TestVector[];
}

function readTestVector(file: string): TestVectorGroup[] {
  const content = fs
    .readFileSync(file, {encoding: 'utf8'})
    .split('\n');
  const groups: TestVectorGroup[] = [];
  let currentGroup: TestVectorGroup = {
    vectors: []
  } as any;
  let currentVector: TestVector | null = null;
  let state = 0;
  for(let i=0; i < content.length; i++) {
    const line = content[i].trim();
    if (line.startsWith('#'))
      continue;
    const m1 = /^\[(\w+) = (.*)\]$/.exec(line);
    if (m1) {
      if (state === 1) {
        groups.push(currentGroup as any);
        currentGroup = {
          vectors: []
        } as any;
        state = 0;
      }

      const key = m1[1].toLowerCase();
      switch (key) {
        case 'keylen':
          currentGroup.keyLen = parseInt(m1[2]);
          break;
        case 'ivlen':
          currentGroup.ivLen = parseInt(m1[2]);
          break;
        case 'ptlen':
          currentGroup.ptLen = parseInt(m1[2]);
          break;
        case 'aadlen':
          currentGroup.aadLen = parseInt(m1[2]);
          break;
        case 'taglen':
          currentGroup.tagLen = parseInt(m1[2]);
          break;
      }
    }
    else
    {
      if (!currentGroup) {
        throw new Error('Wrong data');
      }
      const vector: TestVector = currentVector || {
        fail: false
      } as any;
      if (!currentVector) {
        currentVector = vector;
      }
      if (!line.length) {
        if (vector.key) {
          currentGroup.vectors.push(vector);
          currentVector = null;
        }
      } else {
        const m2 = /^(\w+) = (.*)$/.exec(line);
        if (m2) {
          state = 1;

          const key = m2[1].toLowerCase();
          switch (key) {
            case 'count':
              vector.count = parseInt(m2[2]);
              break;
            case 'key':
              vector.key = Buffer.from(m2[2], 'hex');
              break;
            case 'iv':
              vector.iv = Buffer.from(m2[2], 'hex');
              break;
            case 'ct':
              vector.ct = Buffer.from(m2[2], 'hex');
              break;
            case 'aad':
              vector.aad = Buffer.from(m2[2], 'hex');
              break;
            case 'tag':
              vector.tag = Buffer.from(m2[2], 'hex');
              break;
            case 'pt':
              vector.pt = Buffer.from(m2[2], 'hex');
              break;
          }
        }
        else if (line === 'FAIL') {
          vector.fail = true;
        }
      }
    }
  }
  return groups;
}

describe('AES', function () {
  this.timeout(10000);
  // https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES#GCMVS
  it('AES-GCM Encrypt Test Vectors', function () {
    const testFiles = [
      path.join(GCM_TEST_VECTOR_DIR, 'gcmEncryptExtIV128.rsp'),
      path.join(GCM_TEST_VECTOR_DIR, 'gcmEncryptExtIV192.rsp'),
      path.join(GCM_TEST_VECTOR_DIR, 'gcmEncryptExtIV256.rsp')
    ];
    testFiles.forEach((testVectorFile) => {
      const groups = readTestVector(testVectorFile);
      groups.forEach((group) => {
        if (USE_CONSOLE_OUTPUT) {
          console.log('group:', {
            keyLen: group.keyLen,
            ivLen: group.ivLen,
            ptLen: group.ptLen,
            aadLen: group.aadLen,
            tagLen: group.tagLen
          });
        }
        group.vectors.forEach((vector) => {
          const algo = `aes-${group.keyLen}-gcm`;
          if (USE_CONSOLE_OUTPUT) {
            console.log(`vector algo=${algo}, count=${vector.count}`);
          }
          const cipher = cc.createCipher(algo);
          const ctBuffers: Buffer[] = [];
          if (!cipher) {
            throw new Error('cipher is null');
          }
          cipher.init({
            key: vector.key,
            iv: vector.iv,
            authTagLength: group.tagLen / 8
          });
          if (group.aadLen) {
            cipher.setAAD(vector.aad);
          }
          if (vector.pt) {
            const temp = cipher.update(vector.pt);
            if (temp) ctBuffers.push(temp);
          }
          {
            const temp = cipher.final();
            if (temp) ctBuffers.push(temp);
          }

          expect(cipher.getAuthTag()).eql(vector.tag);

          if (group.ptLen > 0 || vector.ct) {
            const ct = Buffer.concat(ctBuffers);
            expect(vector.ct).eql(ct);
          }
        });
      });
    });
  });
  it('AES-GCM Decrypt Test Vectors', function () {
    const testFiles = [
      path.join(GCM_TEST_VECTOR_DIR, 'gcmDecrypt128.rsp'),
      path.join(GCM_TEST_VECTOR_DIR, 'gcmDecrypt192.rsp'),
      path.join(GCM_TEST_VECTOR_DIR, 'gcmDecrypt256.rsp')
    ];
    testFiles.forEach((testVectorFile) => {
      const groups = readTestVector(testVectorFile);
      groups.forEach((group) => {
        if (USE_CONSOLE_OUTPUT) {
          console.log('group:', {
            keyLen: group.keyLen,
            ivLen: group.ivLen,
            ptLen: group.ptLen,
            aadLen: group.aadLen,
            tagLen: group.tagLen
          });
        }
        group.vectors.forEach((vector) => {
          const algo = `aes-${group.keyLen}-gcm`;
          if (USE_CONSOLE_OUTPUT) {
            console.log(`vector algo=${algo}, count=${vector.count}, fail=${vector.fail}`);
          }
          const cipher = cc.createDecipher(algo);
          const ptBuffers: Buffer[] = [];
          if (!cipher) {
            throw new Error('cipher is null');
          }
          cipher.init({
            key: vector.key,
            iv: vector.iv,
            authTagLength: group.tagLen / 8
          });
          if (group.aadLen) {
            cipher.setAAD(vector.aad);
          }
          if (vector.ct) {
            const temp = cipher.update(vector.ct);
            if (temp) ptBuffers.push(temp);
          }
          if (group.tagLen > 0 || vector.tag) {
            cipher.setAuthTag(vector.tag);
          }
          if (vector.fail) {
            expect(cipher.final.bind(cipher)).to.throw('Unsupported state or unable to authenticate data');
          } else {
            const temp = cipher.final();
            if (temp) ptBuffers.push(temp);
            if (group.ptLen > 0 || vector.pt) {
              const pt = Buffer.concat(ptBuffers);
              expect(vector.pt).eql(pt);
            }
          }
        });
      });
    });
  });
});
