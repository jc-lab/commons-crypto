export function xor (a: Buffer, b: Buffer): Buffer {
  const len = a.length;
  let i = -1;
  while (++i < len) {
    a[i] ^= b[i];
  }
  return a;
}
