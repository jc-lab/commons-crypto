const isArrayBufferSupported = (Buffer.from(new Uint8Array([1]).buffer)[0] === 1);

export const arrayBufferToBuffer = isArrayBufferSupported ? arrayBufferToBufferAsArgument : arrayBufferToBufferCycle;

function arrayBufferToBufferAsArgument(ab): Buffer {
  return Buffer.from(ab);
}

function arrayBufferToBufferCycle(ab): Buffer {
  var buffer = Buffer.alloc(ab.byteLength);
  var view = new Uint8Array(ab);
  for (var i = 0; i < buffer.length; ++i) {
    buffer[i] = view[i];
  }
  return buffer;
}

export function bufferClone(value: ArrayBuffer): ArrayBuffer {
  return value.slice(0, value.byteLength);
}

export function bufferToArrayBuffer(buffer: Buffer | ArrayBuffer): ArrayBuffer {
  if (buffer instanceof ArrayBuffer)
    return buffer;
  var ab = new ArrayBuffer(buffer.length);
  var view = new Uint8Array(ab);
  for (var i = 0; i < buffer.length; ++i) {
    view[i] = buffer[i];
  }
  return ab;
}

export function encodePemLines(input: string): string[] {
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
export function parsePem(input: string): {
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
