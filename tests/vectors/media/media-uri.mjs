// RFC 6920 content identity. No provider address or decryption material.
const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
export const MEDIA_URI_PREFIX = 'ni:///sha-256;';

export function renderMediaURI(digest) {
  if (typeof digest !== 'string' || digest.length !== 64 || !/^[0-9a-f]{64}$/.test(digest))
    throw Error('invalid-media-uri');
  let encoded = '',
    bits = 0,
    accumulator = 0;
  for (const pair of digest.match(/../g)) {
    accumulator = (accumulator << 8) | parseInt(pair, 16);
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      encoded += alphabet[(accumulator >>> bits) & 63];
    }
  }
  if (bits) encoded += alphabet[(accumulator << (6 - bits)) & 63];
  return MEDIA_URI_PREFIX + encoded;
}

export function parseMediaURI(uri) {
  if (
    typeof uri !== 'string' ||
    uri.length !== MEDIA_URI_PREFIX.length + 43 ||
    !/^ni:\/\/\/sha-256;[A-Za-z0-9_-]{43}$/.test(uri)
  )
    throw Error('invalid-media-uri');
  let digest = '',
    bits = 0,
    accumulator = 0;
  for (const char of uri.slice(MEDIA_URI_PREFIX.length)) {
    accumulator = (accumulator << 6) | alphabet.indexOf(char);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      digest += ((accumulator >>> bits) & 255).toString(16).padStart(2, '0');
    }
  }
  if (renderMediaURI(digest) !== uri) throw Error('invalid-media-uri');
  return digest;
}
