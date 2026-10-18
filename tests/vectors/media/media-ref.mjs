// SPEC-101 CON-001: the sole canonical reference recogniser and byte codec.
// No I/O or shell imports; WebCrypto is supplied at the boundary.
import { parseMediaURI, renderMediaURI, MEDIA_URI_PREFIX } from './media-uri.mjs';
export const MAX_STORED_BYTES = 8388608;
export const MIME_TYPES = Object.freeze([
  'image/png',
  'image/jpeg',
  'image/webp',
  'image/gif',
  'audio/wav',
  'audio/mpeg',
  'audio/ogg',
  'audio/webm',
  'audio/mp4',
]);
const grammar =
  /^cbcl-media\/1;h=([0-9a-f]{64});n=([1-9][0-9]{1,6});t=(image\/(?:png|jpeg|webp|gif)|audio\/(?:wav|mpeg|ogg|webm|mp4));k=([A-Za-z0-9_-]{21}[AQgw]);iv=([A-Za-z0-9_-]{16})$/;
const encoder = new TextEncoder();
const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
function invalid() {
  throw new Error('invalid-media-ref');
}
export function containsMediaRef(value) {
  return (
    typeof value === 'string' &&
    (value.includes('cbcl-media/1;') || value.includes(MEDIA_URI_PREFIX))
  );
}
function exact(value, keys) {
  return (
    value &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}
function validate(ref) {
  if (!ref || ['digest', 'type', 'key', 'iv'].some((key) => typeof ref[key] !== 'string'))
    invalid();
  const legacy = `cbcl-media/1;h=${ref.digest};n=${ref.size};t=${ref.type};k=${ref.key};iv=${ref.iv}`;
  const m = grammar.exec(legacy);
  if (
    !Number.isInteger(ref.size) ||
    !m ||
    m[0].length !== legacy.length ||
    ref.size < 48 ||
    ref.size > MAX_STORED_BYTES
  )
    invalid();
  return ref;
}
export function mediaDescriptor(reference) {
  const ref = parseMediaRef(reference);
  return {
    version: 2,
    uri: renderMediaURI(ref.digest),
    size: ref.size,
    type: ref.type,
    encryption: { algorithm: 'AES-128-GCM', key: ref.key, iv: ref.iv },
  };
}
export function mediaURI(reference) {
  return renderMediaURI(parseMediaRef(reference).digest);
}
export function parseMediaRef(value) {
  if (exact(value, ['digest', 'size', 'type', 'key', 'iv'])) return validate({ ...value });
  if (typeof value === 'object' || (typeof value === 'string' && value.startsWith('{'))) {
    let descriptor;
    try {
      descriptor = typeof value === 'string' ? JSON.parse(value) : value;
    } catch {
      invalid();
    }
    if (
      !exact(descriptor, ['version', 'uri', 'size', 'type', 'encryption']) ||
      descriptor.version !== 2 ||
      !exact(descriptor.encryption, ['algorithm', 'key', 'iv']) ||
      descriptor.encryption.algorithm !== 'AES-128-GCM'
    )
      invalid();
    let digest;
    try {
      digest = parseMediaURI(descriptor.uri);
    } catch {
      invalid();
    }
    const ref = validate({
      digest,
      size: descriptor.size,
      type: descriptor.type,
      key: descriptor.encryption.key,
      iv: descriptor.encryption.iv,
    });
    if (typeof value === 'string' && JSON.stringify(mediaDescriptor(ref)) !== value) invalid();
    return ref;
  }
  if (typeof value !== 'string') invalid();
  const m = grammar.exec(value);
  // JS `$` also matches before a final newline: require whole-field recognition.
  if (!m || m[0].length !== value.length) invalid();
  const size = Number(m[2]);
  if (size < 48 || size > MAX_STORED_BYTES) invalid();
  return { digest: m[1], size, type: m[3], key: m[4], iv: m[5] };
}
export function renderMediaRef(ref) {
  if (
    !ref ||
    typeof ref.digest !== 'string' ||
    typeof ref.type !== 'string' ||
    typeof ref.key !== 'string' ||
    typeof ref.iv !== 'string' ||
    !Number.isInteger(ref.size)
  )
    invalid();
  return JSON.stringify(mediaDescriptor(validate(ref)));
}
function byteArray(value) {
  if (value instanceof Uint8Array) return value.slice();
  if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
  throw new TypeError('expected-media-bytes');
}
function base64url(bytes) {
  let result = '',
    bits = 0,
    accumulator = 0;
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      result += alphabet[(accumulator >>> bits) & 63];
    }
  }
  if (bits) result += alphabet[(accumulator << (6 - bits)) & 63];
  return result;
}
function unbase64url(text) {
  let accumulator = 0,
    bits = 0,
    offset = 0;
  const bytes = new Uint8Array(Math.floor((text.length * 6) / 8));
  for (const char of text) {
    accumulator = (accumulator << 6) | alphabet.indexOf(char);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes[offset++] = (accumulator >>> bits) & 255;
    }
  }
  return bytes;
}
function hex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}
function equal(a, b) {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
  return difference === 0;
}
function platform(options) {
  const crypto = options.crypto ?? globalThis.crypto;
  if (!crypto?.subtle) throw new Error('media-crypto-unavailable');
  return crypto;
}
async function commitment(crypto, key) {
  const hmac = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
  ]);
  return new Uint8Array(
    await crypto.subtle.sign('HMAC', hmac, encoder.encode('cbcl-media/1 key-commitment'))
  );
}
function aad(type, size) {
  return encoder.encode(`cbcl-media/1;t=${type};n=${size}`);
}
export class MediaIntegrityError extends Error {
  constructor(code) {
    super('media-integrity-failed');
    this.name = 'MediaIntegrityError';
    this.code = code;
  }
}
export async function sealMedia(plaintext, type, options = {}) {
  const bytes = byteArray(plaintext),
    size = bytes.length + 48;
  if (!MIME_TYPES.includes(type)) throw new Error('unsupported-media-type');
  if (size > MAX_STORED_BYTES) throw new Error('media-too-large');
  const crypto = platform(options);
  // Explicit keys/IVs support byte-exact contract vectors. Normal callers omit
  // both: every seal draws an independent 128-bit key and 96-bit IV.
  const key =
    options.key === undefined ? crypto.getRandomValues(new Uint8Array(16)) : byteArray(options.key);
  const iv =
    options.iv === undefined ? crypto.getRandomValues(new Uint8Array(12)) : byteArray(options.iv);
  if (key.length !== 16 || iv.length !== 12) throw new Error('invalid-media-key-or-iv');
  const prefix = await commitment(crypto, key);
  const aes = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad(type, size), tagLength: 128 },
      aes,
      bytes
    )
  );
  const stored = new Uint8Array(size);
  stored.set(prefix);
  stored.set(sealed, 32);
  const digest = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', stored)));
  const ref = { digest, size, type, key: base64url(key), iv: base64url(iv) };
  return {
    reference: renderMediaRef(ref),
    descriptor: mediaDescriptor(ref),
    uri: renderMediaURI(digest),
    stored,
    ref,
  };
}
export async function openMedia(reference, storedObject, options = {}) {
  const ref = parseMediaRef(reference),
    stored = byteArray(storedObject),
    crypto = platform(options);
  const digest = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', stored)));
  if (digest !== ref.digest) throw new MediaIntegrityError('digest-mismatch');
  const key = unbase64url(ref.key);
  if (!equal(stored.subarray(0, 32), await commitment(crypto, key)))
    throw new MediaIntegrityError('commitment-mismatch');
  if (stored.length !== ref.size) throw new MediaIntegrityError('size-mismatch');
  try {
    const aes = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
    return new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: unbase64url(ref.iv),
          additionalData: aad(ref.type, ref.size),
          tagLength: 128,
        },
        aes,
        stored.subarray(32)
      )
    );
  } catch {
    throw new MediaIntegrityError('decryption-failed');
  }
}
