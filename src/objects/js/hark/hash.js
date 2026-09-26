// hark shim: SHA-256 comes from the host (Rust sha2), not WebCrypto.
export async function sha256Hex(bytes) { return globalThis.__hark.sha256(typeof bytes === 'string' ? bytes : new TextDecoder().decode(bytes)); }
export async function contentAddress(canonicalString) { return globalThis.__hark.sha256(canonicalString); }
export function base64url(bytes) { let bin = ''; for (const b of bytes) bin += String.fromCharCode(b); return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
export function niName(digestBytesOrHex, mediaType) {
  let bytes = digestBytesOrHex;
  if (typeof digestBytesOrHex === 'string') bytes = new Uint8Array(digestBytesOrHex.match(/../g).map((h) => parseInt(h, 16)));
  const ct = mediaType ? `?ct=${encodeURIComponent(mediaType)}` : '';
  return `ni:///sha-256;${base64url(bytes)}${ct}`;
}
