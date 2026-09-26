// SPEC-085 REQ-006: names identify content; locators carry room and frontier.
import { niName, sha256Hex } from './hash.js';
import { normaliseCausedBy } from './store.js';
const HEX = /^[0-9a-f]{64}$/;
export function digestOfNi(name) {
  if (typeof name !== 'string' || !/^ni:\/\/\/sha-256;[A-Za-z0-9_-]{43}$/.test(name)) throw new Error('Expected an ni:///sha-256; name.');
  const encoded = name.slice('ni:///sha-256;'.length);
  const raw = atob(encoded.replace(/-/g, '+').replace(/_/g, '/') + '=');
  const hex = [...raw].map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
  if (!HEX.test(hex) || niName(hex) !== name) throw new Error('Non-canonical object name.');
  return hex;
}
export function recognizeFrontier(frontier) {
  if (!Array.isArray(frontier) || !frontier.length || frontier.length > 256 || !frontier.every(hash => HEX.test(hash)) || new Set(frontier).size !== frontier.length) throw new Error('Invalid or oversized frontier.');
  return frontier.slice().sort();
}
export async function pinName(frontier) { return niName(await sha256Hex(recognizeFrontier(frontier).join(','))); }

export function closedMessages(store, thread, frontier) {
  const seen = new Set(), visiting = new Set(), out = [];
  // Explicit traversal stack also avoids a recursive call-stack limit.
  const stack = frontier.map(cid => [cid, false]);
  while (stack.length) {
    const [cid, done] = stack.pop();
    if (done) { visiting.delete(cid); seen.add(cid); continue; }
    if (seen.has(cid)) continue;
    if (visiting.has(cid)) throw new Error('Cyclic object history.');
    const message = store.get(thread, cid);
    if (!message) throw new Error('Pinned history is incomplete: missing a causal predecessor.');
    if (out.length >= 10000) throw new Error('Pin closure exceeds the pilot limit.');
    visiting.add(cid); out.push(message); stack.push([cid, true]);
    for (const predecessor of normaliseCausedBy(message.causedBy)) stack.push([predecessor, false]);
  }
  return out;
}
export function objectLink(base, reference) {
  const url = new URL(base); const params = new URLSearchParams({object:reference.object});
  digestOfNi(reference.object);
  if (reference.pin) { digestOfNi(reference.pin); params.set('pin',reference.pin); params.set('frontier',recognizeFrontier(reference.frontier).join(',')); }
  url.hash = params.toString(); return url.href;
}
export function parseObjectLink(value, base) {
  if (value.startsWith('ni:')) { digestOfNi(value); return {object:value}; }
  if (value.length > 20000) throw new Error('Object link is too long.');
  const url = new URL(value, base);
  if (url.origin !== new URL(base).origin) throw new Error('Open this link on its originating hub.');
  const params = new URLSearchParams(url.hash.slice(1));
  if ([...params.keys()].some(key=>!['object','pin','frontier'].includes(key)) || [...params.keys()].length !== new Set(params.keys()).size) throw new Error('Invalid object link parameters.');
  const object = params.get('object'); digestOfNi(object);
  const result = {object, pathname:url.pathname};
  if (params.has('pin')) { result.pin=params.get('pin');digestOfNi(result.pin);result.frontier=recognizeFrontier((params.get('frontier')||'').split(',')); }
  else if (params.has('frontier')) throw new Error('Frontier requires a pin name.');
  return result;
}

// Older clients stored object URL fragments as invite capabilities. Recognize
// only a complete, valid object locator; arbitrary capabilities remain opaque.
export function isObjectLocatorFragment(fragment, base) {
  if (typeof fragment !== 'string' || !fragment.startsWith('object=')) return false;
  try { parseObjectLink('#' + fragment, base); return true; } catch { return false; }
}
