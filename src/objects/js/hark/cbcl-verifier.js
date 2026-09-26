// hark shim: every CBCL judgement is made by cbcl-rs linked natively into hark
// (the cbcl-wasm crate at the cbcl-bus pin), never re-derived in JS.
export function readyCBCL() { return Promise.resolve(); }
export async function verifyCBCL(source) { const r = globalThis.__hark.verifyDialect(source); if (r !== 'ok') throw new Error(`CBCL dialect verification failed: ${r}`); }
function outcome(call) { try { return { ok: true, result: call() }; } catch (error) { return { ok: false, result: String(error?.message ?? error) }; } }
export function verifyShape(dialect, verb, message) {
  const { ok, result } = outcome(() => globalThis.__hark.verifyShape(`(verify-shape ${dialect} ${verb} ${message})`));
  return ok && result === 'ok' ? { ok: true } : { ok: false, reason: result };
}
export function verifyProtocol(dialect, thread, message, history = []) {
  const entries = history.map(([hash, text]) => `(${JSON.stringify(hash)} ${text})`).join(' ');
  const frame = `(verify-protocol ${dialect} ${JSON.stringify(thread)} ${message}${entries ? ` (history ${entries})` : ''})`;
  const { ok, result } = outcome(() => globalThis.__hark.verifyProtocol(frame));
  if (ok && result === 'ok') return 'Valid';
  if (result.startsWith('(pending')) return 'Unknown';
  return 'Violation';
}
export function messageHash(message) { return globalThis.__hark.messageHash(message); }
