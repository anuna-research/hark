// SPEC-019 CON-002 — the emit broker (view -> client accept path).
//
// The ONE accept path every intent crosses (the sandboxed iframe broker AND the
// client-owned inert editors route through here). Each step is a gate; failing
// any one rejects WITHOUT touching the store:
//
//   1 identify   (thread, dialect) := registry[MessagePort]  — NOT from payload
//   2 recognise  verb ∈ emit-grammar(dialect) ∧ verb ∉ core performatives  (REQ-011)
//   3 bind       :from := auth user; room; :thread; :caused-by := pickCausedBy  (REQ-012b/14)
//   4 validate   shape + closed + size + value-domain + verify_causal = Valid  (REQ-023/026/008)
//   5 sign       content-address (SHA-256) + Ed25519-sign + (MLS-encrypt)  (REQ-013)
//   6 union      append to the store; everyone re-projects
//
// A view supplies ONLY { verb, kw } — no routing, identity, or causal metadata
// (CON-002). Any :from/:thread/:dialect/:caused-by it tries to assert that
// CONFLICTS with the binding is a forge and is rejected (REQ-012c).
//
// Dependency-injected `host` so this is unit-testable under node without the DOM:
//   host.me()                       -> the authenticated signer handle
//   host.roomOf(thread)             -> the room/audience for a thread
//   host.canonicalize(cbclString)   -> canonical form (the cbcl-wasm parser)
//   host.contentAddress(canonical)  -> Promise<hex> SHA-256 of the canonical bytes
//   host.send(canonical)            -> Promise<bool> (Ed25519-sign + wire; sendCBCL)
//   host.store                      -> ThreadStore
//   host.onState(thread)            -> recompute projection + push to the view (optional)
//   host.report(frameInfo)          -> wire-tap UI hook (optional)

import { getDialect, checkShape } from './dialects.js';
import { validSet, verifyCausal, VALID, observedEntries, currentWrites } from './projection.js';
import { normaliseCausedBy } from './store.js';

// The eight core control/identity performatives a view may NEVER cause (REQ-011),
// even if a (mis)declared dialect grammar tried to include one. The grammar
// allowlist is the primary gate; this denylist is defence-in-depth.
// (cbcl-core message.rs CorePerformative); `lang` (the dialect wrapper) is added
// as defence-in-depth so a view can't emit a nested wrapper to escape its scope.
export const CORE_PERFORMATIVES = new Set([
  'tell', 'ask', 'reply', 'error', 'ok', 'cancel', 'hello', 'bye', 'lang',
]);

// fields a view must never set on an intent — the client owns provenance/routing.
const RESERVED = new Set(['from', 'thread', 'dialect', 'caused-by', 'caused_by', 'audience', 'sig']);

/** Serialise a JS keyword value to a CBCL s-expression fragment. */
function val(v) {
  if (Array.isArray(v)) return '(' + v.map(val).join(' ') + ')';
  if (v && typeof v === 'object') {
    return '(' + Object.entries(v).map(([k, x]) => `(${k} ${val(x)})`).join(' ') + ')';
  }
  if (typeof v === 'string') return `"${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
  if (typeof v === 'boolean') return v ? '#t' : '#f'; // CBCL's boolean literals
  return String(v);
}

/** Serialise a keyword record as CBCL `:key value` pairs. */
export function keywordText(kw) {
  return Object.entries(kw).map(([k, v]) => `:${k} ${val(v)}`).join(' ');
}

const token = v => /^[^\s()"\\]+$/.test(String(v)) ? String(v) : val(String(v));

/** Build the canonical-ish CBCL message string with client-bound provenance.
 *  Matches the production wire form `(lang <dialect> (<verb> <@room> … :thread …
 *  :caused-by … :from …))` — the room is the INNER recipient, so the envelope
 *  audience (recipientOf, which descends the lang wrapper) is derived correctly. */
export function buildMessage({ dialect, room, verb, kw, causedBy, thread, from }) {
  const kwStr = keywordText(kw);
  // The canonical serializer emits causal references as bare symbols, even
  // when quoted on input. Tag hex digests so numeric-leading addresses survive
  // every parse/canonicalize pass. The store decodes this wire spelling.
  const wireHash = hash => /^[0-9a-f]{64}$/.test(hash) ? `sha256-${hash}` : hash;
  const cb = causedBy === 'begin' ? 'begin' : val(Array.isArray(causedBy) ? causedBy.map(wireHash) : wireHash(causedBy));
  const inner = `(${verb} ${token(room)}${kwStr ? ' ' + kwStr : ''} :caused-by ${cb} :thread ${token(thread)} :from ${token(from)})`;
  return `(lang ${dialect} ${inner})`;
}

/** The client picks :caused-by = an in-store message of an allowed predecessor
 *  type (REQ-014). When the verb can follow ITSELF (a self-chainable act such as
 *  `arrive`/`vote-next`), chain off the SIGNER'S OWN causal tip so a re-act is a
 *  distinct message with strictly greater causal depth — which is what makes
 *  latest-per-signer actually track the signer's most-recent act (REQ-024).
 *  Without this, a repeated act picks the same predecessor, hashes identically,
 *  and is silently deduped by the G-Set (you "can't re-select"). Falls back to
 *  the global content-hash order (e.g. the opener) for a first act, or 'begin'. */
export function pickCausedBy(dialect, verb, threadMsgs, from) {
  const allowed = (dialect.protocol && dialect.protocol[verb]) || ['begin'];
  const candidates = threadMsgs.filter((m) => allowed.includes(m.verb));
  if (candidates.length === 0) return 'begin';
  const maxByCid = (pool) => pool.reduce((b, m) => (!b || m.cid > b.cid ? m : b), null);
  // prefer the signer's own chain tip (the own message no other own message
  // points at), so re-acts extend a linear per-signer chain.
  const own = from ? candidates.filter((m) => m.signer === from) : [];
  if (own.length) {
    const referenced = new Set();
    for (const m of own) for (const cb of normaliseCausedBy(m.causedBy)) referenced.add(cb);
    const tips = own.filter((m) => !referenced.has(m.cid));
    return maxByCid(tips.length ? tips : own).cid;
  }
  return maxByCid(candidates).cid;
}

export class EmitReject extends Error {
  constructor(reason) { super(reason); this.name = 'EmitReject'; this.reason = reason; }
}

export function makeBroker(host) {
  /**
   * Run the accept path for an intent bound to (thread, dialectName) by its port.
   * `rawKw` is the untrusted keyword payload. Returns { ok, cid } on accept or
   * { ok:false, reason } on any gate failure (the store is never touched on reject).
   */
  async function runIntent(thread, dialectName, verb, rawKw) {
    const report = (info) => { if (host.report) host.report(info); };
    const reject = (reason, label) => {
      report({ ok: false, thread, dialect: dialectName, verb: label || verb, reason });
      return { ok: false, reason };
    };

    const dialect = (host.getDialect || getDialect)(dialectName);
    if (!dialect) return reject(`unknown dialect ${dialectName}`);

    // 2 recognise — grammar + core-verb denylist (REQ-011).
    if (CORE_PERFORMATIVES.has(verb)) return reject(`'${verb}' is a core performative — never view-causable`);
    if (!dialect.grammar.includes(verb)) return reject(`'${verb}' not in ${dialectName} emit-grammar`);

    // 2b reject forged routing / identity (REQ-012c): a view may not assert any
    // reserved field. (A conflicting :thread/:dialect/:from is a forge attempt.)
    if (!rawKw || typeof rawKw !== 'object' || Array.isArray(rawKw)) return reject('intent keywords must be a record');
    const kw = Object.create(null);
    for (const [k, v] of Object.entries(rawKw || {})) {
      const key = k.toLowerCase();
      if (RESERVED.has(key)) {
        // a value that conflicts with the binding is an explicit forge; even a
        // matching one is stripped (the client is the sole authority on routing).
        if (key === 'from' && v !== host.me()) return reject(`view tried to set :from ${v} — client binds :from ${host.me()}`, `spoof ${verb}`);
        if (key === 'thread' && v !== thread) return reject(`view tried to route to thread ${v} — bound to ${thread}`, `forge ${verb}`);
        if (key === 'dialect' && v !== dialectName) return reject(`view tried to route to dialect ${v} — bound to ${dialectName}`, `forge ${verb}`);
        continue; // strip reserved fields; the client supplies them
      }
      kw[k] = v;
    }

    // 3 bind — provenance + routing from the binding, not the payload (REQ-012b/14).
    const from = host.me();
    const room = host.roomOf(thread);
    const threadMsgs = host.store.messages(thread);
    const causal = validSet(threadMsgs, dialect.protocol || {}, dialect.verifyCausal);
    const valid = dialect.recognize ? causal.filter(m => dialect.recognize(m, causal)) : causal;

    // 3b register replacement: the host names the writes this one replaces,
    // from its accepted history. A view-supplied list is a forge attempt.
    // A keyed register replaces only the current writes for the intent's key;
    // its delete verb binds the same way and must have something to delete.
    // A write also names the key's current deletions: that has no effect on
    // state, but keeps a re-added value from repeating the deleted write's
    // exact content address, which would deduplicate it into the deletion.
    for (const { verb: target, replaces, key, drop } of (dialect.registers || []).filter(rule => rule.verb === verb || rule.drop === verb)) {
      if (Object.hasOwn(kw, replaces)) return reject(`view tried to set :${replaces} — client binds replacements`, `forge ${verb}`);
      const sameKey = m => key === undefined || m.kw[key] === kw[key];
      const writes = currentWrites(target, replaces, valid, key, drop).filter(sameKey);
      if (verb === drop && !writes.length) return reject('no current value to delete');
      const deletions = verb === target && drop !== undefined ? currentWrites(drop, replaces, valid, key, target).filter(sameKey) : [];
      const current = [...writes, ...deletions].map(m => m.cid).sort();
      if (current.length > 64) return reject('register replacement exceeds 64 values');
      kw[replaces] = current;
    }

    // 3c observed removal: the host names the live additions of the intent's
    // value, never the untrusted view. They ride a data field rather than
    // :caused-by, which CBCL admits as a list only under an (all ...) fan-in.
    const removals = new Map();
    for (const rule of (dialect.observedSets || []).filter(rule => rule.remove === verb)) {
      if (!removals.has(rule.removes)) removals.set(rule.removes, []);
      removals.get(rule.removes).push(rule);
    }
    for (const [removes, rules] of removals) {
      if (Object.hasOwn(kw, removes)) return reject(`view tried to set :${removes} — client binds removals`, `forge ${verb}`);
      const observed = new Set();
      for (const { add, remove, field } of rules) {
        for (const message of observedEntries(add, remove, field, removes, valid)) {
          if (message.kw[field] === kw[field]) observed.add(message.cid);
        }
      }
      if (!observed.size) return reject('no observed additions to remove');
      if (observed.size > 64) return reject('observed removal exceeds 64 additions');
      kw[removes] = [...observed].sort();
    }

    // 4 validate the CONSTRUCTED message before signing (REQ-023/026): shape +
    // closed + size + value-domain.
    const sh = checkShape(dialect, verb, kw, valid);
    if (!sh.ok) return reject(sh.reason, `shape-violation ${verb}`);
    if (dialect.verifyShape) {
      const cbclShape = dialect.verifyShape(verb, kw); // cbcl-rs: presence and type
      if (!cbclShape.ok) return reject(cbclShape.reason, `shape-violation ${verb}`);
    }
    if (dialect.recognize && !dialect.recognize({verb, kw}, valid)) return reject("invalid action fields");

    const causedBy = pickCausedBy(dialect, verb, valid, from);

    // 4b verify_causal = Valid at the current store (REQ-008/014): the message we
    // are about to sign must itself verify Valid.
    const canonicalDraft = buildMessage({ dialect: dialectName, room, verb, kw, causedBy, thread, from });
    let canonical = host.canonicalize ? host.canonicalize(canonicalDraft) : canonicalDraft;
    if (host.prepare) canonical = await host.prepare(canonical);
    const cid = await host.contentAddress(canonical);
    const candidate = { cid, verb, signer: from, thread, causedBy, kw };
    const byCid = new Map(threadMsgs.map((m) => [m.cid, m]));
    byCid.set(cid, candidate);
    const verdict = dialect.verifyCausal ? dialect.verifyCausal(candidate, byCid) : verifyCausal(candidate, byCid, dialect.protocol || {});
    if (verdict !== VALID) return reject(`constructed message verify_causal = ${verdict}`, `causal ${verb}`);

    // 5 sign + wire (REQ-013). The client is the sole signer; the view never is.
    if (host.me() !== from) return reject('identity changed before send');
    const sent = await host.send(canonical);
    if (sent === false) return reject('wire send blocked');

    // 6 optimistic union (the hub fans the signed copy back; dedup-by-hash makes
    // that a no-op — REQ-029). State re-projects.
    host.store.append(candidate);
    if (host.onState) host.onState(thread);
    report({ ok: true, thread, dialect: dialectName, verb, cid, causedBy, from, kw });
    return { ok: true, cid };
  }

  // Hashing and signing yield. Serialize per object so rapid re-acts see the
  // previous accepted act before choosing their causal predecessor (REQ-024).
  const queues = new Map();
  function applyIntent(thread, dialectName, verb, rawKw = {}) {
    const previous = queues.get(thread) || Promise.resolve();
    const next = previous.then(() => runIntent(thread, dialectName, verb, rawKw)).catch(error => {
      const result = { ok: false, reason: error.message || String(error) };
      if (host.report) host.report({ ...result, thread, dialect: dialectName, verb });
      return result;
    });
    queues.set(thread, next);
    void next.then(() => { if (queues.get(thread) === next) queues.delete(thread); });
    return next;
  }
  return { applyIntent };
}

export { normaliseCausedBy };
