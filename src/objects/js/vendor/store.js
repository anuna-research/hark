// SPEC-019 REQ-006 / REQ-007 / REQ-009 — the per-:thread message store.
//
// This mirrors cbcl-rs `ThreadedMessageStore` (store.rs): a G-Set / join-
// semilattice CvRDT. Messages are content-addressed elements; merge is set-union
// with dedup by content hash; `:caused-by` links form the causal DAG. Object
// instance identity is `:thread` (REQ-006) — only messages bearing that thread
// contribute to its state. State is NOT stored here; it is project(dialect, store)
// recomputed on demand (REQ-007) — the messages are the sole source of truth.
//
// Pure data structure — no I/O, order-independent (REQ-009).

/**
 * @typedef {Object} Msg
 * @property {string} cid       SHA-256 content address (hex) — the G-Set key.
 * @property {string} verb      the inner performative.
 * @property {string} signer    `:from` — the authenticated signer.
 * @property {string} thread    `:thread` — the addressing scope (REQ-006).
 * @property {('begin'|string|string[])} causedBy  `:caused-by`.
 * @property {Object} kw        keyword fields (field -> value).
 */

export class ThreadStore {
  constructor() {
    /** @type {Map<string, Map<string, Msg>>} thread -> (cid -> Msg) */
    this._threads = new Map();
  }

  _thread(thread) {
    let t = this._threads.get(thread);
    if (!t) { t = new Map(); this._threads.set(thread, t); }
    return t;
  }

  /**
   * Union a message into its thread. Returns true iff newly inserted (dedup by
   * content hash — a byte-identical re-delivery is the SAME element, REQ-029).
   */
  append(msg) {
    if (!msg || !msg.cid || !msg.thread) return false;
    const t = this._thread(msg.thread);
    if (t.has(msg.cid)) return false;
    t.set(msg.cid, msg);
    return true;
  }

  contains(thread, cid) {
    const t = this._threads.get(thread);
    return !!t && t.has(cid);
  }

  get(thread, cid) {
    const t = this._threads.get(thread);
    return t ? t.get(cid) || null : null;
  }

  /** All messages in a thread (order is insertion order; consumers must not rely on it). */
  messages(thread) {
    const t = this._threads.get(thread);
    return t ? [...t.values()] : [];
  }

  threads() {
    return [...this._threads.keys()];
  }

  /** CvRDT join: union another ThreadStore's elements into this one. Idempotent + commutative. */
  merge(other) {
    if (!(other instanceof ThreadStore)) return this;
    for (const thread of other.threads()) {
      for (const m of other.messages(thread)) this.append(m);
    }
    return this;
  }

  /**
   * Frontier of a thread: the cids not referenced by any other message's
   * `:caused-by` (the causal leaves). Mirrors store.rs `frontier`.
   */
  frontier(thread) {
    const msgs = this.messages(thread);
    const referenced = new Set();
    for (const m of msgs) {
      for (const cb of normaliseCausedBy(m.causedBy)) referenced.add(cb);
    }
    return msgs.map((m) => m.cid).filter((cid) => !referenced.has(cid));
  }

  /**
   * Causal closure (principal ideal ↓target): the target and all its transitive
   * `:caused-by` predecessors that are present in the thread. Mirrors store.rs
   * `causal_closure`. Returns an array of cids (target included), de-duplicated.
   */
  causalClosure(thread, target) {
    const t = this._threads.get(thread);
    if (!t || !t.has(target)) return [];
    const out = [];
    const seen = new Set();
    const stack = [target];
    while (stack.length) {
      const cid = stack.pop();
      if (seen.has(cid)) continue;
      seen.add(cid);
      const m = t.get(cid);
      if (!m) continue; // predecessor not (yet) present — bounded by what we hold
      out.push(cid);
      for (const cb of normaliseCausedBy(m.causedBy)) {
        if (!seen.has(cb)) stack.push(cb);
      }
    }
    return out;
  }
}

/** Normalise a `:caused-by` field to an array of predecessor hashes ('begin' -> []). */
export function normaliseCausedBy(causedBy) {
  if (causedBy === 'begin' || causedBy == null) return [];
  const hashes = Array.isArray(causedBy) ? causedBy : [causedBy];
  return hashes.filter(h => h && h !== 'begin').map(h =>
    typeof h === 'string' && /^sha256-[0-9a-f]{64}$/.test(h) ? h.slice(7) : h);
}
