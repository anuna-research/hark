// SPEC-019 CON-003 / REQ-007..010, 024, 029, 030, 031 — the projection engine.
//
//   project : (Dialect, MessageStore) -> State
//
// The pipeline: verify_causal gates the set (Valid kept, Violation excluded,
// Unknown held pending); a FIXED combinator vocabulary folds the survivors into
// State. State is a RECORD, one field per combinator application; the verb is an
// ARGUMENT and the CRDT is the codomain (the CRDT lives on the field-fold, never
// on the verb). Every combinator is a pure SET-FUNCTION — `c(σ s) = c s` — with
// ties resolved by an internal content-hash order (REQ-024), so equal Valid sets
// give equal State (REQ-009/010). Pure: no I/O, no time, no randomness.
//
// CONVERGENCE, NOT FAIRNESS (REQ-030): the latest/last order buys agreement on A
// winner, not a fair one — a content hash is grindable and cross-signer causal
// depth is flood-advanceable. Contested single-assignment uses request->grant
// (REQ-031), realised as `authorityLast` below, never bare `last` over claims.

import { normaliseCausedBy } from './store.js';

// ---- verify_causal (3-valued lattice, REQ-008) -----------------------------
// A protocol maps a verb to its allowed predecessor verbs. 'begin' as an allowed
// predecessor means the verb may be a causal root. A verb absent from the
// protocol is unconstrained -> Valid (mirrors cbcl-rs protocol.rs).
// A `:caused-by` LIST is a fan-in, which cbcl-rs accepts only under an
// `(all ...)` declaration of at least two verbs. These protocols declare only
// single/`any` predecessors, so a list is a Violation here as it is there
// (FanInWithoutAllDecl), even with one element.

export const VALID = 'Valid';
export const UNKNOWN = 'Unknown';
export const VIOLATION = 'Violation';

/**
 * @param {object} msg     the message under test ({verb, causedBy}).
 * @param {Map<string,object>} byCid  cid -> Msg for the message's thread.
 * @param {Object<string,string[]>} protocol  verb -> allowed predecessor verbs.
 */
export function verifyCausal(msg, byCid, protocol) {
  const allowed = Object.hasOwn(protocol, msg.verb) ? protocol[msg.verb] : null;
  if (!allowed) return VALID; // not constrained by the protocol
  if (Array.isArray(msg.causedBy)) return VIOLATION;
  const preds = normaliseCausedBy(msg.causedBy);
  if (preds.length === 0) {
    // a causal root: allowed only if 'begin' is an admitted predecessor.
    return allowed.includes('begin') ? VALID : VIOLATION;
  }
  // Each predecessor must resolve in-store to an allowed type. A missing
  // predecessor makes the verdict Unknown (held pending, never silently Valid).
  let sawUnknown = false;
  for (const cb of preds) {
    const pred = byCid.get(cb);
    if (!pred) { sawUnknown = true; continue; }
    if (!allowed.includes(pred.verb)) return VIOLATION;
  }
  return sawUnknown ? UNKNOWN : VALID;
}

/**
 * The Valid, same-thread message set the combinators fold over (REQ-006/008).
 * Violation is excluded; Unknown is held pending (re-evaluated monotonically as
 * the store grows). Returns an array of Msg. A dialect with a verified CBCL
 * contract supplies `verify` (cbcl-rs); this JS rule serves only the built-in
 * dialects, which have no CBCL contract.
 */
export function validSet(messages, protocol, verify = (m, byCid) => verifyCausal(m, byCid, protocol)) {
  const byCid = new Map(messages.map((m) => [m.cid, m]));
  return messages.filter((m) => verify(m, byCid) === VALID);
}

// ---- the total order for latest/last (REQ-024) -----------------------------
// Causal depth = longest `:caused-by` chain to a root WITHIN the given set. Used
// only to let re-acts supersede within a single signer's own chain; cross-signer
// the order falls through to the content hash (convergent, NOT fair).

function depthMap(msgs) {
  const byCid = new Map(msgs.map((m) => [m.cid, m]));
  const memo = new Map();
  const depth = (cid, seen) => {
    if (memo.has(cid)) return memo.get(cid);
    if (seen.has(cid)) return 0; // cycle guard (shouldn't happen in a DAG)
    seen.add(cid);
    const m = byCid.get(cid);
    const preds = m ? normaliseCausedBy(m.causedBy).filter((p) => byCid.has(p)) : [];
    const d = preds.length === 0 ? 0 : 1 + Math.max(...preds.map((p) => depth(p, seen)));
    seen.delete(cid);
    memo.set(cid, d);
    return d;
  };
  for (const m of msgs) depth(m.cid, new Set());
  return memo;
}

/** Pick the winner of a concurrent set by content hash only (cross-signer `last`). */
function maxByHash(group) {
  let best = null;
  for (const m of group) if (!best || m.cid > best.cid) best = m;
  return best;
}

/** Within a single signer's chain: greatest causal depth, then content hash. */
function maxByDepthThenHash(group, depths) {
  let best = null;
  for (const m of group) {
    if (!best) { best = m; continue; }
    const dm = depths.get(m.cid) || 0;
    const db = depths.get(best.cid) || 0;
    if (dm > db || (dm === db && m.cid > best.cid)) best = m;
  }
  return best;
}

// ---- the combinator vocabulary (CON-003) -----------------------------------
// Each returns a CRDT-valued read. `msgs` is the Valid set. `field`/`key` name
// keyword fields on the message. These are the only combinators; a dialect's
// projection is a composition of them (ADR-011 — declarative, bounded).

/** G-Counter: count of DISTINCT `verb` messages (dedup-by-hash already applied). */
export function count(verb) {
  return (msgs) => new Set(msgs.filter(m => m.verb === verb).map(m => m.cid)).size;
}

/** Monotone latch (REQ-008): true once any Valid `verb` exists, true forever. */
export function exists(verb) {
  return (msgs) => msgs.some((m) => m.verb === verb);
}

/** Cross-signer register: select by content hash, not time or causality (REQ-030). */
export function last(verb, field) {
  return (msgs) => {
    const group = msgs.filter((m) => m.verb === verb);
    const w = maxByHash(group);
    return w ? w.kw[field] : null;
  };
}

/** LWW per signer: each signer's causally-latest `field` (depth-then-hash within their chain). */
export function latestPerSigner(verb, field) {
  return (msgs) => {
    const group = msgs.filter((m) => m.verb === verb);
    const bySigner = new Map();
    for (const m of group) {
      const g = bySigner.get(m.signer) || [];
      g.push(m); bySigner.set(m.signer, g);
    }
    const out = {};
    for (const [signer, g] of bySigner) {
      const w = maxByDepthThenHash(g, depthMap(g));
      if (w) Object.defineProperty(out, signer, { value: w.kw[field], enumerable: true, configurable: true, writable: true });
    }
    return out;
  };
}

/** Map of registers: per distinct value of `keyField`, the latest `valueField`. */
export function latestPerKey(verb, keyField, valueField) {
  return (msgs) => {
    const group = msgs.filter((m) => m.verb === verb);
    const byKey = new Map();
    for (const m of group) {
      const k = m.kw[keyField];
      if (k == null) continue;
      const g = byKey.get(k) || [];
      g.push(m); byKey.set(k, g);
    }
    const out = {};
    for (const [k, g] of byKey) {
      const writers = new Map();
      for (const m of g) {
        if (!writers.has(m.signer)) writers.set(m.signer, []);
        writers.get(m.signer).push(m);
      }
      // Causal depth orders only one writer's revisions. Concurrent writers
      // are compared by hash, never by how long a chain they can manufacture.
      const w = maxByHash([...writers.values()].map(own => maxByDepthThenHash(own, depthMap(own))));
      if (w) Object.defineProperty(out, k, { value: w.kw[valueField], enumerable: true, configurable: true, writable: true });
    }
    return out;
  };
}

/**
 * histogram aggregates a SELECTOR's output (REQ-029 declared basis: one
 * contribution per signer/key). `selector` is a combinator returning a
 * {key: value} map (e.g. latestPerSigner). Returns {value: count}.
 */
export function histogram(selector) {
  return (msgs) => {
    const picked = selector(msgs); // {signer|key: value}
    const out = {};
    for (const v of Object.values(picked)) {
      if (v == null) continue;
      Object.defineProperty(out, v, { value: (Object.hasOwn(out, v) ? out[v] : 0) + 1, enumerable: true, configurable: true, writable: true });
    }
    return out;
  };
}

/**
 * REQ-031 request->grant: the assignment read from a designated AUTHORITY's
 * grant only. `grantVerb` carries the decision; `whoField` the assignee; only
 * grants whose signer === authority count (a grant from anyone else is ignored).
 * Convergent AND attributable — not a forgeable tiebreak over claims.
 */
export function authorityLast(grantVerb, whoField, authority) {
  return (msgs) => {
    const group = msgs.filter((m) => m.verb === grantVerb && m.signer === authority);
    // re-grants supersede within the authority's own chain by causal depth, then
    // content hash for genuinely-concurrent grants (REQ-024). A single grant wins
    // trivially; a chained re-assignment picks the deepest (latest) one.
    const depths = depthMap(group);
    const w = maxByDepthThenHash(group, depths);
    return w ? w.kw[whoField] : null;
  };
}

// SDK collection outputs are JSON arrays/maps, never JS Sets. Canonical value
// spelling provides a stable order and structural equality for scalar lists.
function uniqueValues(values) {
  return [...new Set(values.map(value => JSON.stringify(value)))].sort().map(value => JSON.parse(value));
}

/** One contribution per content-addressed event, also exposing its identity. */
export function events(verb, field) {
  return msgs => Object.fromEntries([...new Map(msgs.filter(m => m.verb === verb).map(m => [m.cid, m.kw[field]]))]
    .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0));
}

/** Grow-only set over distinct values of `field`. Multiplicity-invariant. */
export function setUnion(verb, field) {
  const select = events(verb, field);
  return msgs => uniqueValues(Object.values(select(msgs)));
}

/** Fixed key order prevents delivery order from affecting floating-point sums. */
export function sum(selector) {
  return msgs => {
    const selected = selector(msgs);
    return Object.keys(selected).sort().reduce((total, key) => total + selected[key], 0);
  };
}

export function counter(incVerb, decVerb, field) {
  return sum(msgs => Object.fromEntries(msgs.filter(m => m.verb === incVerb || m.verb === decVerb)
    .map(m => [m.cid, m.verb === incVerb ? m.kw[field] : -m.kw[field]])));
}

/**
 * Writes of `verb` that no other write names in its `replacesField`. The acyclic
 * protocol forbids a write causally following another write of the same verb,
 * so replacement is carried in data: the host binds the list, never the view.
 * With `keyField`, a write replaces only writes carrying the same key. A
 * `deleteVerb` message replaces the same way but contributes no value itself.
 */
export function currentWrites(verb, replacesField, msgs, keyField, deleteVerb) {
  const distinct = name => [...new Map(msgs.filter(m => m.verb === name).map(m => [m.cid, m])).values()];
  const writes = distinct(verb);
  const replacers = deleteVerb === undefined ? writes : [...writes, ...distinct(deleteVerb)];
  const keyOf = m => keyField === undefined ? '' : JSON.stringify(m.kw[keyField]);
  const replaced = new Set(replacers.flatMap(m =>
    (Array.isArray(m.kw[replacesField]) ? m.kw[replacesField] : []).map(cid => keyOf(m) + '\n' + cid)));
  return writes.filter(m => !replaced.has(keyOf(m) + '\n' + m.cid));
}

/** Multi-value register: every current write's value; concurrent writes remain visible. */
export function values(verb, field, replacesField) {
  return msgs => uniqueValues(currentWrites(verb, replacesField, msgs).map(m => m.kw[field]));
}

// Current writes grouped by key, in canonical key order so that map order,
// like its contents, is independent of delivery order.
function currentByKey(verb, keyField, replacesField, deleteVerb, msgs) {
  const groups = new Map();
  for (const m of currentWrites(verb, replacesField, msgs, keyField, deleteVerb)) {
    const key = m.kw[keyField];
    if (key == null) continue;
    const id = JSON.stringify(key);
    if (!groups.has(id)) groups.set(id, { key, writes: [] });
    groups.get(id).writes.push(m);
  }
  return [...groups].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([, group]) => group);
}

function keyedRecord(groups, read) {
  const out = {};
  for (const { key, writes } of groups) {
    Object.defineProperty(out, key, { value: read(writes), enumerable: true, configurable: true, writable: true });
  }
  return out;
}

/**
 * Map of multi-value registers: per key, every current value. A key with no
 * current write is absent, so an optional `deleteVerb` removes the writes it
 * names; a concurrent write it did not name keeps the key.
 */
export function valuesPerKey(verb, keyField, valueField, replacesField, deleteVerb) {
  return msgs => keyedRecord(currentByKey(verb, keyField, replacesField, deleteVerb, msgs),
    writes => uniqueValues(writes.map(m => m.kw[valueField])));
}

/** Map of registers: per key, one current value; concurrent writes resolve by content hash. */
export function registerPerKey(verb, keyField, valueField, replacesField, deleteVerb) {
  return msgs => keyedRecord(currentByKey(verb, keyField, replacesField, deleteVerb, msgs),
    writes => maxByHash(writes).kw[valueField]);
}

/**
 * Live addition instances. A removal names, in its host-bound `removesField`,
 * the additions it observed; it cancels only those that carry its value. An
 * addition it did not name, such as a concurrent one, survives.
 */
export function observedEntries(addVerb, removeVerb, field, removesField, msgs) {
  const byCid = new Map(msgs.map(m => [m.cid, m]));
  const removed = new Set();
  for (const message of byCid.values()) {
    if (message.verb !== removeVerb || !Array.isArray(message.kw[removesField])) continue;
    for (const cid of message.kw[removesField]) {
      const add = byCid.get(cid);
      if (add?.verb === addVerb && add.kw[field] === message.kw[field]) removed.add(cid);
    }
  }
  return [...byCid.values()].filter(m => m.verb === addVerb && !removed.has(m.cid));
}

export function observedSet(addVerb, removeVerb, field, removesField) {
  return msgs => uniqueValues(observedEntries(addVerb, removeVerb, field, removesField, msgs).map(m => m.kw[field]));
}

/**
 * Run a dialect's projection over a thread's messages.
 * @param {object} dialect  { protocol, project } — project: (validMsgs) -> State.
 * @param {object[]} messages  all messages in the thread.
 * @returns {object} the projected State.
 */
export function project(dialect, messages) {
  const valid = validSet(messages, dialect.protocol || {}, dialect.verifyCausal);
  return dialect.project(dialect.recognize ? valid.filter(m => dialect.recognize(m, valid)) : valid);
}
