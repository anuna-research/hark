// SPEC-019 — the hypermedia object controller (the effectful shell seam).
//
// Ties the pure core (store, projection, dialects, media-type) to the broker and
// the sandbox host, and wires the broker's host dependencies to the live web
// client (identity, the cbcl-wasm canonical parser, sendCBCL). app.js calls
// `ingest` for every incoming object message and `card` to mount an opener.

import { ThreadStore } from './store.js';
import { project } from './projection.js';
import { getDialect as builtinDialect, validateDialect, checkShape, DIALECTS } from './dialects.js';
import { makeBroker, buildMessage } from './emit.js';
import { createSandboxHost } from './sandbox.js';
import { contentAddress, niName } from './hash.js';
import { digestOfNi, pinName, closedMessages } from './object-address.js';
import { compileVerifiedDefinition, isSDKDialect } from './object-sdk.js';

// the protocol root verb (opener) for each object dialect — the verb whose only
// allowed predecessor is 'begin'. An opener gets a card; a follow feeds state.
function openerVerb(dialect) {
  for (const [verb, preds] of Object.entries(dialect.protocol || {})) {
    if (preds.length === 1 && preds[0] === 'begin') return verb;
  }
  return null;
}

// coerce a parsed-sexpr value to a plain JS value the pure core expects.
export function normalizeValue(v, asText) {
  if (v == null) return v;
  if (Array.isArray(v)) return v.map((x) => normalizeValue(x, asText));
  if (typeof v === 'object' && v.str !== undefined) return v.str; // quoted string
  const t = typeof v === 'string' ? v : asText(v);
  if (/^-?\d+$/.test(t)) return parseInt(t, 10);
  if (/^-?\d*\.\d+$/.test(t)) return parseFloat(t);
  if (t === '#t') return true;
  if (t === '#f') return false;
  return t;
}

export function createHypermediaController(deps) {
  const { me, send, canonicalize, prepare, defaultRoom, report } = deps;
  const store = new ThreadStore();
  const learned = new Map();
  const definitions = new Map();
  const views = new Map(); // view digest -> verified presentation, scoped to room
  const selectedViews = new Map(); // thread -> locally selected view digest (or null)
  const contracts = new Map(); // dialect -> exact v2 contract bytes
  const getDialect = name => learned.get(name) || builtinDialect(name);
  const isObjectDialect = name => !!getDialect(name);
  const pending = [];
  let pendingBytes = 0;
  let requestedHistory = false;
  const references = new Map();
  let ingestion = Promise.resolve();
  const threadDialect = new Map(); // thread -> dialect name
  const threadRoom = new Map();    // thread -> @room (the inner recipient)
  const roomOf = (thread) => threadRoom.get(thread) || (defaultRoom ? defaultRoom() : '');

  // reject any built-in dialect whose aggregations declare no multiplicity basis
  // (REQ-029) at load — never partially projected (ADR-011 error model).
  for (const [name, d] of Object.entries(DIALECTS)) {
    const v = validateDialect(d);
    if (!v.ok) console.error(`[hypermedia] dialect ${name} rejected at load: ${v.reason}`);
  }

  function dialectOf(thread) {
    const n = threadDialect.get(thread);
    return n ? getDialect(n) : null;
  }

  function reproject(thread) {
    const d = dialectOf(thread);
    if (!d) return null;
    const state = project(d, store.messages(thread));
    host.pushState(thread, state);
    return state;
  }

  const broker = makeBroker({
    me, roomOf, canonicalize, prepare, contentAddress, send, store, getDialect,
    onState: reproject,
    report,
  });
  const host = createSandboxHost(broker);

  /**
   * Ingest an incoming object message.
   * @param {object} rec { dialect, verb, kw, thread, from, causedBy, canonical }
   *   `kw` already normalized to plain JS; `canonical` the full (lang …) string.
   * Returns { cid, thread } or null if not an object dialect.
   */
  async function receive(rec) {
    if (!rec.thread || !rec.from || rec.causedBy == null) return null;
    let compiled = null;
    if (isSDKDialect(rec.dialect)) {
      const text = rec.kw?.['object-spec'];
      if (text !== undefined) {
        compiled = await compileVerifiedDefinition(text);
        if (compiled.name !== rec.dialect) throw new Error('object definition digest mismatch');
        if (rec.verb !== compiled.opener || rec.causedBy !== 'begin') return null;
      } else if (!learned.has(rec.dialect)) {
        const size = new TextEncoder().encode(rec.canonical).length;
        if (pending.length >= 128 || pendingBytes + size > 524288) throw new Error('pending object limit');
        pending.push(rec); pendingBytes += size; requestHistory(); return null;
      }
    }
    if (!compiled && !isObjectDialect(rec.dialect)) return null;
    const boundDialect = threadDialect.get(rec.thread), boundRoom = threadRoom.get(rec.thread);
    if ((boundDialect && boundDialect !== rec.dialect) || (boundRoom && boundRoom !== rec.room)) return null;
    const d = compiled?.dialect || getDialect(rec.dialect);
    if (!Object.hasOwn(d.protocol, rec.verb)) return null;
    // Domain validation needs the opener, which may arrive later. Recognize the
    // structural shape here; projection/emit enforce domains against known roots.
    let kw = rec.kw || {};
    if (compiled) { kw = { ...kw }; delete kw['object-spec']; }
    // CBCL has lists, not JS records: table rows travel as ((name amount) ...).
    if (rec.dialect === 'budget' && rec.verb === 'table' && Array.isArray(kw.rows)) {
      if (!kw.rows.every(row => Array.isArray(row) && row.length === 2 && typeof row[0] === 'string' && typeof row[1] === 'number' && Number.isFinite(row[1]))) return null;
      kw = { ...kw, rows: Object.fromEntries(kw.rows) };
    }
    if (!checkShape(d, rec.verb, kw, []).ok) return null;
    // recognize strips object-spec itself; cbcl-rs checks the whole message.
    if (compiled && !d.recognize({verb:rec.verb, kw: rec.kw}, [])) return null;
    const canonical = canonicalize ? canonicalize(rec.canonical) : rec.canonical;
    if (compiled) {
      if (!learned.has(rec.dialect) && learned.size >= 64) throw new Error('object definition limit');
      if (compiled.viewId && !views.has(compiled.viewId) && views.size >= 128) throw new Error('object view limit');
      if (!learned.has(rec.dialect)) {
        // The registry owns contract semantics; presentation is selected per instance.
        const base = await compileVerifiedDefinition(compiled.contractText);
        learned.set(rec.dialect, base.dialect);
        definitions.set(rec.dialect, rec.kw['object-spec']);
        contracts.set(rec.dialect, compiled.contractText);
      }
      if (compiled.viewId) views.set(compiled.viewId, {contract:rec.dialect, dialect:d});
      if (!selectedViews.has(rec.thread)) selectedViews.set(rec.thread, compiled.viewId);
    }
    threadDialect.set(rec.thread, rec.dialect);
    if (rec.room) threadRoom.set(rec.thread, rec.room);
    const cid = await contentAddress(canonical);
    // Store an object opener as received: its definition is part of the message
    // the native contract (and so cbcl-rs's shape check) requires.
    const inserted = store.append({
      cid, verb: rec.verb, signer: rec.from, thread: rec.thread,
      causedBy: rec.causedBy, kw: compiled ? rec.kw : kw,
    });
    if (inserted) reproject(rec.thread);
    if (!store.messages(rec.thread).some(message => message.verb === openerVerb(d))) requestHistory();
    if (compiled) {
      const waiting = pending.filter(item => item.dialect === rec.dialect);
      for (const item of waiting) {
        pending.splice(pending.indexOf(item), 1);
        pendingBytes -= new TextEncoder().encode(item.canonical).length;
        await receive(item);
      }
    }
    return { cid, thread: rec.thread };
  }

  function ingest(rec) {
    const result = ingestion.then(() => receive(rec));
    ingestion = result.catch(() => {});
    return result;
  }

  /** Mount an object card for a thread (called on the opener). Returns a DOM element. */
  function card(dialectName, thread, room) {
    const d = getDialect(dialectName);
    if (!d || (threadDialect.has(thread) && threadDialect.get(thread) !== dialectName)) return null;
    threadDialect.set(thread, dialectName);
    if (room) threadRoom.set(thread, room);
    const selected = selectedViews.get(thread) || null;
    const presentation = views.get(selected)?.dialect || d;
    return host.mount({
      dialect: dialectName,
      viewId: selected,
      ...(contracts.has(dialectName) ? {
        views: [{id:'', label:'Default state view'}, ...[...views].filter(([,v]) => v.contract === dialectName).map(([id]) => ({id, label:id.slice(0, 17)}))],
        onSelectView: id => selectView(thread, id || null),
        onImportView: async text => selectView(thread, await installView(dialectName, text)),
      } : {}),
      label: d.name,
      layout: presentation.layout,
      resources: presentation.resources,
      thread,
      room,
      viewBody: presentation.view(),
      tier: presentation.external ? 'untrusted-external' : undefined,
      indicator: presentation.external ? 'custom HTML/JS · network-capable' : undefined,
      // a LIVE thunk, not a snapshot: the opener may not be in the store yet when
      // the card mounts (ingest is async), so the view must read current state at
      // iframe-load time, not a stale mount-time projection.
      initialState: () => project(d, store.messages(thread)),
    });
  }

  async function installView(dialectName, text) {
    const contract = contracts.get(dialectName);
    if (!contract) throw new Error('Contract is unavailable.');
    const compiled = await compileVerifiedDefinition(JSON.stringify({version:2, contract, view:text}));
    if (!views.has(compiled.viewId) && views.size >= 128) throw new Error('object view limit');
    views.set(compiled.viewId, {contract:dialectName, dialect:compiled.dialect});
    return compiled.viewId;
  }

  function selectView(thread, viewId) {
    const dialectName = threadDialect.get(thread);
    if (!contracts.has(dialectName)) throw new Error('Contract is unavailable.');
    if (viewId !== null && views.get(viewId)?.contract !== dialectName) throw new Error('View is unavailable or incompatible with this contract.');
    selectedViews.set(thread, viewId);
    const previous = host.registry.get(thread)?.card;
    if (!previous) return null;
    // Destroy the old capability before rendering a new, independently gated view.
    host.destroy(thread);
    const next = card(dialectName, thread, roomOf(thread));
    previous.replaceWith(next);
    return next;
  }

  function requestHistory() {
    if (requestedHistory) return;
    const request = deps.onMissing?.();
    if (request === false) return;
    requestedHistory = true;
    void Promise.resolve(request).then(sent => { if (sent === false) requestedHistory = false; }, () => { requestedHistory = false; });
  }

  async function reference(thread, pinned = false) {
    const d = dialectOf(thread);
    if (!d) throw new Error('Object definition is unavailable.');
    const roots = store.messages(thread).filter(m => m.verb === openerVerb(d));
    const root = roots.sort((a,b)=>a.cid.localeCompare(b.cid)).at(-1);
    if (!root) throw new Error('Object opener is unavailable.');
    const result = { object: niName(root.cid), room: roomOf(thread), thread };
    if (pinned) {
      result.frontier = store.frontier(thread).sort();
      closedMessages(store, thread, result.frontier);
      result.pin = await pinName(result.frontier);
      references.set(result.pin, result);
    }
    return result;
  }

  async function resolve(reference) {
    if (references.has(reference.object) && !reference.pin) reference = references.get(reference.object);
    const root = digestOfNi(reference.object);
    const thread = store.threads().find(thread => store.contains(thread, root));
    if (!thread) { requestHistory(); throw new Error('Object is not in loaded history. Retry after joining or after earlier history arrives.'); }
    const d = dialectOf(thread), opener = store.get(thread,root);
    if (!d || opener.verb !== openerVerb(d)) throw new Error('This name does not identify an object opener.');
    let messages = store.messages(thread);
    if (reference.pin) {
      if (await pinName(reference.frontier) !== reference.pin) throw new Error('Pin digest does not match its frontier.');
      try { messages = closedMessages(store, thread, reference.frontier); }
      catch (error) { requestHistory(); throw error; }
      if (!messages.some(m => m.cid === root)) throw new Error('Pin does not include the named opener.');
    }
    return { thread, room: roomOf(thread), state: project(d, messages), pinned: !!reference.pin };
  }

  function creationDialects() {
    return [...Object.entries(DIALECTS), ...learned].map(([id, d]) => {
      const verb = openerVerb(d);
      return { id, name: d.name || id, fields: d.shapes?.[verb]?.fields || {} };
    });
  }

  function createObject(name, fields, thread) {
    const d = getDialect(name), verb = d && openerVerb(d);
    if (!verb) throw new Error('This dialect has no object creation schema.');
    const checked = checkShape(d, verb, fields, []);
    if (!checked.ok) throw new Error(checked.reason);
    const kw = { ...fields };
    if (definitions.has(name)) kw['object-spec'] = definitions.get(name);
    if (d.recognize && !d.recognize({verb, kw}, [])) throw new Error('Invalid starting data.');
    return publish({ open: ({room, thread, from}) => buildMessage({ dialect: name, room, thread, from, verb, kw, causedBy: 'begin' }) }, fields, thread);
  }

  async function publish(object, fields, thread) {
    const from = me(), room = defaultRoom();
    let canonical = canonicalize(object.open({room, thread, from, fields}));
    if (prepare) canonical = await prepare(canonical);
    if (me() !== from) return false;
    return (await send(canonical)) !== false;
  }

  function isOpener(dialectName, verb) {
    const d = getDialect(dialectName);
    return !!d && openerVerb(d) === verb;
  }

  // Only dialects attached to accepted object messages belong in the room UI.
  const objectDialects = () => [...new Set(threadDialect.values())].map(name => ({ name: getDialect(name).name || name, digest: name, object: true }));
  return { store, broker, host, ingest, card, installView, selectView, publish, reference, resolve, requestHistory, reproject, objectDialects, creationDialects, createObject, isOpener, isObjectDialect, openerVerb: (n) => openerVerb(getDialect(n)) };
}

// minimal chrome CSS for the object card (host-drawn, REQ-021 indicator included).
export const HYPERMEDIA_CSS = `
.hm-object{max-width:560px;margin-top:5px;border:1px solid var(--line,#2a3039);border-radius:14px;background:var(--bg-card,#21262f);overflow:hidden;box-shadow:0 4px 16px var(--shadow-card,rgba(0,0,0,.08))}
.hm-obar{display:flex;align-items:center;gap:8px;padding:14px 18px;flex-wrap:wrap;background:var(--bg-surface,#1b1f26);border-bottom:1px solid var(--line,#2a3039);font-size:11px;color:var(--ink-faint,#6b7484)}
.hm-obar .hm-dn{font-family:ui-monospace,Menlo,monospace;color:var(--channel,#79ac74);font-weight:600;text-transform:lowercase;letter-spacing:.5px;font-size:12px}
.hm-obar .hm-thr{font-family:ui-monospace,Menlo,monospace;max-width:14ch;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.hm-obar button,.hm-obar select{font:inherit;min-height:32px;max-width:100%;border:1px solid var(--line,#39414b);border-radius:6px;padding:5px 8px;background:var(--bg-card,#21262f);color:var(--ink,#e7e9ee)}
.hm-obar button{cursor:pointer}
.hm-obar button:focus-visible,.hm-obar select:focus-visible{outline:2px solid var(--channel,#79ac74);outline-offset:2px}
.hm-obar .hm-tier{margin-left:auto;display:inline-flex;align-items:center;gap:5px;font-size:10px}
.hm-obar .hm-inert{color:var(--verify,#7e8c84)}
.hm-obar .hm-external{color:var(--danger,#f0808f)}
.hm-custom-gate{padding:24px;color:var(--ink,#e7e9ee)}
.hm-custom-head{display:flex;align-items:center;gap:14px}
.hm-custom-mark{display:grid;place-items:center;flex:none;width:44px;height:44px;border:1px solid var(--line,#39414b);border-radius:12px;background:var(--bg-surface,#1b1f26);color:var(--channel,#79ac74);font:600 17px ui-monospace,Menlo,monospace}
.hm-custom-head h3{margin:0 0 5px;font-size:17px;line-height:1.3;font-weight:650;letter-spacing:-.2px;color:var(--ink,#e7e9ee)}
.hm-custom-state{font-size:12px;line-height:1.4;color:var(--ink-dim,#9aa3b2)}
.hm-custom-gate .hm-custom-notice{margin:18px 0 0;max-width:55ch;font-size:13px;line-height:1.65;color:var(--ink-dim,#9aa3b2)}
.hm-custom-actions{display:flex;justify-content:flex-start;margin-top:20px}
.hm-custom-run{min-height:42px;padding:10px 16px;border:1px solid var(--channel,#79ac74);border-radius:9px;background:var(--channel,#79ac74);color:var(--on-accent,#10151b);font-family:inherit;font-size:13px;font-weight:600;line-height:1.4;cursor:pointer}
.hm-custom-run:hover{filter:brightness(1.08)}
.hm-custom-run:focus-visible{outline:2px solid var(--channel,#79ac74);outline-offset:3px}
.hm-custom-gate .hm-resource-permissions{min-width:0;margin:20px 0 0;padding:12px 14px;border:1px solid var(--line,#39414b);border-radius:10px;background:var(--bg-surface,#1b1f26)}
.hm-custom-gate .hm-resource-permissions legend{padding:0 5px;color:var(--ink-dim,#9aa3b2);font-size:12px;font-weight:600}
.hm-custom-gate .hm-resource-permissions label{display:flex;align-items:flex-start;gap:9px;padding:6px 0;margin:0;font-size:12px;line-height:1.5;overflow-wrap:anywhere}
.hm-custom-gate .hm-resource-permissions input{flex:none;width:16px;height:16px;margin-top:2px;accent-color:var(--channel,#79ac74)}
.hm-custom-gate .hm-resource-permissions p{margin:10px 0 0;font-size:12px;line-height:1.6;color:var(--ink-dim,#9aa3b2)}
@media(max-width:480px){.hm-custom-gate{padding:20px}.hm-custom-run{min-height:44px;width:100%}}
.hm-frame{display:block;width:100%;border:0;background:transparent}
.hm-csv{padding:11px 13px;background:#10151b}
.hm-csv-edit{width:100%;height:128px;background:#0b0e12;color:var(--ink,#e7e9ee);border:1px solid var(--line,#2a3039);border-radius:6px;font-family:ui-monospace,Menlo,monospace;font-size:12.5px;line-height:1.7;padding:9px 11px;resize:vertical}
.hm-plain,.hm-json{margin:0;padding:11px 13px;white-space:pre-wrap;font-family:ui-monospace,Menlo,monospace;font-size:12.5px;color:var(--ink,#e7e9ee)}
.hm-md{padding:4px 13px}
`;
