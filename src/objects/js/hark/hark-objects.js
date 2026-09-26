// hark glue (SPEC-086 Stage B): the browser's object controller, headless.
//
// One controller per agent handle, built from the VENDORED `controller.js` with
// the same dependencies the browser injects — identity, room, send, canonicalise,
// history-on-missing — except that every one of them is a host function backed by
// hark's Rust side: signing and transport through the agent's own hub connection,
// canonical text and CBCL verdicts through cbcl-rs linked natively.
//
// `ingest` mirrors `renderObject` in app.js line for line: the same reader
// (`cbcl-read.js`), the same field decoding (`normalizeValue`), the same record.
// That is the parity argument — hark runs the browser's code, it does not port it.
import { createHypermediaController, normalizeValue } from './controller.js';
import { parseSexpr, kwargs, asText } from './cbcl-read.js';
import { isSDKDialect, importObject, defineObject } from './object-sdk.js';

const agents = new Map();

function createAgent(handle, me, room) {
  const C = createHypermediaController({
    me: () => me,
    defaultRoom: () => room,
    send: canonical => globalThis.__hark.send(handle, canonical),
    canonicalize: text => globalThis.__hark.parseMessage(text),
    onMissing: () => globalThis.__hark.history(handle, room),
    report: info => globalThis.__hark.log('debug', JSON.stringify(info)),
  });
  const threadDialect = new Map();
  return { C, me, room, threadDialect };
}

function agent(handle) {
  const a = agents.get(handle);
  if (!a) throw new Error('agent has no object controller');
  return a;
}

/** Build the agent's controller on first use. Returns "created" when this
 *  call built it (the host then replays the agent's journal into it) and
 *  "existing" otherwise. */
export async function ensure(handle, me, room) {
  if (agents.has(handle)) return 'existing';
  agents.set(handle, createAgent(handle, me, room));
  return 'created';
}

/** Test hook: a script that never yields, so the host's interrupt deadline
 *  can be exercised. Never called by production code. */
export async function __spin() {
  for (;;) {}
}

export async function close(handle) {
  agents.delete(handle);
  return null;
}

/** Ingest one delivered object message. `signer` is the record's attested signer. */
export async function ingest(handle, text, signer, room) {
  const { C, threadDialect } = agent(handle);
  const list = parseSexpr(text);
  if (!Array.isArray(list) || asText(list[0]) !== 'lang') return null;
  const dialect = asText(list[1]);
  const inner = Array.isArray(list[2]) ? list[2] : null;
  if (!inner || !(C.isObjectDialect(dialect) || isSDKDialect(dialect))) return null;
  const verb = asText(inner[0]);
  const kw = kwargs(inner);
  const thread = asText(kw.thread), from = signer || asText(kw.from);
  if (!thread || !from || kw['caused-by'] === undefined) return null;
  const fields = {};
  for (const [key, value] of Object.entries(kw)) {
    if (['thread', 'from', 'caused-by', 'dialect'].includes(key)) continue;
    fields[key] = normalizeValue(value, asText);
  }
  const result = await C.ingest({ dialect, verb, kw: fields, thread, from, room, canonical: text, causedBy: normalizeValue(kw['caused-by'], asText) });
  if (result) threadDialect.set(thread, dialect);
  return result ? JSON.stringify(result) : null;
}

/** The projected state of one object thread, or null when it is not in loaded history. */
export async function read(handle, thread) {
  const { C, threadDialect } = agent(handle);
  const dialect = threadDialect.get(thread);
  if (!dialect) return null;
  return JSON.stringify({ thread, dialect, state: C.reproject(thread) });
}

export async function list(handle) {
  const { threadDialect } = agent(handle);
  return JSON.stringify([...threadDialect].map(([thread, dialect]) => ({ thread, dialect })));
}

/** Act on an object through the vendored broker: it binds provenance, picks the
 *  predecessor, fills register/removal fields, verifies with cbcl-rs, and sends. */
export async function act(handle, thread, verb, fieldsJson) {
  const { C, threadDialect } = agent(handle);
  const dialect = threadDialect.get(thread);
  if (!dialect) return JSON.stringify({ ok: false, reason: 'object is not in loaded history' });
  const result = await C.broker.applyIntent(thread, dialect, verb, JSON.parse(fieldsJson));
  return JSON.stringify(result);
}

/** Compile a definition exactly as the browser's import dialog would.
 *
 *  Three input forms: the serialised artifact text (a contract, or a
 *  `{version, contract, view}` bundle), the same as a JSON object, or an
 *  authoring definition `{name, verbs, project, view?, layout?, resources?}`,
 *  which `defineObject` turns into a contract artifact plus a view artifact
 *  bound to the contract's digest. In every case cbcl-rs verifies the native
 *  dialect the contract compiles to. */
async function compile(definition) {
  if (typeof definition === 'string') return importObject(definition);
  const isArtifact = definition.kind === 'contract'
    || (definition.version === 2 && typeof definition.contract === 'string' && !definition.verbs);
  return isArtifact ? importObject(JSON.stringify(definition)) : defineObject(definition);
}

function describe(object) {
  const contract = JSON.parse(object.contract);
  const verbs = Object.fromEntries(Object.entries(contract.verbs).map(([verb, rule]) => [verb, { after: rule.after, fields: rule.fields }]));
  const opener = Object.keys(verbs).find(verb => verbs[verb].after.includes('begin')) || null;
  return { dialect: object.name, opener, verbs, project: contract.project, view: object.viewId || null,
    serialized: object.serialized, cbcl: object.cbcl };
}

/** Validate a definition without sending anything: the dialect digest it
 *  would get, its verbs and projections, the view digest, the serialised
 *  bundle an opener would carry, and the native CBCL dialect cbcl-rs
 *  verified. Throws the SDK's own error for an invalid definition. */
export async function check(definitionJson) {
  const object = await compile(JSON.parse(definitionJson));
  return JSON.stringify(describe(object));
}

/** Create an object: verify the definition, build its opener with the contract
 *  (and view) embedded, send it on the agent's connection, and learn it locally
 *  so the next `act` need not wait for the hub's echo (which deduplicates by cid). */
export async function open(handle, definitionJson, thread, fieldsJson) {
  const a = agent(handle);
  const object = await compile(JSON.parse(definitionJson));
  const fields = JSON.parse(fieldsJson);
  const canonical = globalThis.__hark.parseMessage(object.open({ room: a.room, thread, from: a.me, fields }));
  if (globalThis.__hark.send(handle, canonical) === false) return JSON.stringify({ ok: false, reason: 'send refused' });
  await ingest(handle, canonical, a.me, a.room);
  return JSON.stringify({ ok: true, thread, dialect: object.name, view: object.viewId || null,
    cid: globalThis.__hark.sha256(canonical), message: canonical });
}
