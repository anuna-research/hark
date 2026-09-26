// SPEC-085: data-only authoring and shared browser/agent interpretation.
import { last, latestPerSigner, latestPerKey, exists, histogram, project, count, events, setUnion, sum, counter, values, valuesPerKey, registerPerKey, observedSet, VIOLATION, UNKNOWN } from './projection.js';
import { checkShape } from './dialects.js';
import { buildMessage, makeBroker, keywordText, CORE_PERFORMATIVES } from './emit.js';
import { viewResources } from './resource-policy.js';
import { contentAddress } from './hash.js';
import { verifyCBCL, verifyShape, verifyProtocol, messageHash } from './cbcl-verifier.js';
import { normaliseCausedBy } from './store.js';

export const MAX_DEFINITION_BYTES = 16384;
export const isSDKDialect = name => /^object-[0-9a-f]{64}$/.test(name);
const bytes = text => new TextEncoder().encode(text).length;
const reserved = new Set(['from','thread','dialect','caused-by','audience','sig','key','signing-key','object-spec','constructor','prototype','__proto__']);
const identifier = value => typeof value === 'string' && /^[a-z][a-z0-9-]{0,47}$/.test(value) && !reserved.has(value);
function require(condition, message) { if (!condition) throw new Error(`Object definition: ${message}`); }
function record(value, keys) {
  require(value && typeof value === 'object' && !Array.isArray(value), 'expected record');
  require(Object.keys(value).every(key => keys.includes(key)), 'unknown record field');
  require(keys.every(key => Object.hasOwn(value, key)), 'missing record field');
}
function entries(value, max) {
  require(value && typeof value === 'object' && !Array.isArray(value), 'expected field map');
  const result = Object.entries(value);
  require(result.length > 0 && result.length <= max && result.every(([key]) => identifier(key)), 'invalid field map');
  return result;
}
function label(value) { require(typeof value === 'string' && bytes(value) <= 2048, 'invalid label'); }
// Replacement lists of registers are bound by the host broker:
// [{verb, replaces, key?, drop?}]. One replacement field serves one key field
// and one optional delete verb, so the broker binds it one way.
function registerRules(project) {
  const rules = new Map();
  const visit = expr => {
    if (!Array.isArray(expr)) return;
    const [op, verb, key, , replaces] = expr;
    if (op === 'histogram' || op === 'sum') return visit(verb);
    const rule = op === 'values' ? { verb, replaces: expr[3] }
      : op === 'valuesPerKey' || op === 'registerPerKey' ? { verb, replaces, key, ...(expr.length === 6 ? { drop: expr[5] } : {}) } : null;
    if (!rule) return;
    const id = `${rule.verb}\n${rule.replaces}`;
    require(!rules.has(id) || rules.get(id).key === rule.key, 'replacement field serves one key');
    require(!rules.has(id) || rules.get(id).drop === rule.drop, 'replacement field serves one delete verb');
    rules.set(id, rule);
  };
  Object.values(project || {}).forEach(visit);
  const result = [...rules.values()];
  // A delete verb deletes for exactly one register and never writes values.
  const drops = result.map(rule => rule.drop).filter(drop => drop !== undefined);
  require(new Set(drops).size === drops.length && !result.some(rule => drops.includes(rule.verb)),
    'delete verb serves one register');
  return result;
}
// Observed-set removals name the additions they cancel in a host-bound list
// field: [{add, remove, field, removes}]. The references ride data, not
// `:caused-by`, because CBCL accepts a multi-hash `:caused-by` only under an
// `(all ...)` fan-in of at least two verbs.
function removalRules(project) {
  return Object.values(project || {}).filter(expr => Array.isArray(expr) && expr[0] === 'observedSet')
    .map(([, add, remove, field, removes]) => ({ add, remove, field, removes }));
}
function hostBoundFields(project) {
  const bound = new Map();
  const bind = (verb, field) => {
    if (!bound.has(verb)) bound.set(verb, new Set());
    bound.get(verb).add(field);
  };
  for (const { verb, replaces, drop } of registerRules(project)) for (const name of drop === undefined ? [verb] : [verb, drop]) bind(name, replaces);
  for (const { remove, removes } of removalRules(project)) bind(remove, removes);
  return bound;
}

/** Validate semantics independently of any presentation. */
function validateContract(spec) {
  record(spec, ['version','kind','name','verbs','project']);
  require(spec.version === 2 && spec.kind === 'contract', 'unsupported contract');
  require(identifier(spec.name), 'invalid contract name');
  const verbs = entries(spec.verbs, 16);
  let roots = 0;
  for (const [verb, rule] of verbs) {
    require(!CORE_PERFORMATIVES.has(verb) && verb !== 'begin', 'reserved verb');
    record(rule, ['after','fields']);
    require(Array.isArray(rule.after) && rule.after.length > 0 && rule.after.length <= 16, 'invalid predecessors');
    require(rule.after.every(p => p === 'begin' || Object.hasOwn(spec.verbs, p)), 'unknown predecessor');
    if (rule.after.includes('begin')) { require(rule.after.length === 1, 'root must follow only begin'); roots++; }
    require(rule.fields && typeof rule.fields === 'object' && !Array.isArray(rule.fields), 'invalid fields');
    require(Object.keys(rule.fields).length <= 16, 'too many fields');
    for (const [field, type] of Object.entries(rule.fields)) {
      require(identifier(field), 'invalid field name');
      if (typeof type === 'object' && type !== null) { record(type, ['enumOf']); require(identifier(type.enumOf), 'invalid domain field'); }
      else require(['string','number','bool','list'].includes(type), 'invalid field type');
    }
  }
  require(roots === 1, 'exactly one opener required');
  const rootFields = verbs.find(([,rule]) => rule.after.includes('begin'))[1].fields;
  for (const [,rule] of verbs) for (const type of Object.values(rule.fields)) {
    if (typeof type === 'object') require(rootFields[type.enumOf] === 'list', 'domain must name opener list');
  }
  const projections = entries(spec.project, 32);
  const fieldType = (verb, field) => {
    require(Object.hasOwn(spec.verbs, verb), 'unknown projection verb');
    require(Object.hasOwn(spec.verbs[verb].fields, field), 'unknown projection field');
    const type = spec.verbs[verb].fields[field];
    return typeof type === 'object' ? 'string' : type;
  };
  function expression(expr, depth = 0) {
    require(depth <= 8 && Array.isArray(expr), 'invalid expression or depth');
    const [op, verb, field, value] = expr;
    if (op === 'histogram' || op === 'sum') {
      const bases = op === 'sum' ? ['events','latestPerSigner','latestPerKey','registerPerKey'] : ['latestPerSigner','latestPerKey','registerPerKey'];
      require(expr.length === 2 && Array.isArray(verb) && bases.includes(verb[0]), `${op} needs a multiplicity basis`);
      const type = expression(verb, depth + 1);
      if (op === 'sum') require(type === 'number', 'sum requires a numeric selector');
      return 'number';
    }
    if (op === 'counter' || op === 'observedSet') {
      require(expr.length === (op === 'counter' ? 4 : 5) && verb !== field, 'invalid paired projection');
      const first = fieldType(verb, value), second = fieldType(field, value);
      if (op === 'counter') require(first === 'number' && second === 'number', 'counter requires numeric fields');
      else {
        require(['string','number','bool'].includes(first) && first === second, 'observedSet requires matching scalar fields');
        const removes = expr[4];
        require(removes !== value && fieldType(field, removes) === 'list', 'observedSet requires a distinct list removal field');
      }
      return op === 'counter' ? 'number' : 'list';
    }
    if (op === 'valuesPerKey' || op === 'registerPerKey') {
      require([5, 6].includes(expr.length) && Object.hasOwn(spec.verbs, verb), 'expression arity');
      const [replaces, drop] = expr.slice(4);
      require(['string','number','bool'].includes(fieldType(verb, field)), 'map key must be scalar');
      require(fieldType(verb, replaces) === 'list' && new Set([field, value, replaces]).size === 3,
        'per-key register requires a distinct list replacement field');
      if (expr.length === 6) {
        // A deletion names only its key; the broker supplies what it replaces.
        require(drop !== verb && Object.hasOwn(spec.verbs, drop), 'unknown delete verb');
        const fields = spec.verbs[drop].fields;
        require(Object.keys(fields).length === 2 && fields[field] === spec.verbs[verb].fields[field]
          && fieldType(drop, replaces) === 'list', 'delete verb needs exactly the key and replacement fields');
      }
      const type = fieldType(verb, value);
      return op === 'registerPerKey' ? type : 'map';
    }
    require(['last','latestPerSigner','latestPerKey','exists','count','events','setUnion','values'].includes(op)
      && Object.hasOwn(spec.verbs, verb), 'unknown projection');
    const noField = op === 'exists' || op === 'count';
    require(expr.length === (noField ? 2 : ['latestPerKey','values'].includes(op) ? 4 : 3), 'expression arity');
    if (noField) return op === 'count' ? 'number' : 'bool';
    const type = fieldType(verb, field);
    if (op === 'latestPerKey') {
      require(['string','number','bool'].includes(type), 'map key must be scalar');
      return fieldType(verb, value);
    }
    if (op === 'setUnion') require(['string','number','bool'].includes(type), 'setUnion requires a scalar field');
    if (op === 'values') {
      require(value !== field && fieldType(verb, value) === 'list', 'values requires a distinct list replacement field');
      return 'list';
    }
    return type;
  }
  for (const [, expr] of projections) expression(expr);
  const replacements = new Set(), data = new Set();
  for (const { verb, replaces, drop } of registerRules(spec.project)) {
    replacements.add(`${verb}:${replaces}`);
    if (drop !== undefined) replacements.add(`${drop}:${replaces}`);
  }
  for (const { remove, removes } of removalRules(spec.project)) {
    // A removal field names additions; it cannot also carry a register's replacements.
    require(!replacements.has(`${remove}:${removes}`), 'host-bound field serves one projection kind');
  }
  const removalFields = new Set(removalRules(spec.project).map(({ remove, removes }) => `${remove}:${removes}`));
  const uses = ([op, verb, field, value]) => {
    if (op === 'histogram' || op === 'sum') return uses(verb);
    if (op === 'counter' || op === 'observedSet') { data.add(`${verb}:${value}`); data.add(`${field}:${value}`); return; }
    // Every data field precedes a register's trailing replacement field.
    for (const name of op === 'values' ? [field] : [field, value]) if (name !== undefined) data.add(`${verb}:${name}`);
  };
  for (const [, expr] of projections) uses(expr);
  require([...replacements, ...removalFields].every(field => !data.has(field)), 'replacement field cannot be projected as data');
}

/** Validate presentation against its contract's fields and actions. */
function validateView(spec) {
  if (Object.hasOwn(spec, 'layout')) {
    const layout = spec.layout;
    require(layout && typeof layout === 'object' && !Array.isArray(layout), 'invalid layout');
    require(Object.keys(layout).every(k => ['width','minHeight','maxHeight','aspectRatio','overflow'].includes(k)), 'unknown layout field');
    if (Object.hasOwn(layout, 'width')) require(['compact','standard','wide'].includes(layout.width), 'invalid layout width');
    for (const key of ['minHeight','maxHeight']) if (Object.hasOwn(layout, key)) require(Number.isInteger(layout[key]) && layout[key] >= 80 && layout[key] <= 1200, 'invalid layout height');
    require((layout.minHeight ?? 80) <= (layout.maxHeight ?? 1200), 'inverted layout heights');
    if (Object.hasOwn(layout, 'aspectRatio')) require(Number.isFinite(layout.aspectRatio) && layout.aspectRatio >= 0.25 && layout.aspectRatio <= 4, 'invalid aspect ratio');
    if (Object.hasOwn(layout, 'overflow')) require(layout.overflow === 'scroll', 'invalid overflow');
  }
  if (Object.hasOwn(spec, 'resources')) {
    viewResources(spec.resources);
    require(!Array.isArray(spec.view), 'resource requests require a custom view');
  }
  if (!Array.isArray(spec.view)) {
    require(spec.view && typeof spec.view === 'object', 'invalid custom view');
    const kind = Object.hasOwn(spec.view, 'html') ? 'html' : 'render';
    record(spec.view, [kind]);
    require(typeof spec.view[kind] === 'string' && bytes(spec.view[kind]) <= 12000, 'invalid custom view source');
    return;
  }
  require(spec.view.length > 0 && spec.view.length <= 32, 'invalid view');
  for (const component of spec.view) {
    if (component?.type === 'text') { record(component, ['type','text']); label(component.text); }
    else if (component?.type === 'value') {
      record(component, ['type','field','label']); label(component.label);
      require(Object.hasOwn(spec.project, component.field), 'unknown view field');
    } else {
      record(component, ['type','verb','label','fields']); label(component.label);
      require(component.type === 'form' && Object.hasOwn(spec.verbs, component.verb), 'unknown view component or action');
      require(!spec.verbs[component.verb].after.includes('begin'), 'view cannot open another object');
      const bound = hostBoundFields(spec.project).get(component.verb) || new Set();
      const fields = Object.fromEntries(Object.entries(spec.verbs[component.verb].fields).filter(([field]) => !bound.has(field)));
      record(component.fields, Object.keys(fields));
      Object.values(component.fields).forEach(label);
      require(!Object.values(fields).includes('list'), 'forms accept scalar fields only');
    }
  }
}

// Hash only the exact contract bytes. A bundle may suggest an independent view.
function parseDefinition(text) {
  require(typeof text === 'string' && bytes(text) <= MAX_DEFINITION_BYTES, 'definition exceeds 16 KiB');
  const wire = JSON.parse(text);
  let contractText, viewText;
  if (wire.kind === 'contract') contractText = text;
  else {
    record(wire, ['version', 'contract', ...(Object.hasOwn(wire, 'view') ? ['view'] : [])]);
    require(wire.version === 2, 'unsupported bundle version');
    contractText = wire.contract; viewText = wire.view;
  }
  require(typeof contractText === 'string' && bytes(contractText) <= MAX_DEFINITION_BYTES, 'invalid contract bytes');
  const contract = JSON.parse(contractText);
  validateContract(contract);
  let presentation = { view: Object.keys(contract.project || {}).map(field => ({type:'value', field, label:field})) };
  if (viewText !== undefined) {
    require(typeof viewText === 'string' && bytes(viewText) <= MAX_DEFINITION_BYTES, 'invalid view bytes');
    const view = JSON.parse(viewText);
    record(view, ['version','kind','contract','view', ...(Object.hasOwn(view, 'layout') ? ['layout'] : []), ...(Object.hasOwn(view, 'resources') ? ['resources'] : [])]);
    require(view.version === 2 && view.kind === 'view' && isSDKDialect(view.contract), 'invalid view contract');
    const { version, kind, contract: target, ...rest } = view;
    presentation = rest;
  }
  const spec = { name:contract.name, verbs:contract.verbs, project:contract.project, ...presentation };
  validateView(spec);
  return { spec, contractText, viewText };
}

/** Recognize a contract or contract/view bundle. */
export function recognizeDefinition(text) { return parseDefinition(text).spec; }

function compileExpression(expr) {
  const [op, ...args] = expr;
  if (op === 'histogram' || op === 'sum') return (op === 'sum' ? sum : histogram)(compileExpression(args[0]));
  return ({last, latestPerSigner, latestPerKey, exists, count, events, setUnion, counter, values, valuesPerKey, registerPerKey, observedSet})[op](...args);
}

const COMPONENT_STYLES = `
:root{color-scheme:light;--paper:#fcfbf7;--ink:#28382f;--muted:#68736b;--line:#dce1d8;--accent:#365e44}
*{box-sizing:border-box}body{margin:0;padding:24px;background:var(--paper);color:var(--ink);font:14px/1.55 system-ui,-apple-system,sans-serif}
#object-root{display:grid;gap:22px;max-width:720px;margin:auto}section{min-width:0}h3{font-size:20px;line-height:1.3;letter-spacing:-.4px;margin:0;font-weight:650}
.value-label{display:block;color:var(--muted);font-size:11px;font-weight:650;letter-spacing:.09em;text-transform:uppercase;margin-bottom:8px}
.value-body{overflow-wrap:anywhere;white-space:pre-wrap}.value-body>.scalar{font-size:18px;line-height:1.45;font-weight:550}.empty{color:var(--muted);font-size:13px;font-style:italic}
.state-list{list-style:none;padding:0;margin:0;border:1px solid var(--line);border-radius:10px;overflow:hidden}.state-row{padding:10px 12px;display:flex;align-items:baseline;justify-content:space-between;gap:16px}.state-row+.state-row{border-top:1px solid var(--line)}.state-key{min-width:0;overflow-wrap:anywhere}.state-value{min-width:0;text-align:right}.state-row.done .state-key{text-decoration:line-through;color:var(--muted)}
.bool{display:inline-flex;align-items:center;justify-content:center;border:1px solid var(--line);border-radius:50%;width:21px;height:21px;font-size:13px;flex:none;color:var(--muted)}.bool.yes{background:#e5eee2;border-color:#b8cdb4;color:var(--accent)}
form{display:grid;gap:14px;padding-top:20px;border-top:1px solid var(--line)}label{display:grid;gap:6px;font-size:12px;font-weight:600;color:var(--muted)}input{width:100%;min-width:0;min-height:42px;padding:9px 11px;border:1px solid #c5cec2;border-radius:8px;background:#fff;color:var(--ink);font:inherit;line-height:1.4}input:hover{border-color:#97ab96}input:focus-visible,button:focus-visible{outline:2px solid var(--accent);outline-offset:3px}label.checkbox{display:flex;align-items:center;gap:9px;color:var(--ink);min-height:32px}.item-toggle{width:100%;cursor:pointer;font-size:14px;font-weight:400}.item-toggle input{flex:none}input[type=checkbox]{width:18px;height:18px;min-height:0;margin:0;accent-color:var(--accent)}button{justify-self:start;min-height:42px;padding:10px 18px;border:1px solid var(--accent);border-radius:8px;background:var(--accent);color:#fff;font:600 13px/1.4 system-ui;cursor:pointer}button:hover{background:#294a35}button:active{transform:translateY(1px)}
button.item-remove{flex:none;min-height:32px;padding:4px 10px;background:none;border-color:var(--line);color:var(--muted);font-weight:500}button.item-remove:hover{background:#f0f2ec;color:var(--ink)}
@media(max-width:400px){body{padding:18px}#object-root{gap:18px}button{width:100%;min-height:44px}button.item-remove{width:auto;min-height:36px}.state-row{gap:10px}}
`;

/** The renderer is trusted code. Author data is never inserted as HTML/code. */
function renderComponents(spec) {
  const root = document.getElementById('object-root');
  let currentState = {};
  // An editable boolean map is unambiguous only when its projection and an
  // explicitly offered form identify the same two-field action.
  const checklists = new Map();
  for (const component of spec.view) {
    if (component.type !== 'value') continue;
    const [op, verb, key, flag, replaces, drop] = spec.project[component.field] || [];
    const fields = spec.verbs[verb]?.fields;
    // A register's replacement field is host-bound, so it is not an action field here.
    const own = Object.keys(fields || {}).filter(field => op !== 'registerPerKey' || field !== replaces);
    if ((op === 'latestPerKey' || op === 'registerPerKey') && fields?.[key] === 'string' && fields?.[flag] === 'bool'
        && own.length === 2 && spec.view.some(c => c.type === 'form' && c.verb === verb)) {
      // Offering the delete verb's form turns it into a Remove button per item.
      const remove = op === 'registerPerKey' && drop !== undefined && spec.view.some(c => c.type === 'form' && c.verb === drop) ? drop : null;
      checklists.set(component.field, { verb, key, flag, remove, field: component.field });
    }
  }
  const removals = new Set([...checklists.values()].map(c => c.remove).filter(Boolean));
  for (const component of spec.view) {
    if (component.type === 'form' && removals.has(component.verb)) continue;
    const section = document.createElement('section'); root.appendChild(section);
    if (component.type === 'text') { const h = document.createElement('h3'); h.textContent = component.text; section.appendChild(h); }
    else if (component.type === 'value') {
      const label = document.createElement('strong'); label.textContent = component.label; label.className = 'value-label';
      const value = document.createElement('div'); value.className = 'value-body'; value.dataset.field = component.field;
      section.append(label, value);
    } else {
      const form = document.createElement('form'), inputs = {};
      const checklist = [...checklists.values()].find(c => c.verb === component.verb);
      for (const [name, text] of Object.entries(component.fields)) {
        if (checklist && name === checklist.flag) continue;
        const label = document.createElement('label'); label.textContent = text;
        const input = document.createElement('input'); input.name = name;
        const type = spec.verbs[component.verb].fields[name];
        input.type = type === 'number' ? 'number' : type === 'bool' ? 'checkbox' : 'text';
        if (type === 'number') { input.step = 'any'; input.min = '-1000000000000'; input.max = '1000000000000'; }
        else if (type === 'string') input.maxLength = 2048;
        if (type === 'bool') { label.className = 'checkbox'; label.prepend(input); } else label.appendChild(input);
        input.required = type !== 'bool'; form.appendChild(label); inputs[name] = input;
      }
      const button = document.createElement('button'); button.textContent = checklist ? 'Add item' : component.label; button.type = 'button'; form.appendChild(button);
      const submit = event => {
        event.preventDefault(); if (!form.reportValidity()) return; const kw = {};
        for (const [name, input] of Object.entries(inputs)) kw[name] = input.type === 'checkbox' ? input.checked : input.type === 'number' ? Number(input.value) : input.value;
        if (checklist) {
          const items = currentState[checklist.field];
          kw[checklist.flag] = items && Object.hasOwn(items, kw[checklist.key]) ? items[kw[checklist.key]] : false;
        }
        window.emit(component.verb, kw);
      };
      button.addEventListener('click', submit);
      form.addEventListener('keydown', event => { if (event.key === 'Enter') submit(event); });
      section.appendChild(form);
    }
  }
  function display(value, depth = 0, checklist = null) {
    const node = document.createElement('span');
    if (value == null) { node.className = 'empty'; node.textContent = 'Nothing yet'; }
    else if (typeof value === 'boolean') {
      node.className = 'bool' + (value ? ' yes' : ''); node.textContent = value ? '✓' : '−';
      node.setAttribute('role', 'img'); node.setAttribute('aria-label', value ? 'Yes' : 'No');
    } else if (typeof value === 'object' && depth < 4) {
      const entries = Object.entries(value);
      if (!entries.length) { node.className = 'empty'; node.textContent = 'Nothing yet'; return node; }
      const list = document.createElement('ul'); list.className = 'state-list';
      for (const [key, item] of entries) {
        const row = document.createElement('li'); row.className = 'state-row' + (item === true ? ' done' : '');
        if (!Array.isArray(value)) { const label = document.createElement('span'); label.className = 'state-key'; label.textContent = key; row.append(label); }
        if (checklist && typeof item === 'boolean') {
          const label = document.createElement('label'); label.className = 'checkbox item-toggle';
          const input = document.createElement('input'); input.type = 'checkbox'; input.checked = item;
          input.setAttribute('aria-label', key);
          input.addEventListener('change', () => {
            window.emit(checklist.verb, { [checklist.key]: key, [checklist.flag]: input.checked });
            input.checked = item; // confirmed projection owns the visible state
          });
          label.append(input, row.firstChild); row.append(label);
          if (checklist.remove) {
            const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'item-remove';
            remove.textContent = 'Remove'; remove.setAttribute('aria-label', 'Remove ' + key);
            remove.addEventListener('click', () => window.emit(checklist.remove, { [checklist.key]: key }));
            row.append(remove);
          }
        } else {
          const content = display(item, depth + 1); content.classList.add('state-value'); row.append(content);
        }
        list.append(row);
      }
      return list;
    } else { node.className = 'scalar'; node.textContent = typeof value === 'object' ? JSON.stringify(value) : String(value); }
    return node;
  }
  window.onProjection = state => {
    currentState = state;
    for (const node of root.querySelectorAll('[data-field]')) {
      const value = state[node.dataset.field];
      node.replaceChildren(display(value, 0, checklists.get(node.dataset.field)));
    }
  };
}

export function compileDefinition(text) {
  const parts = parseDefinition(text);
  const { spec } = parts;
  const protocol = Object.fromEntries(Object.entries(spec.verbs).map(([verb, rule]) => [verb, rule.after]));
  const opener = Object.keys(protocol).find(verb => protocol[verb].includes('begin'));
  // cbcl-rs checks field presence and type against the verified (shape ...)
  // clauses. These JS rules cover only what CBCL shapes cannot express:
  // closed field sets, size bounds and domains drawn from the opener.
  const shapes = Object.fromEntries(Object.entries(spec.verbs).map(([verb, rule]) => [verb, { closed: true,
    fields: Object.fromEntries(Object.entries(rule.fields).map(([field, type]) => [field,
      { max: typeof type === 'object' || type === 'string' ? 2048 : type === 'list' ? 64 : type === 'number' ? 1e12 : undefined, ...(typeof type === 'object' ? {domain: valid => last(opener, type.enumOf)(valid)} : {}) }])) }]));
  const folds = Object.entries(spec.project).map(([field, expr]) => [field, compileExpression(expr)]);
  const observedSets = removalRules(spec.project);
  const counters = Object.values(spec.project).filter(expr => expr[0] === 'counter');
  const registers = registerRules(spec.project);
  // cbcl-rs verdicts are fixed per content address, except a pending protocol
  // verdict, which is re-asked once more history arrives.
  const shapeVerdicts = new Map(), causalVerdicts = new Map(), cbclTexts = new Map(), cbclHashes = new Map();
  const sender = handle => /^@[A-Za-z0-9_.-]+$/.test(handle) ? handle : JSON.stringify(String(handle));
  const references = causedBy => causedBy == null || causedBy === 'begin' ? 'begin'
    : Array.isArray(causedBy) ? `(${causedBy.map(ref => JSON.stringify(ref)).join(' ')})` : JSON.stringify(causedBy);
  // A message as CBCL text. The recipient is fixed: neither shape nor protocol reads it.
  const cbclText = (message, causedBy = references(message.causedBy)) =>
    `(${message.verb} @object ${keywordText(message.kw)} :caused-by ${causedBy} :thread ${JSON.stringify(message.thread)} :from ${sender(message.signer)})`;
  const cached = (cache, message, compute) => {
    if (!message.cid) return compute();
    if (!cache.has(message.cid)) cache.set(message.cid, compute());
    return cache.get(message.cid);
  };
  const shapeOk = message => dialect.cbcl !== undefined && cached(shapeVerdicts, message,
    () => verifyShape(dialect.cbcl, message.verb, `(${message.verb} @object ${keywordText(message.kw)})`).ok);
  const dialect = {
    observedSets, registers,
    external: !Array.isArray(spec.view),
    layout: spec.layout,
    resources: spec.resources,
    name: spec.name, protocol, shapes, grammar: Object.keys(protocol).filter(verb => verb !== opener),
    project: valid => Object.fromEntries(folds.map(([field, fold]) => [field, fold(valid)])),
    // The broker reports cbcl-rs's own blame for a rejected intent.
    verifyShape: (verb, kw) => dialect.cbcl === undefined ? { ok: false, reason: 'object definition is not CBCL-verified' }
      : verifyShape(dialect.cbcl, verb, `(${verb} @object ${keywordText(kw)})`),
    // cbcl-rs decides causal validity. Predecessors are named by CBCL's own
    // content address, so each one present in the thread is supplied as history
    // under messageHash; an absent one keeps its transport address and yields
    // Unknown until it arrives.
    verifyCausal: (message, byCid) => {
      if (dialect.cbcl === undefined) return VIOLATION;
      if (message.cid && causalVerdicts.has(message.cid)) return causalVerdicts.get(message.cid);
      const history = [];
      // Stored references may keep their wire spelling; the store's decoder names the predecessor.
      const cbclReference = ref => {
        const predecessor = byCid.get(normaliseCausedBy(ref)[0]);
        if (!predecessor) return ref;
        const text = cached(cbclTexts, predecessor, () => cbclText(predecessor));
        const hash = cached(cbclHashes, predecessor, () => messageHash(text));
        history.push([hash, text]);
        return hash;
      };
      const causedBy = message.causedBy == null || message.causedBy === 'begin' ? 'begin'
        : Array.isArray(message.causedBy) ? message.causedBy.map(cbclReference) : cbclReference(message.causedBy);
      const verdict = verifyProtocol(dialect.cbcl, message.thread, cbclText(message, references(causedBy)), history);
      if (message.cid && verdict !== UNKNOWN) causalVerdicts.set(message.cid, verdict);
      return verdict;
    },
    recognize: (message, valid) => {
      let kw = message.kw;
      if (!kw || typeof kw !== 'object' || Array.isArray(kw)) return false;
      if (Object.hasOwn(kw, 'object-spec')) {
        if (message.verb !== opener) return false;
        try {
          const other = parseDefinition(kw['object-spec']);
          if (other.contractText !== parts.contractText) return false;
          if (other.viewText && dialect.contractId && JSON.parse(other.viewText).contract !== dialect.contractId) return false;
        } catch { return false; }
        kw = { ...kw }; delete kw['object-spec'];
      }
      if (counters.some(([,inc,dec,field]) => (message.verb === inc || message.verb === dec) && kw[field] < 0)) return false;
      if (registers.some(({verb, replaces, drop}) => (message.verb === verb || message.verb === drop)
        && !kw[replaces]?.every?.(cid => typeof cid === 'string'))) return false;
      if (observedSets.some(({remove, removes}) => message.verb === remove
        && !kw[removes]?.every?.(cid => typeof cid === 'string'))) return false;
      return Object.hasOwn(protocol, message.verb) && checkShape(dialect, message.verb, kw, valid).ok
        && Object.values(kw).every(value => !Array.isArray(value) || value.every(x =>
          typeof x === 'boolean' || (typeof x === 'number' && Number.isFinite(x) && Math.abs(x) <= 1e12) || (typeof x === 'string' && bytes(x) <= 2048)))
        && shapeOk(message);
    },
    view: () => !Array.isArray(spec.view) ? customView(spec) : '<style>' + COMPONENT_STYLES + '</style><div id="object-root"></div><script>('
      + renderComponents.toString() + ')(' + JSON.stringify(spec).replace(/</g, '\\u003c') + ');</script>',
  };
  return { ...parts, dialect, opener };
}

// Compile the actual verbs, field types, and every causal edge. In particular,
// never drop cyclic edges merely to make R5 pass. The SDK validates projection
// and presentation separately; CBCL verifies the native dialect contract.
export async function compileVerifiedDefinition(text) {
  const compiled = compileDefinition(text);
  const name = 'object-' + await contentAddress(compiled.contractText);
  let viewId = null;
  if (compiled.viewText !== undefined) {
    require(JSON.parse(compiled.viewText).contract === name, 'view contract digest mismatch');
    viewId = 'view-' + await contentAddress(compiled.viewText);
  }
  compiled.dialect.contractId = name;
  const clauses = [];
  for (const [verb, rule] of Object.entries(compiled.spec.verbs)) {
    const fields = { ...rule.fields, ...(verb === compiled.opener ? { 'object-spec': 'string' } : {}) };
    const keys = Object.keys(fields);
    clauses.push(`  (extend ${verb} (${keys.join(' ')}) (tell @room${keys.map(key => ` :${key} ${key}`).join('')}))`);
    if (keys.length) clauses.push(`  (shape ${verb}${Object.entries(fields).map(([key, type]) => ` (require :${key} ${typeof type === 'object' ? 'string' : type})`).join('')})`);
  }
  clauses.push('  (protocol' + Object.entries(compiled.spec.verbs).map(([verb, rule]) =>
    ` (then ${rule.after.length === 1 ? rule.after[0] : `(any ${rule.after.join(' ')})`} ${verb})`).join('') + ')');
  const cbcl = `(define ${name} (cbcl) @object-sdk\n${clauses.join('\n')}\n)`;
  try { await verifyCBCL(cbcl); }
  catch (error) { throw new Error(`Object definition: CBCL verification failed: ${String(error?.message || error)}`); }
  // Only a verified contract may judge messages; until then the dialect rejects them.
  compiled.dialect.cbcl = cbcl;
  return { ...compiled, name, cbcl, viewId };
}

// This helper runs only inside the opted-in iframe. Escaped interpolations are
// text; event functions are attached through generated markers, never attributes.
export function html(strings, ...values) { return { strings: Array.from(strings), values }; }
function customRuntime(render) {
  const root = document.getElementById('object-root');
  window.onProjection = state => {
    const handlers = [];
    const escape = value => String(value).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
    function markup(value) {
      if (Array.isArray(value)) return value.map(markup).join('');
      if (value && Array.isArray(value.strings) && Array.isArray(value.values)) {
        return value.strings.reduce((out, part, i) => out + part + (i < value.values.length ? markup(value.values[i]) : ''), '');
      }
      if (typeof value === 'function') { const id = handlers.push(value) - 1; return '"object-handler-' + id + '"'; }
      return value == null ? '' : escape(value);
    }
    try {
      root.innerHTML = markup(render(state, {emit:window.emit}));
      for (const node of root.querySelectorAll('*')) for (const attr of Array.from(node.attributes)) {
        if (!attr.name.startsWith('on')) continue;
        const match = /^object-handler-(\d+)$/.exec(attr.value);
        if (match) { node.removeAttribute(attr.name); node.addEventListener(attr.name.slice(2), handlers[Number(match[1])]); }
      }
    } catch (error) { root.textContent = 'View error: ' + error.message; }
  };
}
function customView(spec) {
  if (Object.hasOwn(spec.view, 'html')) return spec.view.html;
  // The source is author code, deliberately executable ONLY after host opt-in.
  // Protect script end tags in author string literals at the HTML boundary.
  const source = '(' + spec.view.render.replace(/<\/script/gi, '<\\/script') + ')';
  return '<div id="object-root"></div><script>const html=' + html.toString()
    + ';(' + customRuntime.toString() + ')(' + source + ');</script>';
}

export const enumOf = field => ({enumOf:field});

export const c = Object.freeze({
  setUnion: (verb, field) => ['setUnion', verb, field],
  count: verb => ['count', verb],
  events: (verb, field) => ['events', verb, field],
  sum: selector => ['sum', selector],
  counter: (incVerb, decVerb, field) => ['counter', incVerb, decVerb, field],
  values: (verb, field, replaces) => ['values', verb, field, replaces],
  observedSet: (addVerb, removeVerb, field, removes) => ['observedSet', addVerb, removeVerb, field, removes],
  last: (verb, field) => ['last', verb, field],
  latestPerSigner: (verb, field) => ['latestPerSigner', verb, field],
  latestPerKey: (verb, key, field) => ['latestPerKey', verb, key, field],
  valuesPerKey: (verb, key, field, replaces, deleteVerb) =>
    ['valuesPerKey', verb, key, field, replaces, ...(deleteVerb === undefined ? [] : [deleteVerb])],
  registerPerKey: (verb, key, field, replaces, deleteVerb) =>
    ['registerPerKey', verb, key, field, replaces, ...(deleteVerb === undefined ? [] : [deleteVerb])],
  exists: verb => ['exists', verb],
  histogram: selector => ['histogram', selector],
});

/** Normalize authoring sugar without changing imported artifact bytes. */
function normalizeAuthoring(definition) {
  const normalized = { ...definition };
  if (Object.hasOwn(normalized, 'dialect')) { normalized.name = normalized.dialect; delete normalized.dialect; }
  normalized.version ??= 2;
  normalized.verbs = Object.fromEntries(Object.entries(normalized.verbs || {}).map(([verb, rule]) => {
    const next = { ...rule };
    if (Object.hasOwn(next, 'causedBy')) { next.after = Array.isArray(next.causedBy) ? next.causedBy : [next.causedBy]; delete next.causedBy; }
    next.fields = Object.fromEntries(Object.entries(next.fields || {}).map(([key, value]) => [key, Array.isArray(value) && value.length === 1 && value[0] === 'string' ? 'list' : value]));
    return [verb, next];
  }));
  if (typeof normalized.view === 'function') normalized.view = { render: normalized.view.toString() };
  return normalized;
}

/** Import exact artifact bytes without changing their content addresses. */
export async function importObject(serialized) {
  const { dialect, opener, name, cbcl, contractText, viewText, viewId } = await compileVerifiedDefinition(serialized);
  return Object.freeze({
    name, serialized, cbcl, contract: contractText, view: viewText, viewId,
    read: messages => project(dialect, messages),
    open({ room, thread, from, fields }) {
      require(dialect.recognize({ verb: opener, kw: { ...fields, 'object-spec': serialized } }, []), 'invalid opener fields');
      return buildMessage({ dialect: name, room, thread, from, verb: opener, causedBy: 'begin', kw: { ...fields, 'object-spec': serialized } });
    },
    agent(host) {
      const broker = makeBroker({ ...host, getDialect: key => key === name ? dialect : null });
      return { read: thread => project(dialect, host.store.messages(thread)), act: (thread, verb, fields) => broker.applyIntent(thread, name, verb, fields) };
    },
  });
}


/** Publish a headless contract. Presentation is deliberately absent. */
export async function defineContract(definition) {
  const normalized = normalizeAuthoring(definition);
  require(!Object.hasOwn(normalized, 'view') && !Object.hasOwn(normalized, 'layout') && !Object.hasOwn(normalized, 'resources'), 'contract cannot contain presentation');
  record(normalized, ['version','name','verbs','project']);
  require(normalized.version === 2, 'contracts require version 2');
  return importObject(JSON.stringify({version:2, kind:'contract', name:normalized.name, verbs:normalized.verbs, project:normalized.project}));
}

/** Bind presentation to the exact verified contract; does not execute it. */
export async function defineView({ contract, ...presentation }) {
  record(presentation, ['view', ...(Object.hasOwn(presentation, 'layout') ? ['layout'] : []), ...(Object.hasOwn(presentation, 'resources') ? ['resources'] : [])]);
  const contractText = typeof contract === 'string' ? contract : contract?.contract || contract?.serialized;
  const compiled = await compileVerifiedDefinition(contractText);
  if (typeof presentation.view === 'function') presentation.view = { render: presentation.view.toString() };
  const serialized = JSON.stringify({version:2, kind:'view', contract:compiled.name, ...presentation});
  const checked = await compileVerifiedDefinition(JSON.stringify({version:2, contract:compiled.contractText, view:serialized}));
  return Object.freeze({ id:checked.viewId, contract:compiled.name, serialized });
}

/** Convenience authoring for separate contract and view artifacts. */
export async function defineObject(definition) {
  if (definition.contract) {
    record(definition, ['contract','view']);
    const contract = typeof definition.contract === 'string' ? definition.contract : definition.contract.contract || definition.contract.serialized;
    const view = typeof definition.view === 'string' ? definition.view : definition.view?.serialized;
    require(view !== undefined, 'expected a serialized view artifact');
    return importObject(JSON.stringify({version:2, contract, view}));
  }
  const normalized = normalizeAuthoring(definition);
  const { view, layout, resources, ...rules } = normalized;
  const contract = await defineContract(rules);
  if (view === undefined) {
    require(layout === undefined && resources === undefined, 'presentation requires a view');
    return contract;
  }
  const artifact = await defineView({contract, view, ...(layout !== undefined ? {layout} : {}), ...(resources !== undefined ? {resources} : {})});
  return defineObject({contract, view:artifact});
}
