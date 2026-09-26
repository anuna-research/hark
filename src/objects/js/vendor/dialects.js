// SPEC-019 ADR-009 / ADR-011 — the per-dialect object registry (client side).
//
// In the full design the emit-grammar, (protocol), (shape)+closed+size, and the
// declarative projection vocabulary all ride the content-addressed, R4-signed
// .cbcl dialect definition learned by digest on join (ADR-009/011). Those are
// NET-NEW cbcl-rs additions (OQ-003/008) not yet on the wire. Until they land,
// the client carries a built-in registry of the well-known object dialects
// (mirroring the sandboxed-views oracle): poll / geo / stay / budget / task.
// Same shape as a learned dialect, so swapping the source later is mechanical.

import {
  latestPerSigner, latestPerKey, last, exists, histogram, authorityLast,
} from './projection.js';

// ---- shape + closed-shape + size + value-domain (REQ-023, REQ-026) ---------
// A field rule: { type, max, domain }. `type` is checked (reused shape, REQ-023a);
// `closed` rejects undeclared fields (REQ-023b, net-new — cbcl-rs (shape) is open);
// `max` bounds byte/element count (REQ-023c, net-new); `domain` validates the
// field VALUE against an enumerated set derived from an earlier authenticated
// message (REQ-026), e.g. a vote :date must be one of the propose's options.

const TYPE_OK = {
  string: (v) => typeof v === 'string',
  number: (v) => typeof v === 'number' && Number.isFinite(v),
  bool: (v) => typeof v === 'boolean',
  list: (v) => Array.isArray(v),
  object: (v) => v && typeof v === 'object' && !Array.isArray(v),
};

function fieldSize(v) {
  if (typeof v === 'string') return new TextEncoder().encode(v).length;
  if (typeof v === 'number') return Math.abs(v);
  if (Array.isArray(v)) return v.length;
  if (v && typeof v === 'object') return Object.keys(v).length;
  return 0;
}

/**
 * Validate a constructed message's keyword fields against a verb's shape.
 * Returns { ok:true } or { ok:false, reason }. `validMsgs` is the current Valid
 * set, used to evaluate value-domains (REQ-026).
 */
export function checkShape(dialect, verb, kw, validMsgs) {
  const shape = dialect.shapes && dialect.shapes[verb];
  if (!shape) return { ok: true }; // unconstrained verb
  const fields = shape.fields || {};
  // required present + typed + sized + in-domain
  for (const [name, rule] of Object.entries(fields)) {
    const present = Object.prototype.hasOwnProperty.call(kw, name);
    if (rule.required && !present) return { ok: false, reason: `missing required field :${name}` };
    if (!present) continue;
    const v = kw[name];
    if (rule.type && !TYPE_OK[rule.type](v)) {
      return { ok: false, reason: `field :${name} is not a ${rule.type}` };
    }
    if (rule.max != null && fieldSize(v) > rule.max) {
      return { ok: false, reason: `field :${name} exceeds size bound ${rule.max}` };
    }
    if (rule.domain) {
      const allowed = rule.domain(validMsgs);
      if (allowed && !allowed.includes(v)) {
        return { ok: false, reason: `field :${name} value ${JSON.stringify(v)} outside declared domain` };
      }
    }
  }
  // closed shape (REQ-023b): reject any undeclared field.
  if (shape.closed) {
    for (const name of Object.keys(kw)) {
      if (!Object.hasOwn(fields, name)) return { ok: false, reason: `undeclared field :${name} (closed shape)` };
    }
  }
  return { ok: true };
}

function opener(messages, verb) {
  return messages.filter(m => m.verb === verb).reduce((best, m) => !best || m.cid > best.cid ? m : best, null);
}

// ---- value-domain helpers --------------------------------------------------
function optionsFromOpener(validMsgs, openerVerb, field) {
  const root = opener(validMsgs, openerVerb);
  const opts = root && root.kw[field];
  return Array.isArray(opts) ? opts : null;
}

// the valid stop-ids for an ar-crawl = the ids declared in its `crawl` opener.
// stops are [id, label] pairs (or bare ids); the value-domain (REQ-026) binds
// arrive/vote-next to exactly those ids.
function crawlStopIds(validMsgs) {
  const c = opener(validMsgs, 'crawl');
  const stops = c && c.kw.stops;
  return Array.isArray(stops) ? stops.map((s) => (Array.isArray(s) ? s[0] : s)) : null;
}

// ---- the dialect definitions ----------------------------------------------
// Each: grammar (REQ-011), protocol (REQ-008), shapes (REQ-023/026), projection
// (CON-003), declared aggregation basis (REQ-029), and a view body (the inner
// <body> HTML the sandbox host renders; the runtime + CSP are added by the host).

export const DIALECTS = {
  poll: {
    name: 'poll',
    grammar: ['vote'],
    // `vote` self-chains (preds include `vote`) so a member can CHANGE their vote:
    // a re-vote is caused-by the member's previous vote, gaining causal depth, so
    // latest-per-signer supersedes within their own chain (REQ-024). Without the
    // self-pred, re-votes are concurrent and resolved by content hash (no recency),
    // so changing your vote has no visible effect.
    protocol: { propose: ['begin'], vote: ['propose', 'vote'] },
    shapes: {
      propose: { closed: true, fields: {
        q: { required: true, type: 'string', max: 280 },
        options: { required: true, type: 'list', max: 24 },
      } },
      vote: { closed: true, fields: {
        date: { required: true, type: 'string', max: 64,
          domain: (v) => optionsFromOpener(v, 'propose', 'options') },
      } },
    },
    aggregations: [{ field: 'tally', basis: 'latest-per-signer' }],
    project: (valid) => ({
      perSigner: latestPerSigner('vote', 'date')(valid),
      tally: histogram(latestPerSigner('vote', 'date'))(valid),
      options: optionsFromOpener(valid, 'propose', 'options') || [],
      q: (opener(valid, 'propose') || { kw: {} }).kw.q || '',
    }),
    view: pollView,
  },

  geo: {
    name: 'geo',
    grammar: ['pin-vote'],
    // self-chains so a member can change their pin (latest-per-signer, REQ-024).
    protocol: { map: ['begin'], 'pin-vote': ['map', 'pin-vote'] },
    shapes: {
      map: { closed: true, fields: { pins: { required: true, type: 'list', max: 64 } } },
      'pin-vote': { closed: true, fields: {
        place: { required: true, type: 'string', max: 64,
          domain: (v) => {
            const m = opener(v, 'map');
            const pins = m && m.kw.pins;
            return Array.isArray(pins) ? pins.map((p) => (Array.isArray(p) ? p[0] : p)) : null;
          } },
      } },
    },
    aggregations: [{ field: 'tally', basis: 'latest-per-signer' }],
    project: (valid) => ({
      pins: (opener(valid, 'map') || {kw:{}}).kw.pins || [],
      perSigner: latestPerSigner('pin-vote', 'place')(valid),
      tally: histogram(latestPerSigner('pin-vote', 'place'))(valid),
    }),
    view: geoView,
  },

  stay: {
    name: 'stay',
    grammar: ['pick'],
    // self-chains so a member can change their pick (latest-per-signer, REQ-024).
    protocol: { compare: ['begin'], pick: ['compare', 'pick'] },
    shapes: {
      compare: { closed: true, fields: { items: { required: true, type: 'list', max: 32 } } },
      pick: { closed: true, fields: {
        id: { required: true, type: 'string', max: 64,
          domain: (v) => {
            const c = opener(v, 'compare');
            const items = c && c.kw.items;
            return Array.isArray(items) ? items.map((it) => (Array.isArray(it) ? it[0] : it)) : null;
          } },
      } },
    },
    aggregations: [{ field: 'tally', basis: 'latest-per-signer' }],
    project: (valid) => ({
      items: (opener(valid, 'compare') || {kw:{}}).kw.items || [],
      perSigner: latestPerSigner('pick', 'id')(valid),
      tally: histogram(latestPerSigner('pick', 'id'))(valid),
    }),
    view: stayView,
  },

  budget: {
    name: 'budget',
    grammar: ['edit'],
    protocol: { table: ['begin'], edit: ['table', 'edit'] },
    shapes: {
      table: { closed: true, fields: { rows: { required: true, type: 'object', max: 64 } } },
      edit: { closed: true, fields: {
        row: { required: true, type: 'string', max: 64 },
        amount: { required: true, type: 'number', max: 1e12 },
      } },
    },
    aggregations: [{ field: 'cells', basis: 'latest-per-key' }],
    project: (valid) => {
      const seed = (opener(valid, 'table') || { kw: {} }).kw.rows || {};
      const edited = latestPerKey('edit', 'row', 'amount')(valid);
      const cells = { ...seed, ...edited };
      const total = Object.values(cells).reduce((a, b) => a + (+b || 0), 0);
      return { cells, total };
    },
    view: budgetView,
  },

  'ar-crawl': {
    name: 'ar-crawl',
    grammar: ['arrive', 'vote-next'],
    // arrive/vote-next self-chain: a member moves through stops, each act caused-by
    // their previous one, so re-acts supersede by causal depth within their own
    // chain (REQ-024) rather than racing concurrently on content hash.
    protocol: { crawl: ['begin'], arrive: ['crawl', 'arrive'], 'vote-next': ['crawl', 'vote-next'] },
    shapes: {
      crawl: { closed: true, fields: {
        stops: { required: true, type: 'list', max: 32 },
        title: { required: false, type: 'string', max: 120 },
      } },
      arrive: { closed: true, fields: {
        stop: { required: true, type: 'string', max: 64, domain: (v) => crawlStopIds(v) },
      } },
      'vote-next': { closed: true, fields: {
        stop: { required: true, type: 'string', max: 64, domain: (v) => crawlStopIds(v) },
      } },
    },
    // both aggregations fold a latest-per-signer selector: one contribution per
    // member (your current location; your single next-stop vote) — REQ-029.
    aggregations: [
      { field: 'presence', basis: 'latest-per-signer' },
      { field: 'nextTally', basis: 'latest-per-signer' },
    ],
    project: (valid) => {
      const root = opener(valid, 'crawl');
      const stops = (root && root.kw.stops) || [];
      return {
        stops,
        title: (root && root.kw.title) || 'AR crawl',
        here: latestPerSigner('arrive', 'stop')(valid),                 // signer -> stop
        presence: histogram(latestPerSigner('arrive', 'stop'))(valid),  // stop -> # here now
        nextTally: histogram(latestPerSigner('vote-next', 'stop'))(valid), // stop -> # next-votes
      };
    },
    view: arCrawlView,
  },

  task: {
    name: 'task',
    grammar: ['claim', 'complete', 'grant'],
    // `grant` self-chains (preds include `grant`) so the authority can RE-ASSIGN: a
    // later grant is caused-by the authority's previous grant, giving it greater
    // causal depth, and authorityLast supersedes within the authority's own chain
    // (REQ-024) — convergent, still authority-only (REQ-031).
    protocol: { open: ['begin'], claim: ['open'], grant: ['open', 'claim', 'grant'], complete: ['claim', 'open', 'grant'] },
    shapes: {
      open: { closed: true, fields: {
        title: { required: true, type: 'string', max: 200 },
        authority: { required: false, type: 'string', max: 64 },
      } },
      claim: { closed: true, fields: {} },
      grant: { closed: true, fields: { who: { required: true, type: 'string', max: 64 } } },
      complete: { closed: true, fields: {} },
    },
    aggregations: [],
    project: (valid) => {
      // REQ-031: assignee read from the opener-named AUTHORITY's grant only — NOT
      // last(claim), which would be a forgeable contested race (REQ-030).
      const root = opener(valid, 'open');
      const authority = (root && root.kw.authority) || (root && root.signer) || null;
      const assignee = authority ? authorityLast('grant', 'who', authority)(valid) : null;
      return { title: (root && root.kw.title) || '', assignee, done: exists('complete')(valid), authority };
    },
    view: taskView,
  },
};

// Apply the same shape/domain rules to peer messages before projection.
for (const dialect of Object.values(DIALECTS)) {
  dialect.recognize = (message, valid) => Object.hasOwn(dialect.protocol, message.verb)
    && checkShape(dialect, message.verb, message.kw, valid).ok;
}

/**
 * Validate a dialect at load (ADR-011 / REQ-029): a counting aggregation
 * (sum/count/histogram) MUST declare a multiplicity basis (latest-* output or
 * distinct-messages); a bare counting aggregation with no basis is REJECTED at
 * load — never partially projected. set-union is exempt (multiplicity-invariant).
 * Returns { ok:true } or { ok:false, reason }.
 */
export function validateDialect(dialect) {
  if (!dialect || typeof dialect.project !== 'function') {
    return { ok: false, reason: 'dialect has no projection' };
  }
  const BASES = new Set(['latest-per-signer', 'latest-per-key', 'distinct-messages']);
  for (const agg of dialect.aggregations || []) {
    if (!BASES.has(agg.basis)) {
      return { ok: false, reason: `aggregation ${agg.field} declares no valid multiplicity basis (REQ-029)` };
    }
  }
  return { ok: true };
}

export function getDialect(name) {
  return Object.hasOwn(DIALECTS, name) ? DIALECTS[name] : null;
}

export function isObjectDialect(name) {
  return getDialect(name) !== null;
}

// ---- view bodies -----------------------------------------------------------
// The inner <body> HTML for the sandboxed iframe. The host (sandbox.js) wraps
// this in a full document with the host-imposed CSP + the MessagePort runtime.
// Each view: renders from `state` pushed over the port; `emit(verb, kw)` posts
// an intent over the port; never touches a key, never reaches the network.

function VIEW_CSS() {
  return `:root{--c:#79ac74;--dim:#9aa3b2;--paper:#21262f;--ink:#e7e9ee;--surface:#1b1f26;--line:#39414b}@media(prefers-color-scheme:light){:root{--c:#365e44;--dim:#6b7368;--paper:#fcfbf7;--ink:#29332b;--surface:#f1f2eb;--line:#dce1d8}}*{box-sizing:border-box}
body{margin:0;padding:24px;font:14px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:var(--ink);background:var(--paper)}
h{display:block;font-size:20px;font-weight:650;line-height:1.35;letter-spacing:-.4px;color:var(--ink);margin-bottom:20px;overflow-wrap:anywhere}
button{font:inherit;font-size:13px;cursor:pointer;background:var(--surface);color:var(--ink);border:1px solid var(--line);border-radius:9px;padding:10px 16px;min-height:44px;overflow-wrap:anywhere}
button:hover{border-color:var(--c)}button:focus-visible{outline:2px solid var(--c);outline-offset:3px}
.hint{color:var(--dim);font-size:12px;margin:20px 0 0;padding-top:14px;border-top:1px solid var(--line)}
code{font-family:ui-monospace,Menlo,monospace;color:#5cc2c2;font-size:11px}`;
}

// Values from canonical messages remain text even inside the isolated view.
const VIEW_ESCAPE = `function esc(value){return String(value==null?'':value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}`;

function pollView() {
  return `<style>${VIEW_CSS()}
    .opt{display:grid;grid-template-columns:minmax(0,1fr) minmax(32px,90px) 24px;align-items:center;gap:12px;margin:10px 0}.opt button{text-align:left;min-width:0}
    .bar{flex:1;height:8px;border-radius:5px;background:var(--line);overflow:hidden}.bar i{display:block;height:100%;background:var(--c)}
    .n{width:22px;text-align:right;color:var(--dim);font-variant-numeric:tabular-nums}</style>
    <h id="q">poll</h><div id="opts"></div>
    <p class="hint">Choose an option to vote. You can change your vote anytime.</p>
    <script>
      ${VIEW_ESCAPE}
      let S={tally:{},options:[],perSigner:{},q:''};
      function draw(){
        document.getElementById('q').textContent=S.q||'poll';
        const opts=S.options||[],t=S.tally||{},max=Math.max(1,...Object.values(t),1);
        document.getElementById('opts').innerHTML=opts.map(o=>
          '<div class=opt><button data-o="'+esc(o)+'">'+esc(o)+'</button>'
          +'<div class=bar><i style="width:'+(100*(t[o]||0)/max)+'%"></i></div><span class=n>'+(t[o]||0)+'</span></div>').join('');
        document.querySelectorAll('#opts button').forEach(b=>b.onclick=()=>emit('vote',{date:b.dataset.o}));
      }
      window.onProjection=(s)=>{S=s||S;draw();}; draw();
    <\/script>`;
}

function geoView() {
  return `<style>${VIEW_CSS()}.leg{display:flex;gap:14px;margin-top:8px;flex-wrap:wrap}
    .leg span{display:inline-flex;align-items:center;gap:6px;color:var(--dim);font-size:12px}.sw{width:9px;height:9px;border-radius:50%}
    .pins{display:flex;gap:8px;flex-wrap:wrap}.pins button{min-width:84px}</style>
    <h>neighbourhood</h><div class="pins" id="pins"></div><div class="leg" id="leg"></div>
    <p class="hint">tapping a pin emits a <code>pin-vote</code>; the client scopes it to this map's thread.</p>
    <script>
      ${VIEW_ESCAPE}
      let S={tally:{},pins:[]};
      function draw(){
        const t=S.tally||{};
        document.getElementById('pins').innerHTML=(S.pins||[]).map(pin=>{const p=Array.isArray(pin)?pin[0]:pin,label=Array.isArray(pin)?pin[1]:pin;return '<button data-p="'+esc(p)+'">'+esc(label)+' · '+(Number(t[p])||0)+'</button>';}).join('');
        document.querySelectorAll('#pins button').forEach(b=>b.onclick=()=>emit('pin-vote',{place:b.dataset.p}));
      }
      window.onProjection=(s)=>{S=s||S;draw();}; draw();
    <\/script>`;
}

function stayView() {
  return `<style>${VIEW_CSS()}.row{display:flex;gap:10px;align-items:center;padding:8px;border:1px solid #2a3039;border-radius:8px;margin:7px 0}
    .row .n{font-weight:600}.row .pr{margin-left:auto;text-align:right}.row button{margin-left:8px}.row.win{border-color:var(--c)}</style>
    <h>where we stay</h><div id="list"></div>
    <p class="hint">votes ride back as signed <code>pick</code> frames — the projection tallies them.</p>
    <script>
      ${VIEW_ESCAPE}
      let S={tally:{},items:[]};
      function draw(){
        const t=S.tally||{};
        document.getElementById('list').innerHTML=(S.items||[]).map(item=>{const id=Array.isArray(item)?item[0]:item,n=Array.isArray(item)?item[1]:item;return '<div class=row><div class=n>'+esc(n)+'</div><div class=pr>'+(Number(t[id])||0)+' ♥</div><button data-id="'+esc(id)+'">pick</button></div>';}).join('');
        document.querySelectorAll('#list button').forEach(b=>b.onclick=()=>emit('pick',{id:b.dataset.id}));
      }
      window.onProjection=(s)=>{S=s||S;draw();}; draw();
    <\/script>`;
}

function budgetView() {
  return `<style>${VIEW_CSS()}table{width:100%;border-collapse:collapse;font-size:13px}
    td,th{text-align:left;padding:6px 8px;border-bottom:1px solid #232a33}th{color:var(--dim);font-weight:500;font-size:11px;text-transform:uppercase}
    td.amt{text-align:right;font-variant-numeric:tabular-nums}[contenteditable]{outline:none;border-radius:4px;padding:2px 5px;cursor:text}
    [contenteditable]:focus{background:#10151b;box-shadow:0 0 0 1px var(--c)}tfoot td{font-weight:700;color:#fff;border-top:1px solid #2a3039}</style>
    <h>budget · per person</h>
    <table><thead><tr><th>line</th><th style="text-align:right">¥ each</th></tr></thead>
    <tbody id="rows"></tbody><tfoot><tr><td>total</td><td class="amt" id="tot"></td></tr></tfoot></table>
    <p class="hint">each cell edit emits an <code>edit</code> keyed by row — a per-cell CRDT, so concurrent edits don't clobber.</p>
    <script>
      ${VIEW_ESCAPE}
      let S={cells:{},total:0};
      function draw(){
        const c=S.cells||{};
        document.getElementById('rows').innerHTML=Object.keys(c).map(k=>'<tr><td>'+esc(k)+'</td><td class="amt" contenteditable data-row="'+esc(k)+'">'+esc(c[k]||0)+'</td></tr>').join('');
        document.getElementById('tot').textContent='¥'+(S.total||0).toLocaleString();
        document.querySelectorAll('[contenteditable]').forEach(td=>td.onblur=()=>{
          const raw=td.textContent.trim(),v=Number(raw); if(raw && Number.isFinite(v)) emit('edit',{row:td.dataset.row,amount:v});});
      }
      window.onProjection=(s)=>{S=s||S;draw();}; draw();
    <\/script>`;
}

function arCrawlView() {
  return `<style>${VIEW_CSS()}
    .stop{display:flex;align-items:center;gap:10px;padding:8px;border:1px solid #2a3039;border-radius:8px;margin:7px 0}
    .stop.here-you{border-color:var(--c)}
    .stop .nm{font-weight:600}.stop .meta{color:var(--dim);font-size:12px}
    .stop .counts{margin-left:auto;text-align:right;color:var(--dim);font-size:12px;font-variant-numeric:tabular-nums}
    .stop .acts{display:flex;gap:6px}.stop .acts button{font-size:12px;padding:5px 9px}
    .bad{border-color:#5a3340 !important;color:#f0808f;background:transparent}</style>
    <h id="title">AR crawl</h><div id="stops"></div>
    <p class="hint">"I'm here" emits <code>arrive</code>; "next →" emits <code>vote-next</code>. Your location + next-vote are signed as you (last-per-member wins).</p>
    <p class="hint"><button class="bad" id="spoof">spoof :from @mira ⚠</button>
      <button class="bad" id="forge">forge routing → other thread ⚠</button></p>
    <script>
      ${VIEW_ESCAPE}
      let S={stops:[],here:{},presence:{},nextTally:{},title:'AR crawl'};
      const ME='@you';
      function draw(){
        document.getElementById('title').textContent=S.title||'AR crawl';
        const here=S.here||{},pres=S.presence||{},nt=S.nextTally||{};
        document.getElementById('stops').innerHTML=(S.stops||[]).map(s=>{
          const id=Array.isArray(s)?s[0]:s, nm=Array.isArray(s)?(s[1]||s[0]):s;
          const youHere=here[ME]===id;
          return '<div class="stop'+(youHere?' here-you':'')+'">'
            +'<div><div class=nm>'+esc(nm)+'</div><div class=meta>'+(pres[id]||0)+' here · '+(nt[id]||0)+' want next</div></div>'
            +'<div class=counts></div>'
            +'<div class=acts><button data-arrive="'+esc(id)+'">'+(youHere?"you're here":"I'm here")+'</button>'
            +'<button data-next="'+esc(id)+'">next →</button></div></div>';
        }).join('');
        document.querySelectorAll('[data-arrive]').forEach(b=>b.onclick=()=>emit('arrive',{stop:b.dataset.arrive}));
        document.querySelectorAll('[data-next]').forEach(b=>b.onclick=()=>emit('vote-next',{stop:b.dataset.next}));
      }
      // adversarial probes (REQ-012): the trusted client must reject both — a
      // :from or :thread carried in the payload is a forge (the client binds them).
      function firstStop(){ const s=S.stops[0]; return (Array.isArray(s)?s[0]:s)||'x'; }
      document.getElementById('spoof').onclick=()=>emit('arrive',{stop:firstStop(),from:'@mira'});
      document.getElementById('forge').onclick=()=>emit('arrive',{stop:firstStop(),thread:'someone-elses-thread'});
      window.onProjection=(s)=>{S=s||S;draw();}; draw();
    <\/script>`;
}

function taskView() {
  return `<style>${VIEW_CSS()}.t{display:flex;align-items:center;gap:10px}
    .t .ck{width:18px;height:18px;border-radius:5px;border:1.5px solid var(--dim);flex-shrink:0;display:grid;place-items:center}
    .t.done .ck{background:var(--c);border-color:var(--c);color:#0f1114}.t.done .lbl{text-decoration:line-through;color:var(--dim)}
    .lbl{flex:1;min-width:0;font-size:20px;font-weight:650;line-height:1.4;overflow-wrap:anywhere}.who{color:var(--dim);font-size:13px;margin:10px 0 0 28px}.acts{margin-top:24px;display:flex;flex-wrap:wrap;gap:10px}.acts #done{background:var(--c);color:var(--paper);border-color:var(--c)}</style>
    <div class="t" id="t"><div class="ck" id="ck"></div><div class="lbl" id="lbl">task</div></div>
    <div class="who" id="who"></div><div class="acts"><button id="claim">claim</button><button id="done">mark done</button></div>
    <p class="hint">Claim this task to take ownership, then mark it done when finished.</p>
    <script>
      ${VIEW_ESCAPE}
      let S={assignee:null,done:false};
      function draw(){
        document.getElementById('lbl').textContent=S.title||'task';
        document.getElementById('t').classList.toggle('done',!!S.done);
        document.getElementById('ck').textContent=S.done?'✓':'';
        document.getElementById('who').textContent=S.assignee?('assigned to '+S.assignee):'unassigned';
      }
      document.getElementById('claim').onclick=()=>emit('claim',{});
      document.getElementById('done').onclick=()=>emit('complete',{});
      window.onProjection=(s)=>{S=s||S;draw();}; draw();
    <\/script>`;
}
