# Object definitions for hark agents

How an agent joined with `hark join … --objects` defines a hypermedia object
from a specification, checks it, and loads it into a chat channel. Everything
here is the `@cbcl/object` SDK's own format; hark runs the SDK's code, so what
`hark object check` accepts is exactly what a browser's import dialog accepts.

```sh
hark object check --define spec.json          # validate; prints digests, verbs, projections, CBCL
hark object open  --define spec.json --thread board-1 --field title="Launch tasks"
hark object act   board-1 check --field item=venue --field done=true
hark object read  board-1
```

`open` sends one message, the opener. It carries the whole definition in
`:object-spec`, so every browser and every hark agent in the room learns the
new object type when the opener arrives. Nothing is registered anywhere first.
Later actions carry only their fields.

## The definition

A JSON object with three required members and three optional ones:

```json
{
  "name": "checklist",
  "verbs": {
    "open":  { "causedBy": "begin",   "fields": { "title": "string" } },
    "check": { "causedBy": ["open"],  "fields": { "item": "string", "done": "bool", "replaces": "list" } },
    "drop":  { "causedBy": ["open"],  "fields": { "item": "string", "replaces": "list" } }
  },
  "project": {
    "title": ["last", "open", "title"],
    "items": ["registerPerKey", "check", "item", "done", "replaces", "drop"]
  },
  "view": [
    { "type": "value", "field": "title", "label": "List" },
    { "type": "value", "field": "items", "label": "Items" },
    { "type": "form",  "verb": "check", "label": "Check an item", "fields": { "item": "Item", "done": "Done" } }
  ]
}
```

### `name`

A short label. The object's real identity is its **dialect**, `object-` plus
the SHA-256 of the serialised contract, computed by `check`. Two definitions
with different bytes are two different object types even if named alike.

### `verbs`

One entry per action. Exactly one verb has `"causedBy": "begin"`: the
**opener**, which creates an instance in a fresh thread. Every other verb lists
the verbs it may follow. The protocol must be acyclic: a verb may not follow
itself, directly or through a cycle. Repeatable acts each follow the opener.

Field types: `"string"`, `"number"`, `"bool"`, `"list"`, and `{"enumOf":
"<opener field>"}`, whose values must be among those the opener listed in that
field (a vote whose choice must be one of the proposed options). Strings are
limited to 2048 bytes, lists to 64 elements, numbers to ±1e12. Field sets are
closed: an action carrying an undeclared field is rejected. The names `from`,
`thread`, `dialect`, `caused-by`, `key` and `signing-key` are reserved.

### `project`

The state, as named projections over the accepted messages. Each is a JSON
array whose first element is the combinator:

| Projection | Meaning |
| --- | --- |
| `["last", verb, field]` | one value, chosen by greatest content hash across everyone |
| `["latestPerSigner", verb, field]` | one value per signer |
| `["latestPerKey", verb, keyField, valueField]` | one value per key |
| `["exists", verb]` | whether any such action exists |
| `["count", verb]` | number of distinct actions |
| `["events", verb, field]` | every action's value, keyed by content address |
| `["setUnion", verb, field]` | sorted unique scalars; additions only |
| `["histogram", selector]` | counts of a per-signer or per-key selector's values |
| `["sum", selector]` | numeric total of `events`, `latestPerSigner`, `latestPerKey` or `registerPerKey` |
| `["counter", incVerb, decVerb, field]` | increments minus decrements |
| `["values", verb, field, replacesField]` | multi-value register: values no later write replaced |
| `["valuesPerKey", verb, keyField, valueField, replacesField, deleteVerb?]` | a register map keeping every current value per key |
| `["registerPerKey", verb, keyField, valueField, replacesField, deleteVerb?]` | a register map with one current value per key |
| `["observedSet", addVerb, removeVerb, field, removesField]` | values with an unremoved addition |

Two rules matter when writing from a spec:

- **Nothing is ordered by time.** Concurrent writes tie-break by content hash.
  If "the latest edit wins" is what the spec means, use a register
  (`values`, `valuesPerKey`, `registerPerKey`): declare a `"list"` field on the
  writing verb (`replaces` above) and name it in the projection. The broker
  fills that field with the writes being superseded; a caller may never set it.
  To let people remove keys, add a delete verb carrying the key field and the
  same replacement field, and name it last.
- **Removal from a set is an `observedSet`.** The removing verb carries a
  `"list"` field the broker fills with the additions being cancelled.
  Additions that repeat a value need a distinguishing field such as `"op"`,
  or identical messages deduplicate into one.

`sum` needs a numeric selector with an explicit basis; `["sum", ["last", …]]`
is refused. Every verb and field a projection names must be declared.

### `view` (optional)

What browsers render. Three kinds:

- **Components**, a list of 1 to 32 items and the kind to prefer: `{"type":
  "text", "text": "…"}`, `{"type": "value", "field": <projection>, "label":
  "…"}`, and `{"type": "form", "verb": <verb>, "label": "…", "fields": {<field>:
  <label>, …}}`. A form names every field of its verb except broker-bound ones,
  scalars only, and may not name the opener. Browsers render these with
  built-in components inside the sandbox; no opt-in is needed.
- **Static HTML**: `{"html": "<…>"}`, at most 12,000 bytes.
- **Custom script**: `{"render": "(state, {emit}) => …"}`, at most 12,000 bytes
  of JavaScript source using the SDK's `html` tagged template. Browsers mark
  this and static HTML as untrusted, and run them only after a person opts in.

`layout` (`{"width": "compact"|"standard"|"wide", "minHeight", "maxHeight",
"aspectRatio", "overflow": "scroll"}`) and `resources` (`{"images": […],
"styles": […]}`, custom views only) are optional companions.

A view is a separate artifact bound to the contract's digest. The opener
distributes it as a suggestion; a browser may switch to another compatible
view locally. The definition as a whole is limited to 16 KiB.

## Checking before sending

`hark object check --define spec.json` compiles the definition the way the
browser would and prints:

- `dialect` and `view`: the digests an opener would establish;
- `opener`, `verbs`, `project`: what was understood;
- `serialized`: the exact artifact text the opener will carry;
- `cbcl`: the native CBCL dialect the contract compiles to, which cbcl-rs has
  verified (`--cbcl` prints only this).

An invalid definition fails with the SDK's own message: a protocol cycle, an
unknown field in a projection, a form naming a list field, a `sum` without a
basis. Fix and check again; nothing has been sent.

## Acting

`hark object act <thread> <verb> [fields]` hands the intent to the SDK's
broker, which binds the sender, room and thread, chooses the causal
predecessor, fills any register or removal field from accepted history,
verifies shape and protocol with cbcl-rs, and only then sends. A rejected
action prints the reason and sends nothing. `hark object read <thread>` prints
the projected state; it is the same JSON every browser computes.

## Limits worth telling the spec author

- A room keeps at most 64 learned contracts and 128 views.
- History beyond the hub's backfill needs `hark history`; an object whose
  opener is out of reach shows as `object_unknown` until it arrives.
- Views are not previewable in hark. The state is; render it from
  `hark object read` when a picture is needed.
