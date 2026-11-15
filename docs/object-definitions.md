# Object definitions for hark agents

How an agent joined with `hark join … --objects` defines a hypermedia object
from a specification, checks it, and opens it in a chat channel. A definition
is a SPEC-087 contract (cbcl-bus `specs/SPEC-087-json-authoring-compile.md`),
and cbcl-rs compiles it: what `hark object check` accepts is exactly what a
browser's import dialog accepts, because both call the same
`compile_contract`.

```sh
hark object check --define spec.json          # validate; prints the dialect, verbs, state rules, contract, CBCL
hark object open  --define spec.json --thread board-1 --field title="Launch tasks"
hark object act   board-1 check --field item=venue --field done=true
hark object read  board-1
```

`open` declares the object's dialect to the room (`adddialect`, by its
self-address, with its definition), then sends the opener. The opener carries
no definition. A browser or agent that meets an act of a dialect it has not
learned holds the act, fetches the definition from the room by digest,
verifies that it hashes to its name, installs it through cbcl-rs's R1–R7, and
only then judges the act. Later actions carry only their fields.

## The definition

Version 3 only. The two earlier shapes are refused by name: the pre-v2
single-artifact form (`"version": 1`, the view inside the contract) and the
v2 contract-and-view bundle whose opener carried the definition in
`:object-spec`. Objects published under either must be re-published;
hark does not translate them.

Two forms compile to the same contract. The **authoring form** is what a
person writes:

```json
{
  "name": "checklist",
  "verbs": {
    "open":  { "causedBy": "begin",   "fields": { "title": "string" } },
    "check": { "causedBy": ["open"],  "fields": { "item": "string", "done": "bool", "clock": "hlc" } },
    "drop":  { "causedBy": ["open"],  "fields": { "item": "string" } }
  },
  "project": {
    "title": ["initial", "open", "title"],
    "items": ["lwwMap", "check", "item", "done", "clock", "drop"]
  }
}
```

The **contract record** is what it becomes, and what `check` prints as
`contract`: `{"version": 3, "kind": "contract", "name", "author"?,
"requirements"?, "bounds"?, "roles"?, "verbs", "state"}` with each verb's
`after` list. `causedBy` is sugar for `after`, `project` for `state`,
`dialect` for `name`, and `["string"]` for `"list"`. Either form, or the
record's serialised text, is accepted wherever a definition is.

### `name`

A short label (`[a-z][a-z0-9-]{0,47}`). It is no part of identity: the
object's **dialect** is the self-address `f1220<64hex>` over the body of
the CBCL dialect the contract compiles to (SPEC-019 R.6). Two contracts that
compile to the same body are the same dialect whatever they are called, and a
contract that compiles to the same body as a hand-written `.cbcl` file has
that file's name.

### `verbs`

One entry per action. Exactly one verb has `"causedBy": "begin"`: the
**opener**, which creates an instance in a fresh thread. Every other verb lists
the verbs it may follow. The protocol must be acyclic; cbcl-rs's R5 refuses a
cycle. Repeatable acts each follow the opener.

Field types include `"string"`, `"number"`, `"integer"`, `"float"`, `"decimal"`, `"hlc"`, `"bool"`, `"list"`, and
`{"enumOf": "<state field>"}`, whose values must be among those the named
state field holds (a vote whose choice must be one of the proposed options).
Field sets are closed: an action carrying an undeclared field is rejected.
The routing keywords `from`, `thread`, `dialect`, `caused-by`, `to`,
`sender`, `replaces`, `audience`, `sig`, `key` and `signing-key` are
reserved and never declared.

Optional `bounds` (`maxString`, `maxList`, `maxNumber`, `maxFields`) tighten
the defaults; `requirements` (`maxDepth`, `maxExpansionSize`,
`verificationTime`) are the dialect's resource requirements.

### `project` (the `state`)

The state, as one rule per field over the accepted acts, from the v0.2 state-rule
heads of SPEC-019 R.1. Each is a JSON array whose first element is the rule:

| Rule | Meaning |
| --- | --- |
| `["initial", openerVerb, field]` | immutable value drawn from the unique opener |
| `["lwwRegister", verb, field, clockField]` | one value across everyone, chosen by HLC then deterministic tie-break |
| `["lwwPerSigner", verb, field, clockField]` | one value per signer, chosen by HLC |
| `["lwwMap", verb, keyField, valueField, clockField, deleteVerb?]` | one value per key, chosen by HLC |
| `["exists", verb]` | whether any such act exists |
| `["count", verb]` | number of distinct acts |
| `["events", verb, field]` | every act's value, keyed by address |
| `["setUnion", verb, field]` | sorted unique scalars; additions only |
| `["values", verb, field]` | multi-value register: values no later write replaced |
| `["valuesPerKey", verb, keyField, valueField, deleteVerb?]` | a register map keeping every current value per key |
| `["observedSet", addVerb, removeVerb, field]` | values with an unremoved addition |
| `["counter", incVerb, decVerb, field]` | increments minus decrements |
| `["histogram", stateField]` | counts of another state field's values |
| `["sum", stateField]` | numeric total of another state field |

Two rules matter when writing from a spec:

- **HLC fields belong to Hark.** Register writes declare a `"hlc"` field,
  which Hark fills before binding or opening. A caller-supplied timestamp is
  overwritten. The controller merges only schema-declared clocks from admitted
  history, and retains its clock atomically beside the object journal before
  issuing it. `initial` draws only from the opener; later editable values use
  `lwwRegister`, `lwwPerSigner` or `lwwMap`. Multi-value registers (`values`,
  `valuesPerKey`) retain concurrent values. The compiler and binder own
  `:replaces`; callers never declare or set it. A map delete verb carries the
  key and names no clock field.
- **Removal from a set is an `observedSet`.** The removing verb carries the
  field; cbcl-rs binds the additions being cancelled. Additions that repeat a
  value need a distinguishing field such as `"op"`, or identical acts
  deduplicate into one.

`histogram` and `sum` take the name of another state field, declared before
them. Every verb and field a rule names must be declared.

### `roles` (optional)

`{"role": "singleton" | "indexed"}` in declaration order; with roles every verb
carries `from` (a role) and `to` (a list of roles), and cbcl-rs's R6 admits an
act only from a signer in the role. A role-declaring contract runs only where
the host supplies the cast (cbcl-rs SPEC-014); the chat client mounts none
today.

### Views

A definition carries no presentation. A view is a separate artifact bound to
a dialect by self-address (the chat client's `@cbcl/view` package), imported
and selected per browser; `check` and `open` refuse a definition with a
`view`, `layout` or `resources` member. Hark renders nothing: read the state
with `hark object read` when a picture is needed.

## Checking before sending

`hark object check --define spec.json` compiles the definition with cbcl-rs
and prints:

- `dialect`: the self-address an opener would establish; `label`: the name;
- `opener`, `verbs`, `state`, `roles`: what cbcl-rs understood;
- `contract`: the exact contract bytes the dialect compiled from;
- `cbcl`: the `(define …)` text every host installs and the room declares,
  verified by cbcl-rs (`--cbcl` prints only this).

An invalid definition fails with cbcl-rs's own reason: a protocol cycle (R5),
an unknown verb or field in a rule, an ill-typed rule, a `sum` over a field
that is not numeric. Fix and check again; nothing has been sent.

## Acting

`hark object act <thread> <verb> [fields]` hands the verb and its data
fields to cbcl-rs's intent binder, which admits the verb for the agent,
binds recipients, `:thread`, `:caused-by` and `:replaces` from accepted
history, builds the act and verifies it; the daemon signs and sends it. A
routing keyword among the fields is a forgery and is refused. A rejected
action prints the reason and sends nothing. `hark object read <thread>`
prints the state, cbcl-rs's fold over the accepted acts; it is the same JSON
every browser computes.

## Limits worth telling the spec author

- A contract is at most 16 KiB, 16 verbs, 16 fields per verb, 32 state
  fields, 16 roles (SPEC-087 Controls). A controller learns at most 64
  dialects; acts waiting for an unlearned dialect are held up to 128 acts
  and 512 KiB.
- History beyond the hub's backfill needs `hark history`; an object whose
  opener is out of reach shows as `object_unknown` until it arrives. What was
  delivered to the agent, and every dialect it learned, is journalled under
  the identity directory and replayed after a daemon restart, private rooms
  included.
- A paired agent is subscribed automatically when the pairing record lists an
  object dialect; otherwise pass `--objects` to `hark pair` or `hark join`.
- An act of a dialect the room has not declared cannot be judged: the room's
  `roomcfg` menu is what maps a dialect's self-address to the digest
  `fetchdialect` takes. `open` declares before it sends, so an object created
  through hark is always fetchable.

For exact decimal values, pass `{"decimal":"1.2500"}`; Hark renders a native
CBCL decimal without conversion through binary floating point. JSON numbers
remain integers or finite floats. Counter inputs must be declared `integer`.
The v0.1 `last`, `latestPerSigner`, `latestPerKey` and `registerPerKey` rules
are retired; update definitions explicitly rather than relabeling old messages.
