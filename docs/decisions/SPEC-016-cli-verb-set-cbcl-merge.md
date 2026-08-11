# CLI Verb Set / CBCL Convention Merge — ADR-008, ADR-009, ADR-010 (PROPOSED)

| | |
|---|---|
| **id** | `SPEC-016/ADR-008..010` — an amendment record to [[SPEC-016-agent-onboarding-dx]]; artefacts are pre-numbered for folding into that spec |
| **title** | CLI verb set merges with CBCL convention: `progress` retired, `emit` splits into `tell` and `send` |
| **status** | **PROPOSED** — owner decisions of 2026-08-11 folded; needs a fresh-context adversarial pass on the revision |
| **date** | 2026-08-08 · revised 2026-08-11 |
| **owner-repo** | hark |
| **supersedes** | [[SPEC-016-agent-onboarding-dx#ADR-004]] ("`emit` for plain chat"); [[SPEC-016-agent-onboarding-dx#REQ-004]] |
| **amends** | [[cli]]; [[local-api]]; [[router-protocol]] |
| **breaking** | Yes — CLI surface, [[local-api]] `kind` enum, and the removal of a capability. hark is pre-1.0 (v0.2.1). |

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all
capitals.

---

## Orientation

**Intent:** Make the hark CLI's message verbs say what goes on the wire, by
naming them after [[CBCL]] performatives and deleting the one verb that never
named a performative at all.

**Metaphor:** a post office. `tell`, `reply` and `error` write the letter for
you; `send` posts an envelope you sealed yourself. There is no counter for
"progress" — that was hark's own invented stamp.

```
  ┌──────────── hark CLI · message-minting surface (ADR-008) ────────────┐
  │                                                                       │
  │   named for the performative on the wire   named for the transport    │
  │   ┌───────────────────────────────┐        ┌───────────────────────┐  │
  │   │ tell  <text>   mints a tell   │        │ send <frame>          │  │
  │   │ reply <frame>  reply only     │        │  any performative     │  │
  │   │ error <frame>  error only     │        │  never wraps/rewrites │  │
  │   └───────────────┬───────────────┘        └───────────┬───────────┘  │
  │                   │   progress ── RETIRED (ADR-010) ───┤              │
  └───────────────────┼────────────────────────────────────┼──────────────┘
                      ▼                                    ▼
              ┌────────────────────────────────────────────────┐
              │  local API  POST /v1/send                      │
              │  kind ∈ {reply, error, send} · api_version 4   │
              └───────────────────────┬────────────────────────┘
                                      ▼
                                   @router
```

**Decisions:**
[[#2. ADR-008 — A message-minting verb is named for what it produces|ADR-008]] a minting verb is named for its performative ·
[[#3. ADR-009 — `emit` splits into `tell` and `send`|ADR-009]] `emit` splits into `tell` + `send` ·
[[#4. ADR-010 — `progress` is retired without replacement|ADR-010]] `progress` is retired without replacement

**Load-bearing:**
[[#REQ-013]] minting verbs are performative-named ·
[[#REQ-014]] `tell` wraps literal text ·
[[#REQ-016]] `send` transmits unmodified ·
[[#REQ-019]] `progress` is retired

**Controls:**
[[#REQ-015]] `tell` SHALL NOT parse its argument as CBCL, whatever it starts with
[[#REQ-017]] `send` SHALL NOT wrap, rewrite, or inject parameters
[[#REQ-018]] `send` SHALL refuse a `(meta …)` form
[[#REQ-019]] no replacement verb for `progress` — hark mints no progress frame
[[#REQ-020]] deprecating aliases live exactly one minor release, and warn on stderr

**Open:** [[#7. Open questions]] OQ-005 progress-as-dialect (cross-stack, owner:
project owner) · OQ-006 residual client guard (owner: unassigned) · OQ-007 `hark
ask` (cross-stack) · OQ-008 release staging

**Detail:** [[SPEC-016-agent-onboarding-dx]] · [[cli]] · [[local-api]] ·
[[router-protocol]]

---

## 1. Context

The hark CLI mints [[CBCL]] frames, but its verbs were named independently of
[[CBCL-performative|CBCL's performatives]]. The result is a private vocabulary at the
one boundary where the two conventions ought to be the same word.

The [[CBCL]] core performatives are fixed (`cbcl-core/src/message.rs:61`):

```
tell  ask  reply  error  ok  cancel  hello  bye
```

Beyond those eight, CBCL's sanctioned extension mechanism is a **custom
performative** carried inside a dialect — `Performative::Custom(String)`,
`cbcl-core/src/message.rs:113`, annotated *"Either a core or custom performative
(REQ-011)"*. This matters for ADR-010: hark has a second, hand-rolled extension
mechanism sitting beside the real one.

The CLI's **message-minting** verbs today are `reply`, `error`, `progress`, `emit`
(`src/cli.rs:55-63`). Two of the four are performatives; two are not:

| CLI verb | frame it actually puts on the wire | performative? |
|---|---|---|
| `reply` | caller-supplied `(reply …)` | ✅ `reply` |
| `error` | caller-supplied `(error …)` | ✅ `error` |
| `progress` | `(lang <d> (tell @router "progress" :thread "<id>"))` — `src/cli.rs:1119` | ❌ a **content string** on a `tell` |
| `emit` | plain text → `(tell @chan "…" :from @me)` — `src/cli.rs:823`; **or** a caller-supplied form passed through unchanged | ❌ CLI-only coinage |

Lifecycle and transport verbs (`config`, `daemon`, `join`, `pair`, `init`, `recv`,
`close`, `dialect`, `safety-number`) are **out of scope**: they do not mint an
agent-authored frame as their purpose, so they are free to be named for what they do.

Two observations forced the question:

1. **`emit` is one verb with two contracts, disambiguated by the first character of a
   string.** `emit_input_is_cbcl_form` (`src/cli.rs:815`) branches on a leading `(`.
   The text path wraps into a `tell`; the form path passes through and is validated by
   `validate_for_emit`, which — unlike `validate_for_send` — *deliberately* accepts a
   `Dialect`/`Wrapped` envelope and does **not** require a `:thread`
   (`src/cbcl_validation.rs:165-212`). Both behaviours were specified:
   [[SPEC-016-agent-onboarding-dx#REQ-004]] asks for text wrapping *and* form
   pass-through under one verb. The defect is the shared name, not an accident of
   implementation.
2. **The two ends of the same bus disagree about what typed text means.**
   [[playtest-findings-2026-08-06]] FINDING-5: the web composer sends a typed raw CBCL
   form as the *body of a `tell`*, while `hark emit` passes it through as a form. With
   one overloaded verb there is no way to say which is correct.

---

## 2. ADR-008 — A message-minting verb is named for what it produces

**Decision.** On the hark CLI's message-minting surface, a verb that constrains the
frame to one [[CBCL-performative|performative]] SHALL be named for that performative;
a verb that transmits a caller-supplied frame of **any** performative SHALL be named
for the transport. No third category of name is permitted on that surface.

**Rationale.** This is the whole merge stated as one rule, and it decides every case
below without further appeal. It also explains the exemption: `join` and `recv` are not
named for performatives because minting is not their purpose.

**Consequence.** `progress` and `emit` both fail the rule and are resolved by
[[#3. ADR-009 — `emit` splits into `tell` and `send`|ADR-009]] and
[[#4. ADR-010 — `progress` is retired without replacement|ADR-010]].
`reply` and `error` already satisfy it and are unchanged.

**Rejected alternative — rename `emit` to `send`, keep one verb.** `send` is already the
transport word one layer down: `SendRequest`, `SendMessageKind::{Reply, Error, Progress,
Emit}` (`src/local_api.rs:72-99`). Reply, error, progress and emit *all* send. Promoting
`send` to a user-facing verb for one particular frame kind makes it mean both "put a
frame on the wire" and "one specific frame", reproducing the overload the merge exists to
remove.

---

## 3. ADR-009 — `emit` splits into `tell` and `send`

**Decision.** `hark emit` SHALL be replaced by two verbs, one per contract:

* **`hark tell <text>`** — mints `(tell @<channel> "<text>" :from @<handle>)`. The
  argument is **always literal text**, never parsed as CBCL, whatever character it starts
  with. This is the plain-chat verb [[SPEC-016-agent-onboarding-dx#REQ-004]] asked for,
  under the name of the performative it was already minting.
* **`hark send <frame>`** — transmits a **caller-supplied CBCL frame** of any
  performative, core or custom, bare or wrapped. Never wraps, never rewrites. This is the
  existing `validate_for_emit` pass-through contract, under the transport name that
  matches what it does.

**Rationale.** The split is not cosmetic — it removes the leading-`(` sniff, which is the
mechanism by which one verb carried two contracts. It also gives both ends of the bus a
word for what they mean, settling FINDING-5's parenthetical at the CLI end: text typed at
`tell` is text; a form handed to `send` is a form.

**The pass-through contract is wider than `(lang …)`.** `validate_for_emit` rejects only
`Message::Meta` (`src/cbcl_validation.rs:182-186`), so it also admits `Message::Wrapped`
— `(envelope …)`, `(signed …)`, `(with-limits …)` (`cbcl-core/src/message.rs:266`).
`send` SHALL preserve that width. Enumerating only `(lang …)` narrows a contract this
ADR claims to carry over unchanged.

**Consequence.** `send` is the CLI's only route for a hand-built frame, and — because
[[#4. ADR-010 — `progress` is retired without replacement|ADR-010]] retires `progress`
rather than folding it in — `send` is **`emit` renamed and nothing more**. Its runtime
behaviour, including causal-store handling, is unchanged. See [[#5.1 The causal store is
untouched]].

**Not decided here — `hark ask`.** [[playtest-findings-2026-08-06]] FINDING-5 shows the
web's most prominent agent-facing affordance (`/ask`) mints a bare `ask` that
`src/chat_responder.rs:153` is specified to discard. ADR-008 makes `hark ask` an obvious
empty slot, but whether hark surfaces bare asks or the web wraps in the channel dialect is
a **cross-stack decision with cbcl-bus** and is deliberately left open — see
[[#7. Open questions]] OQ-007.

---

## 4. ADR-010 — `progress` is retired without replacement

**Decision.** `hark progress` SHALL be retired in full: the CLI verb, the
`kind=progress` [[local-api]] variant, and the progress-specific frame validation.
**No replacement verb is added, and no progress-shaped frame rule is introduced.**
An agent that needs progress semantics authors the frame itself and transmits it with
`hark send`.

Concretely, the following are removed: `Command::Progress` and `ProgressArgs`
(`src/cli.rs:58`, `:242-255`), `progress_command` and `build_progress_message`
(`src/cli.rs:731`, `:1119`), `DEFAULT_PROGRESS_DIALECT`, `SendMessageKind::Progress`
(`src/local_api.rs:82`), `MessageKind::Progress` and its branch in `validate_kind`
(`src/cbcl_validation.rs:464-471`), and the `InvalidProgressRecipient` /
`InvalidProgressContent` errors with their codes (`src/cbcl_validation.rs:67-69`,
`:100-101`).

**Rationale — `progress` is a hand-rolled extension mechanism, and CBCL already has one.**
`progress` is not a performative. It is a magic content string on a `tell`, which is
exactly why it fails ADR-008 and why every one of its failure modes is silent: a frame
carrying the string `"progres"` is well-formed CBCL and indistinguishable from ordinary
chat. CBCL's answer to "we need a word the core eight do not have" is a dialect-scoped
custom performative (`cbcl-core/src/message.rs:113`). hark built a second mechanism
beside it and then needed bespoke validators to make the second one safe.

The [[Simplicity Ladder]] question is rung 1 — does this capability need to exist in
hark at all? The evidence says no:

| what `progress` buys | evidence |
|---|---|
| no delivery confirmation | *"the local API cannot confirm receipt persistence"* — `specs/local-api.md:362`; *"success does not prove receipt persistence"* — `specs/cli.md:345` |
| does not complete or clear the in-flight ask | `specs/router-protocol.md:244-246` |
| no consumer in hark | no read path in `src/`; the only reader is the router's receipt log, in cbcl-bus |
| never exercised in practice | zero occurrences in [[playtest-findings-2026-08-06]] |

Its entire function is to append frame bytes to a log in another repository, fire and
forget. That does not warrant a verb, a `kind`, and two bespoke validation errors in
hark.

**Consequence — hark stops discharging a client obligation, and this is deliberate.**
[[router-protocol]] states it plainly: *"The client must reject progress messages without
`:thread` to avoid orphaning receipt entries"* (`specs/router-protocol.md:250-251`).
After this ADR, hark mints no progress frame, so the obligation binds whoever authors the
frame instead. A hand-built frame with a missing `:thread` orphans under receipt id
`"unknown"`; a typo in the content string is dropped by the router (*"non-progress `tell`
frames from agents are ignored, except for `hello`"*, `specs/router-protocol.md:247`).
Both risks move to the frame's author. This is the price of the retirement and it is
recorded, not buried. See [[#7. Open questions]] OQ-006 for whether a residual guard is
kept.

**Consequence — migration.** `hark progress --thread rcp-… --text "running tests"`
becomes:

```
hark send '(lang <channel-dialect> (tell @router "progress" :thread "rcp-…" :text "running tests"))'
```

The caller now supplies the dialect that `progress_command` resolved from `--dialect`
(`src/cli.rs:733`). An agent that does not know its channel's negotiated dialect cannot
form this frame correctly, and a wrong dialect validates locally while failing downstream.
Callers needing progress SHOULD read the dialect from their join configuration.

**Rejected alternative — move the invariants into frame validation.** The previous
revision of this ADR kept `progress` as a frame shape and taught `validate_for_emit` to
enforce two rules on it: content-keyed `:thread` presence, and a `@router`-keyed content
check. It is rejected on three grounds:

1. **It specifies a validator for a shape hark is retiring.** Speculative scaffolding
   under [[Simplicity Ladder]] discipline rung 1.
2. **The `@router`-keyed rule was wrong.** It admitted no exception, so it invalidated
   hark's own `(lang cbcl-router (tell @router "hello" …))` (`src/router.rs:128`) and
   `(lang cbcl-router (tell @router "heartbeat"))` (`src/router.rs:29`), and contradicted
   the `hello` carve-out at `specs/router-protocol.md:247`.
3. **The "exactly one `:thread`" clause was not implementable where it was placed.**
   `Message::Simple.thread` is an `Option<String>` and cannot represent a duplicate; the
   duplicate check reads the s-expression (`src/cbcl_validation.rs:260`, `:275`, `:432`),
   which `validate_for_emit` never obtains.

**Rejected for now — a `cbcl-router` dialect performative.** The CBCL-native form of
progress is `(lang cbcl-router (progress @router :thread "…" :text "…"))`, with `progress`
as a `Performative::Custom`. It is the right shape: an unknown performative in a known
dialect is a grammar violation rather than a silently-dropped `tell`, which is the
[[LangSec]] recognition rule ([[PROTO-001-usdd-agent-protocol]] Principle 14) applied
where a string comparison stands today. hark already wire-tags its router control frames
`(lang cbcl-router …)` and advertises `cbcl-router` in its own hello dialect list
(`src/router.rs:701`). Two facts defer it:

* **It breaks the wire.** Today's router keys receipt persistence on the content string
  `"progress"` and ignores non-progress agent `tell`s (`specs/router-protocol.md:241`,
  `:247`), so a dialect-shaped progress is dropped until cbcl-bus is taught it.
* **`cbcl-router` has no `(define …)`.** It is a dialect name on the wire with no
  published definition anywhere in this tree.

Both make it a cross-stack decision with cbcl-bus, not a hark-local one. Recorded as
[[#7. Open questions]] OQ-005. Retiring `progress` now does not foreclose it — it clears
the ground for it.

---

## 5. Consequences

### 5.1 The causal store is untouched

`reply`/`error`/`progress` are appended to the per-handle causal store;
**`emit` deliberately is not** (`src/local_api.rs:1199-1216`, comment: *"a proactive ask
is not part of the agent's reply chain"*).

The mechanism is worth stating precisely, because an earlier revision of this document
got it wrong. `emit` is excluded by **control flow**: the append call sits at
`src/local_api.rs:1204`, inside the `Some(kind)` arm, and the `None` arm
(`src/local_api.rs:1212-1215`) calls `validate_for_emit` and nothing else. There is no
thread-based filter. `build_outbound_store_entry` (`src/local_api.rs:1238`) returns an
entry for **every** `Message::Simple`, bucketing a threadless frame under
`ThreadId("default")` (`src/local_api.rs:1254`).

Because [[#4. ADR-010 — `progress` is retired without replacement|ADR-010]] retires
`progress` rather than folding it into `send`, `send` is `emit` renamed and inherits
`emit`'s behaviour exactly: **no append, no change**. `reply` and `error` keep their own
paths and their own appends. No causal-store decision is required, and the question the
previous revision raised as OQ-004 is resolved by the retirement rather than answered.

### 5.2 Breaking changes and how they surface

| surface | change | how a stale peer finds out |
|---|---|---|
| CLI | `emit` renamed; `progress` **removed** | hidden deprecating aliases for one minor release ([[#REQ-020]]) |
| [[local-api]] | `kind` enum: `emit` → `send`; `progress` **dropped** | `LOCAL_API_VERSION` 3 → 4 (`src/constants.rs:2`); a CLI meeting an incompatible daemon maps `ApiIncompatible` to `AppError::Internal` (`src/cli.rs:1390`, `:1484`) and exits `12` (`src/errors.rs:14`) with a restart hint — the mismatch is loud, not silent |
| [[router-protocol]] | none — the wire frame is byte-identical | n/a |

`progress` is the one **capability** removal, not a rename: a caller who was minting
progress frames MUST author the frame and route it through `send`. The wire is
unaffected: `(lang <d> (tell @router "progress" …))` is exactly what `send` transmits.
This merge is a **client-surface** change only.

### 5.3 Pre-existing drift this amendment closes

Five gaps, all predating this ADR set and all inside its blast radius:

| # | drift | evidence |
|---|---|---|
| D-1 | `specs/local-api.md:297` documents `kind` as *"one of `reply`, `error`, or `progress`"* | `SendMessageKind` has carried a fourth variant, `Emit`, since [[SPEC-016-agent-onboarding-dx#REQ-004]] shipped (`src/local_api.rs:79-99`) |
| D-2 | `specs/local-api.md:312` enforces `:thread` on *"all three kinds"* | `Emit` requires none |
| D-3 | `specs/cli.md:307` — *"all sent messages require a `:thread` parameter"* | Same drift, other spec. `emit` requires none (`src/cli.rs:823`), and `tell` will not either |
| D-4 | `specs/local-api.md:135` documents `"api_version": 1` | `src/constants.rs:2` is `3`. The spec missed two bumps |
| D-5 | [[SPEC-016-agent-onboarding-dx#REQ-004]] says plain text is wrapped *"(auto-threaded)"* | `build_emit_message` (`src/cli.rs:823-828`) emits `:from` and never `:thread` |

Two further drifts sit in [[router-protocol]] and are **noted, not closed** here, because
they belong to the router surface rather than the CLI surface: `specs/router-protocol.md:87`
documents the hello frame as `(hello @router …)` while `src/router.rs:128` sends
`(tell @router "hello" …)`, and `heartbeat` (`src/router.rs:29`) is undocumented. Owner:
unassigned.

---

## 6. Requirements this implies (DRAFT — to be folded into [[SPEC-016-agent-onboarding-dx]])

Numbering continues SPEC-016's sequence (REQ-001…012, TEST-001…012, ADR-001…007,
OQ-001…004 are taken).

Each requirement carries one obligation, so a failing test attributes to a single clause
([[PROTO-001-usdd-agent-protocol]] atomicity gate).

### REQ-013

**Performative-named minting verbs.** The hark CLI's message-minting surface SHALL
consist of exactly `tell`, `reply`, `error`, and `send`. A verb on that surface that
constrains its frame to one [[CBCL-performative|performative]] SHALL bear that
performative's name; a verb accepting any performative SHALL bear the transport name
`send`.
Trace: `[[SPEC-016-agent-onboarding-dx#TEST-013]]`.

### REQ-014

**`tell` wraps literal text.** `hark tell <text>` SHALL wrap its argument into
`(tell @<channel> "<text>" :from @<handle>)`.
Trace: `[[SPEC-016-agent-onboarding-dx#TEST-014]]`.

### REQ-015

**`tell` does not parse its argument.** `hark tell` SHALL NOT parse its argument as
CBCL, regardless of the argument's leading character. An argument beginning with `(`
SHALL be transmitted as the quoted body of a `tell`.
Trace: `[[SPEC-016-agent-onboarding-dx#TEST-015]]` (prohibited-action).

### REQ-016

**`send` transmits unmodified.** `hark send <frame>` SHALL transmit a caller-supplied
CBCL frame unmodified, accepting any core or custom performative, bare or carried in a
`(lang …)`, `(envelope …)`, `(signed …)`, or `(with-limits …)` envelope.
Trace: `[[SPEC-016-agent-onboarding-dx#TEST-016]]`.

### REQ-017

**`send` adds nothing.** `hark send` SHALL NOT wrap, rewrite, reorder, or inject any
parameter into the caller's frame — including `:thread`, `:from`, and a `(lang …)`
envelope.
Trace: `[[SPEC-016-agent-onboarding-dx#TEST-017]]` (prohibited-action, scope-invariant).

### REQ-018

**`send` refuses dialect teaching.** `hark send` SHALL refuse a frame whose parsed form
is `(meta …)` (`src/cbcl_validation.rs:182-186`).
Trace: `[[SPEC-016-agent-onboarding-dx#TEST-018]]` (prohibited-action).

### REQ-019

**`progress` is retired.** hark SHALL NOT provide a `progress` CLI verb, a
`kind=progress` [[local-api]] variant, or progress-specific frame validation. No
replacement verb SHALL be added.
Trace: `[[SPEC-016-agent-onboarding-dx#TEST-019]]` (prohibited-action).

### REQ-020

**Deprecation is loud and bounded.** `hark emit` and `hark progress` SHALL remain
accepted as hidden aliases for exactly one minor release, SHALL write a single-line
deprecation notice naming the replacement to **stderr**, and SHALL preserve their current
exit codes so scripts break visibly rather than silently.
Trace: `[[SPEC-016-agent-onboarding-dx#TEST-020]]`.

### Test decomposition

Split into a **core** an implementer writes in one sitting with no new rig, and **depth**
that needs infrastructure. Deferring a depth test is a recorded decision; deferring a core
test is not available.

| TEST | type | case | tier |
|---|---|---|---|
| TEST-013 | positive | the `Command` enum exposes exactly `tell`, `reply`, `error`, `send` on the minting surface | core |
| TEST-014 | positive | `hark tell 'hi'` produces `(tell @chan "hi" :from @me)` | core |
| TEST-015 | prohibited-action | `hark tell '(tell @x "y")'` produces a `tell` whose **body is the literal string** — no frame with performative `tell` addressed to `@x` is transmitted | core |
| TEST-016 | positive | a bare `(ask @bob "q")`, a `(lang elf (ask …))`, and a `(signed "s" (reply …))` each transmit byte-identically | core |
| TEST-017 | scope-invariant | the transmitted bytes equal the input bytes exactly, for every frame in TEST-016 | core |
| TEST-018 | negative-input | `hark send '(meta (define d …))'` is refused before transmission | core |
| TEST-019 | prohibited-action | `hark progress …` is absent from `--help`; the `kind` enum rejects `"progress"`; no progress error code remains | core |
| TEST-020 | positive | `hark emit 'x'` succeeds, writes one stderr line naming `tell`, and exits `0` | core |
| TEST-016b | negative-output | a frame refused by the R1–R5 pipeline exits non-zero and puts nothing on the wire | depth — needs a router harness |
| TEST-020b | negative-input | the alias is gone one minor release later | depth — release-gated; owner: project owner |

---

## 7. Open questions

| # | Question | Recommendation |
|---|---|---|
| OQ-005 | Does progress return as a `cbcl-router` dialect performative, `(lang cbcl-router (progress @router :thread …))`? | **Defer, and pursue.** It is the CBCL-native shape and it converts a silent failure into a grammar violation. It breaks the wire and needs a `(define cbcl-router …)` that does not exist, so it is cross-stack with cbcl-bus. Owner: project owner. |
| OQ-006 | Does hark keep any client-side guard for hand-built progress frames sent through `send`? | **No.** A transport that inspects payload semantics is a minting verb again (ADR-008). The `router-protocol.md:250-251` obligation moves to the frame's author. Revisit if OQ-005 lands, where the dialect grammar discharges it properly. |
| OQ-007 | `hark ask` — does hark surface bare asks, or does the web wrap in the channel dialect? | **Defer.** Cross-stack with cbcl-bus; owns FINDING-5. Do not decide inside a hark-local CLI ADR. |
| OQ-008 | Does the [[local-api]] `kind` change land in the same release as the CLI change, or ride a release behind? | Same release — the `LOCAL_API_VERSION` bump is what makes a stale daemon fail loudly (§5.2), and staging them creates a window where it does not. |

**Resolved by this revision.** The previous revision asked whether `send` appends to the
per-handle causal store. Retiring `progress` rather than folding it in means `send` is
`emit` renamed and the store is untouched — see [[#5.1 The causal store is untouched]].
The previous revision's `tell --progress` shorthand is moot: it selected a second contract
by flag, which is the defect ADR-009 removes, and it has nothing left to shorten.

---

## 8. Amendment checklist (on approval)

Ordered. **Retire `progress` first, then split `emit`** — the retirement shrinks the
surface the split has to carry, and keeps the two changes independently revertible.

**Step 1 — retire `progress`**

- [ ] `src/cli.rs` — remove `Command::Progress`, `ProgressArgs`, `progress_command`,
      `build_progress_message`, `DEFAULT_PROGRESS_DIALECT`
- [ ] `src/local_api.rs` — remove `SendMessageKind::Progress` and its `message_kind()` arm
- [ ] `src/cbcl_validation.rs` — remove `MessageKind::Progress`, the `validate_kind`
      progress branch (`:464-471`), and `InvalidProgressRecipient` /
      `InvalidProgressContent` with their codes
- [ ] `tests/e2e_mvp.rs`, `tests/chat_reconnect.rs` — retarget the progress cases onto
      `send`
- [ ] [[cli]] — delete §`progress` (`specs/cli.md:286-346`); drop `progress` from the
      `CBCL_AGENT_HANDLE` consumer list (`specs/cli.md:31`)
- [ ] [[router-protocol]] — record that hark no longer mints progress frames, and that the
      client obligation at `specs/router-protocol.md:250-251` binds the frame's author

**Step 2 — split `emit`**

- [ ] `src/cli.rs` — `Emit` → `Tell` + `Send`; delete `emit_input_is_cbcl_form`
- [ ] `src/local_api.rs` — `SendMessageKind::Emit` → `Send`
- [ ] `src/constants.rs` — `LOCAL_API_VERSION` 3 → 4
- [ ] [[cli]] — replace §`emit` and §`reply`, `error`, and `progress` with §`tell` and
      §`send`; update the `CBCL_AGENT_HANDLE` consumer list (`specs/cli.md:26-34`)
- [ ] [[local-api]] — `kind` enum → `reply` / `error` / `send`; correct D-1 and D-2
      (§5.3); document the `api_version` history 1 → 3 → 4 rather than jumping (D-4)

**Step 3 — specification and vault**

- [ ] [[SPEC-016-agent-onboarding-dx]] — fold ADR-008/009/010; mark **ADR-004 superseded**;
      replace **REQ-004** with REQ-014/015 and record D-5; add REQ-013…020 +
      TEST-013…020; add OQ-005…008; bump `version` and `last-updated`
- [ ] [[cli]] — correct D-3 (`specs/cli.md:307`) and the *"Thread validation is
      deliberately stricter"* paragraph (`specs/cli.md:310-315`), which describes verbs
      that will no longer exist
- [ ] `zetl -d specs check --dead-links --fail-on error` — baseline at authoring time is
      144 dead links / 0 orphans / 0 syntax errors (`zetl 0.9.3`, verified 2026-08-11); no
      *new* error-level findings

---

## 9. Review status

**Reviewed once, revised, not re-reviewed.** A fresh-context adversarial pass
([[SPEC-016-cli-verb-set-review-findings]], 2026-08-11) raised thirteen findings against
the previous revision. Four were blocking, and all four are discharged by the owner
decision of 2026-08-11 to retire `progress` rather than preserve its frame shape:

| finding | disposition |
|---|---|
| V-01 `@router` rule invalidates hark's own `hello` / `heartbeat` | dissolved — no frame rules are introduced (ADR-010, rejected alternative 2) |
| V-02 §5.1 states the wrong storage mechanism | corrected in [[#5.1 The causal store is untouched]], and the question it raised is resolved |
| V-03 OQ-004 number collision | renumbered to OQ-005…008 |
| V-04 "exactly one `:thread`" not implementable at that point | dissolved — the clause is gone (ADR-010, rejected alternative 3) |
| V-05 router-persistence premise unverified | the claim is no longer load-bearing; the underlying question moves to OQ-005 |
| V-06 REQ narrowed the preserved contract | [[#REQ-016]] now enumerates `Wrapped` envelopes |
| V-07 drift inventory incomplete | §5.3 now carries D-1…D-5 plus two noted router drifts |
| V-08 `tell --progress` reintroduced the two-contract shape | withdrawn as moot (§7) |
| V-09 dialect resolution transferred unremarked | stated in ADR-010's migration consequence |
| V-10 identity / Orientation / BCP 14 | information table `id` qualified; Orientation and BCP 14 added |
| V-11 breaking change to an `implemented` spec | **open** — see below |
| V-12 citation slips | corrected; the exit-`12` claim now cites the code |
| V-13 atomicity and test decomposition | REQ split into eight atomic obligations; core/depth tiers added |

**What still needs a fresh pass**, over this document plus `specs/cli.md`,
`specs/local-api.md`, `specs/router-protocol.md`, and `src/cbcl_validation.rs`:

1. **The retirement's blast radius.** ADR-010 removes a capability. The evidence that
   nothing depends on it is hark-local — no read path in `src/`, absent from the playtest.
   Whether cbcl-bus or any deployed agent consumes the receipt log is **not established
   here**, and a reviewer SHOULD press on it. This is the place this revision is most
   likely to be wrong.
2. **The residual guard decision (OQ-006).** Declining to guard hand-built progress frames
   is defensible under ADR-008 and it does re-open a silent failure mode.
3. **V-11, unresolved.** [[SPEC-016-agent-onboarding-dx]] carries `status: IMPLEMENTED`,
   and [[PROTO-001-usdd-agent-protocol]] requires a materially changed implemented spec to
   be superseded rather than edited. This document folds a breaking change in place. The
   alternative — promoting this to a standalone `SPEC-017` that supersedes SPEC-016's
   REQ-004 and ADR-004 — is unexercised and is an owner call.
4. **The comprehension gate.** The Orientation block above is new and has not been run
   past a fresh-context reader.
