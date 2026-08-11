# SPEC-016 — CLI Verb Set / CBCL Merge: Adversarial Review Findings

Fresh-context adversarial review of
[[SPEC-016-cli-verb-set-cbcl-merge]] (**PROPOSED**, 2026-08-08), run under the
mandate [[PROTO-001-usdd-agent-protocol]] Principle 12 sets: clean context,
document plus code only, brief to find defects. The review covers the document,
`specs/cli.md`, `specs/local-api.md`, `specs/router-protocol.md`,
`src/cbcl_validation.rs`, `src/local_api.rs`, `src/cli.rs`, `src/router.rs`, and
the pinned `cbcl-core` at `fd8f034`.

Every citation in the document under review was checked against the tree. The
line references are, with three exceptions noted in [[#V-12 — citation slips]],
accurate — an unusually high standard for a document of this density, and the
reason the findings below are about *reasoning* rather than about bookkeeping.

> **Principle-12 meta-caveat.** This review was run by Claude Opus 5. The
> document under review names no authoring model, so cross-model independence is
> unproven. Where a finding rests on a judgement rather than on a tree fact
> ([[#V-05 — the router-persistence premise is unverified cross-repo inference]],
> [[#V-08 — OQ-005 reintroduces the defect ADR-009 removes]]), a second reader is
> warranted before the owner acts on it.

**Verdict: DO NOT APPROVE as written.** The merge's central rule ([[#ADR-008]])
is sound and the `emit` split is the right call. Four blocking findings stand
between the document and sign-off, and one of them ([[#V-01 — ADR-010 rule (b)
invalidates hark's own `hello` and `heartbeat` frames]]) is a correctness defect
in the invariant the document exists to generalise. The document invited the
reviewer to press hardest on §5.1; that instinct was right, and §5.1 does carry a
factual error about the code it cites.

---

## Blocking

### V-01 — ADR-010 rule (b) invalidates hark's own `hello` and `heartbeat` frames

**Severity: Critical.** §4 states rule (b) without exception:

> If the frame is a `tell` addressed to `@router`, its content SHALL be exactly
> `"progress"`.

Two frames hark mints today are `tell`s addressed to `@router` whose content is
not `"progress"`:

| frame | source | content | `:thread` |
|---|---|---|---|
| `(lang cbcl-router (tell @router "hello" :agent-id "…" :dialects (…)))` | `src/router.rs:128` | `"hello"` | absent |
| `(lang cbcl-router (tell @router "heartbeat"))` | `src/router.rs:29` | `"heartbeat"` | absent |

As **scoped** in the decision text the rule lands only in `validate_for_emit`,
and neither frame passes through it — both are written straight to the router
WebSocket. The defect is that the document's own rationale refuses that scoping,
in four places:

1. §4 opens by stating the invariants "move into frame validation, where they
   hold for **any** path that produces the frame."
2. §4 closes by claiming the move "discharges that obligation for `send`, for the
   [[local-api]], and for any future producer — not just for one spelling of one
   subcommand." Two current producers are counterexamples.
3. §8 instructs [[router-protocol]] to restate the obligation "as a **frame** rule
   rather than a verb rule." Applied literally, `specs/router-protocol.md`
   contradicts its own line 247, which reads *"non-progress `tell` frames from
   agents are ignored, **except for `hello`**"*.
4. [[SPEC-016-cli-verb-set-cbcl-merge#REQ-015]] carries rule (b) with no carve-out,
   so an agent re-announcing via `hark send '(lang cbcl-router (tell @router
   "hello" …))'` is refused, and the document offers no rationale for refusing it.

The document quotes line 247 in §4's invariant table and drops the four-word
`hello` exception in the same sentence. That omission is what let the rule reach
its universal form unchallenged.

**Resolution.** Rule (b) is a *hark addressing convention for progress reporting*,
not a property of `tell @router`. State it as the narrower rule it is — for
example, keyed on the presence of `:thread` rather than on the recipient — or
enumerate the router's control vocabulary (`hello`, `heartbeat`) as an explicit
exemption with its source. Either way the exemption belongs in ADR-010's decision
text and in REQ-015, not in the implementation.

**Adjacent, unclaimed by the document.** `specs/router-protocol.md:87` documents
the hello frame as `(hello @router …)` — performative `hello`. The
implementation sends `(tell @router "hello" …)`. `heartbeat` appears nowhere in
`specs/router-protocol.md`. Both belong in §5.3's drift inventory, because both
sit inside the invariant ADR-010 proposes to generalise. See
[[#V-07 — the drift inventory and the amendment checklist are both incomplete]].

### V-02 — §5.1 states the wrong mechanism, and OQ-004 rests on it

**Severity: High.** §5.1 reads:

> `build_outbound_store_entry` (`src/local_api.rs:1238`) appends any `Simple`
> message with a thread — so today a `progress` frame **is** stored and an `emit`
> frame is not.

Neither half holds:

- `build_outbound_store_entry` returns `Some` for **every** `Message::Simple`,
  threaded or not. A frame with no `:thread` is bucketed under
  `ThreadId("default")` — `src/local_api.rs:1254`. No thread filter exists.
- `emit` is excluded by **control flow, not by shape**. The call sits at
  `src/local_api.rs:1204`, inside the `Some(kind)` arm. The `None` arm —
  `src/local_api.rs:1212-1215` — calls `validate_for_emit` and nothing else. An
  emit frame carrying a `:thread` is still not stored today.

The consequence is that OQ-004's recommendation — *"Append whenever the frame
carries a `:thread` … preserves today's `progress` behaviour"* — is true only by
accident. It is true because `validate_for_send` independently forces `:thread`
onto every `progress` frame, and not because the append site tests for one. An
implementer reading §5.1 reasonably concludes the gate already exists in
`build_outbound_store_entry` and ships the merge without adding it, at which
point every threadless frame routed through `send` appends under
`ThreadId("default")` — the silent causal-store pollution §5.1 was written to
prevent.

**Resolution.** Correct §5.1 to state that `emit` is excluded by branch and that
the append site has a `"default"` fallback rather than a thread gate. Restate
OQ-004 as introducing a new gate at `src/local_api.rs:1254`, with the
`"default"` fallback named as the behaviour being replaced.

### V-03 — OQ-004 collides with an already-resolved OQ in the spec it amends

**Severity: High.** [[SPEC-016-agent-onboarding-dx]] §7 *Resolved Questions*
already carries **OQ-004** — *"An agent is removable only by its `added_by`
member"* — settled in owner dialogue on 2026-06-09 and cited by that spec's
ADR-007. The document under review introduces a different, open OQ-004 and
directs §8 to fold OQ-004…007 into the same spec.

[[PROTO-001-usdd-agent-protocol]] is explicit: identifiers MUST be unique within
their prefix scope, and numbers MUST NOT be reused. The collision lands on the
one question §9 names as the document's riskiest, so a reader following the
document's own advice arrives at an ambiguous identifier.

**Resolution.** Renumber to OQ-005…008. §6 performed exactly this check for
`REQ-###` and `TEST-###` — *"Numbering continues SPEC-016's sequence
(REQ-001…012, TEST-001…012 are taken)"*, which is correct — and for `ADR-###`,
also correct (SPEC-016 holds ADR-001…007; ADR-008…010 are free). The `OQ-###`
sequence was the one namespace not checked.

### V-04 — §9's soundness claim does not cover the "exactly once" half of rule (a)

**Severity: High.** §9 asserts the enforcement point was checked and is sound,
on the grounds that `validate_for_emit` holds the pipeline's `Message` and
`Message::Simple` carries `thread: Option<String>`. That supports **presence**
and **non-emptiness**. It does not support **"exactly one"**, which rule (a) and
REQ-015 both require.

`Option<String>` cannot represent a duplicate. The duplicate check lives in
`validate_thread`, which reads the **s-expression**, not the parsed `Message`:

- `src/cbcl_validation.rs:260` — `unwrap_supported_message(input, &message)`
  yields `inner_expr`
- `src/cbcl_validation.rs:275` — `validate_thread(&inner_expr)`
- `src/cbcl_validation.rs:432` — raises `CbclValidationError::DuplicateThread`

`validate_for_emit` calls neither. Implementing rule (a) as specified therefore
requires plumbing the inner s-expression into the emit path — real work the
document records as already discharged.

**Resolution.** Either narrow rule (a) to presence and non-emptiness, and state
why duplicate detection is out of scope, or record the s-expression plumbing as
the work it is. §9's "was checked and is sound" claim MUST be scoped to the half
it verified.

---

## High

### V-05 — the router-persistence premise is unverified cross-repo inference

§4's ordering argument — the finding the document is proudest of, and the one
§9 asks the reviewer to confirm — rests on this step:

> `specs/router-protocol.md:241` reads *"`(tell ... "progress" ...)` is appended
> to receipt storage using the `:thread` value as the receipt id"*, with the
> recipient elided. So `(tell @someone-else "progress" :thread …)` **is**
> persisted as a receipt.

The quotation is accurate. The inference is not established. `...` in a
hark-authored prose summary of an external system is an ellipsis, and an ellipsis
carries no commitment about what fills it. The router is cbcl-bus, not this
repository; the document knows this, because OQ-006 defers a different question
on exactly that ground. No cbcl-bus source is cited, and no probe is recorded.

The conclusion is stated as fact ("**is** persisted"), and rule (a)'s primacy
over rule (b) is derived from it. Under the evidence discipline this protocol
applies to tool behaviour, a claim about another system is grounded when
measured, cited outside the authoring session, or marked provisional with a named
ratification step. None of the three is present.

**Resolution.** The ordering is defensible on its own terms — a content-keyed
rule is the safer default whether or not the router persists foreign-recipient
progress, because failing closed costs nothing here. Rest the argument on that,
and mark the router-behaviour claim provisional pending a cbcl-bus check, with an
owner. Do not delete the claim; it is worth verifying.

### V-06 — REQ-015 narrows the contract ADR-009 promises to preserve

ADR-009 defines `hark send` as *"the existing `validate_for_emit` pass-through
contract, under the transport name that matches what it does."* REQ-015 then
enumerates that contract as *"accepting any performative and an optional `(lang
…)` envelope."*

`validate_for_emit` is wider. It rejects only `Message::Meta`
(`src/cbcl_validation.rs:182-186`), so it also accepts `Message::Wrapped` —
`(envelope …)`, `(signed …)`, `(with-limits …)` per `cbcl-core` `message.rs:266`.
Its own doc-comment says so: *"it accepts a `Dialect`/`Wrapped` envelope (which
`validate_for_send` rejects)"*, and §1 of the document quotes that same comment
approvingly.

An implementer working from REQ-015 ships a `send` that refuses `(signed …)`
frames `emit` accepts today. That is a silent behaviour narrowing inside a
document whose §5.2 asserts the change is naming-only apart from §5.1.

**Resolution.** REQ-015 MUST enumerate `Wrapped` alongside `(lang …)`, or ADR-009
MUST stop claiming the existing contract is preserved and state the narrowing as
a decision with rationale.

### V-07 — the drift inventory and the amendment checklist are both incomplete

§5.3 identifies one piece of pre-existing drift, correctly: `specs/local-api.md`
documents three `kind` values while `SendMessageKind` has carried four since
REQ-004 shipped. Four more sit in the same blast radius and are unrecorded:

| drift | evidence | why it is in scope |
|---|---|---|
| `specs/cli.md:307` — *"all sent messages require a `:thread` parameter"* | `emit` requires none (`src/cli.rs:823`) | Identical drift to the one §5.3 claims to close, in the other spec. §8's `[[cli]]` item does not mention it. |
| `specs/cli.md:310-315` — the *"Thread validation is deliberately stricter"* paragraph | `hark tell` mints no `:thread` at all | Becomes wrong for both new verbs. Unlisted in §8. |
| `specs/local-api.md:135` documents `"api_version": 1`; `src/constants.rs:2` is `3` | direct comparison | §8 says "bump the documented `api_version` to `4`", jumping 1→4 and erasing the record that 2 and 3 happened. |
| [[SPEC-016-agent-onboarding-dx#REQ-004]] says plain text is wrapped "(auto-threaded)" | `build_emit_message` (`src/cli.rs:823-828`) emits `:from`, never `:thread` | REQ-014 supersedes REQ-004 and silently drops the claim rather than recording it as drift. |

The last row matters beyond bookkeeping: OQ-004's proposed thread-keyed append
rule interacts directly with whether `tell` frames carry a `:thread`, and REQ-004
asserts they do.

**Resolution.** Fold all four into §5.3 and add the corresponding line items to
§8.

### V-08 — OQ-005 reintroduces the defect ADR-009 removes

OQ-005 recommends `hark tell --progress rcp-… --text "…"`, claiming it "restores
one-line ergonomics **without** reintroducing a verb that fails ADR-008."

Under that flag, `tell` produces a frame with a different recipient
(`@router`, not `@<channel>`), different content (the literal `"progress"`, not
the user's text), a `(lang …)` wrapper plain `tell` does not add, and a `:thread`
plain `tell` does not carry. That is a second contract, selected by a flag.

It also contradicts [[SPEC-016-cli-verb-set-cbcl-merge#REQ-014]] as written:
*"`hark tell <text>` SHALL wrap its argument into `(tell @<channel> "<text>"
:from @<handle>)`"*. Under `--progress` the argument is not wrapped that way, and
`--text` is not the positional argument REQ-014 governs.

ADR-009's stated warrant is that the split "removes the leading-`(` sniff, which
is the mechanism by which one verb carried two contracts." OQ-005 moves the
discriminator from the first character to a flag and keeps the two contracts. The
critique ADR-008 levels at `emit` applies unchanged.

**Resolution.** Take the ergonomic hit, or restore a performative-named verb, or
accept the two-contract shape openly with rationale. The current framing claims a
property the proposal does not have.

### V-09 — the migration example transfers dialect resolution to the caller, unremarked

`progress_command` resolves the dialect from `args.dialect` and passes it to
`build_progress_message` (`src/cli.rs:733`, `src/cli.rs:1119-1128`), so the CLI
owns dialect selection today. §4's migration example hardcodes it:

```
hark send '(lang elf (tell @router "progress" :thread "rcp-…" :text "running tests"))'
```

§4 describes the cost as "materially more ceremony." The cost is larger than
ceremony: the caller now MUST know the channel's negotiated dialect, and a wrong
guess produces a frame that validates locally and is discarded downstream — the
same silent-failure class ADR-010 exists to close.

**Resolution.** State how a `send` caller learns the correct dialect, or specify
that `send` resolves a missing `(lang …)` wrapper from session state. A third
option is to accept the burden explicitly and trace it to the OQ-005 decision.

---

## Medium — protocol conformance

### V-10 — document identity, Orientation block, and BCP 14 declaration

Three [[PROTO-001-usdd-agent-protocol]] obligations are unmet:

- **Identity.** The file is `SPEC-016-cli-verb-set-cbcl-merge.md` and the title
  reads `SPEC-016 — …`, while `specs/SPEC-016-agent-onboarding-dx.md` already
  holds `SPEC-016`. Two documents share a document ID. The information table's
  `id` cell contains prose — *"ADR set for [[SPEC-016-agent-onboarding-dx]] —
  ADR-008, ADR-009, ADR-010"* — where the protocol requires an ID of the form
  `SPEC-###` / `IMPL-###` / `SCREEN-###` / `PROTO-###`.
- **Orientation block.** Absent. The protocol makes it a Phase 2 gate failure for
  any `SPEC-###`, and mandatory for any AI-synthesised specification. This
  document is dense, decision-heavy, and carries an ordering argument the author
  labels non-obvious — precisely the profile the comprehension gate targets.
- **BCP 14 declaration.** Absent. The document uses SHALL and MUST throughout.
  The protocol requires the conformance sentence once, near the head.

**Resolution.** Name the document for what it is — an ADR set amending SPEC-016 —
and give it an identity that does not collide. Add the Orientation block and run
the comprehension gate on it. Add the BCP 14 sentence.

### V-11 — a breaking change to an `implemented` spec, folded in place

[[SPEC-016-agent-onboarding-dx]] carries `status: IMPLEMENTED 2026-06-11`. This
document is marked `breaking: Yes`. §8 directs folding the ADRs in and bumping
`version`.

The protocol's rule for this case is explicit: when a specification changes
materially after `implemented`, create a new version rather than silently
editing, and mark the old one `superseded` with a wikilink to its successor. A
breaking change to the CLI surface and the [[local-api]] `kind` enum is material
by any reading.

**Resolution.** Either follow the supersession rule, or record an explicit,
reasoned deviation in the document. A `version` bump alone does not discharge it.

### V-12 — citation slips

Three, all minor, listed because the document's authority rests on citation
precision and because §5.3 and §9 make claims about its own rigour:

| claim | cited | actual |
|---|---|---|
| *"`:298-311` enforce `:thread` on 'all three kinds'"* (§5.3) | `specs/local-api.md:298-311` | The clause is at line **312**. Line 298 is the `message` field. |
| *"a CLI meeting an old daemon already exits `12` with a restart hint (`specs/local-api.md:140-142`)"* (§5.2) | `specs/local-api.md:140-142` | Substantively true — `ApiIncompatible` maps to `AppError::Internal` (`src/cli.rs:1390`, `src/cli.rs:1484`) and `ExitCode::Internal = 12` (`src/errors.rs:14`). The cited spec lines mention no exit code, and say "should", which carries no normative force. Cite the code. |
| *"`Message::Simple` carries `{performative, recipient, content, params, thread}`"* (§9) | `cbcl-core/src/message.rs:248-256` | The variant has **seven** fields; the range truncates at `sender` and omits `caused_by`. `sender` is the field `tell`'s `:from` populates, so the omission is not neutral. |

The `zetl` baseline in §8 was checked and is exact: 144 dead links, 0 orphans,
0 syntax errors (`zetl 0.9.3`, `zetl -d specs check --dead-links`).

### V-13 — requirement atomicity and test decomposition

Two Phase 1 quality-gate defects and one Phase 2 gap:

- **REQ-015 is not atomic.** It carries three SHALLs and four obligations —
  transmit unmodified, reject on rule (a), reject on rule (b), refuse `(meta …)`.
  The protocol requires one keyword per obligation so a failure attributes to a
  single clause. Split into four.
- **REQ-013 is not verifiable as written.** *"Every hark CLI verb whose purpose
  is to put an agent-authored CBCL frame on the wire"* leaves membership to
  judgement — §1 needs a full paragraph of prose to draw the boundary, and the
  boundary is the requirement's whole content. State the verb set extensionally,
  or state the recognition rule a `TEST-013` lint applies.
- **Test decomposition is missing its two-sided half.** §6 names positive and
  negative-input cases. REQ-014 contains a prohibition (SHALL NOT parse as CBCL)
  and REQ-015 is prohibitive throughout, so both require **prohibited-action**
  tests. REQ-015 is also side-effecting — it transmits — so it requires a
  **scope-invariant** test asserting that a rejected frame put **nothing** on the
  wire. A `send` that rejects after transmission passes every test §6 currently
  names.

---

## What the review confirms

Recorded so the next round does not re-litigate it:

- **[[SPEC-016-cli-verb-set-cbcl-merge#2. ADR-008 — A message-minting verb is named for what it produces|ADR-008]] is sound**, and the rejected alternative is rejected for the right reason. `send` is already the transport word at `src/local_api.rs:72`; promoting it to name one frame kind reproduces the overload.
- **The `emit` split is correct.** The dual contract is real: `emit_input_is_cbcl_form` (`src/cli.rs:815`) branches on a leading `(`, and the two branches reach different validators. Worth noting for the record that the dual contract was *specified*, not accidental — [[SPEC-016-agent-onboarding-dx#REQ-004]] asks for both behaviours explicitly. The document derives the defect from the code and never quotes the requirement that authorised it.
- **[[playtest-findings-2026-08-06]] FINDING-5 is cited accurately**, including the parenthetical about the composer, and `src/chat_responder.rs:153` says what the document says it says.
- **Deferring `hark ask` to OQ-006 is the right call.** It is cross-stack, and deciding it inside a hark-local ADR would bind cbcl-bus without its consent.
- **§5.2's wire claim holds.** `(lang <d> (tell @router "progress" …))` is byte-identical under `send`; this is a client-surface change.
- **Rule (a)'s primacy over rule (b) is the right ordering**, though for a weaker reason than the document gives — see [[#V-05 — the router-persistence premise is unverified cross-repo inference]].
- **The self-correction recorded in §9** — the first draft keyed on the `@router` recipient — is a genuine catch, and recording it rather than quietly fixing it is the behaviour the protocol asks for.

---

## Disposition

| # | Finding | Severity | Blocks approval |
|---|---|---|---|
| V-01 | rule (b) invalidates `hello` / `heartbeat` | Critical | yes |
| V-02 | §5.1 states the wrong mechanism | High | yes |
| V-03 | OQ-004 number collision | High | yes |
| V-04 | §9 soundness claim over-reaches | High | yes |
| V-05 | router-persistence premise unverified | High | no — mark provisional |
| V-06 | REQ-015 narrows the preserved contract | High | no |
| V-07 | drift inventory + checklist incomplete | High | no |
| V-08 | OQ-005 reintroduces the two-contract shape | High | no |
| V-09 | dialect resolution transferred unremarked | High | no |
| V-10 | identity / Orientation / BCP 14 | Medium | no |
| V-11 | breaking change to an `implemented` spec | Medium | no |
| V-12 | citation slips | Low | no |
| V-13 | atomicity + test decomposition | Medium | no |

V-01 through V-04 are corrections to the document, not redesigns. The merge
survives all four.

**Open:** V-05 needs a cbcl-bus check on router receipt persistence for a
non-`@router` progress `tell` (owner: unassigned). V-08 needs an owner decision
between ergonomics and the one-verb-one-contract rule (owner: project owner).
