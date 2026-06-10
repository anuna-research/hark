# SPEC-013 — Round-4 Confirmation Review Brief (cross-model)

> Paste everything below the line into a **fresh context, ideally a different model** than
> drafted the specs (Opus 4.8) or ran round-3 (Fable 5) — Principle 12, no self-validation.
> The reviewer needs read access to `hark`, `cbcl-bus`, and `cbcl-chat`. This is the
> **round-4 confirmation**: rounds 1–2 in [[SPEC-013-design-review-findings]], round-3 in
> [[SPEC-013-round3-review-findings]].

---

## Your role

You are an **independent cryptographic and security reviewer**. Round-3 found 2 Critical + 4
High; v0.6.0/v0.6.1 of SPEC-013 and v0.4.0 of SPEC-016 claim to fold every disposition. Your
job is **not** to re-run round-3 from scratch — it is to **confirm or refute that the v0.6
revisions actually close R3-01…R3-08, and that no new gap opened between the new
requirements.** A fix that moves a hole rather than closing it is the specific thing to hunt.

**Default to skeptical.** Trace each claimed closure to a concrete, checkable mechanism in the
spec (and, where it claims to fix code, to the code). If a new REQ introduces a contradiction,
a liveness break, or a new attack surface, that is a round-4 finding. Do not soften.

## What is being reviewed (the deltas, not the whole spec again)

- **`hark/specs/SPEC-013-mls-private-channels.md` v0.6.1** — PRIMARY. Read §8 (gate) for the
  finding→REQ map, then the changed/added REQs: **REQ-023** (new, enc-mode pin), **REQ-017**
  (extended to all leaf-changing objects), **REQ-012** + **REQ-016** (bootstrap + full-tree
  pin), **REQ-014** (authenticated removal), **REQ-013** (delete ordering), **REQ-022**
  (lifetime + epoch-scope), **REQ-006** (drop-but-count), **REQ-019** (DS label), **REQ-021** +
  **REQ-024** (safety number + agent surface), **NFR-004** (retention knobs), **ADR-006**
  (re-scoped agent AS).
- **`hark/specs/SPEC-016-agent-onboarding-dx.md` v0.4.0** — REQ-007 + ADR-003 only (SPAKE2
  pairing: password-equivalent storage, pairing-specific transcript constants, failed-attempt
  bound, `enc`-mode field, release-bound-to-K).

## Provided input — the §10 spike evidence (do not re-derive; audit if you doubt it)

`experiments/spec-013-mls-spike` (openmls 0.8.1, pinned to `cbcl-mls-wasm`) already verified
the OpenMLS-primitive behaviours round-3 could not assess. Treat these as established unless
you find the spike itself wrong (the crate compiles and runs; `Cargo.lock` pins 0.8.1):

- **R3-07** — OpenMLS *accepts* a credential-rebinding self-Update (committer + peer). So
  REQ-017 clause (c) is load-bearing.
- **R3-10** — `KeyPackageIn::validate()` rejects an expired KeyPackage (`InvalidLifetime`).
- **R3-11** — `max_past_epochs`/`number_of_resumption_psks`/`sender_ratchet_configuration`
  exist; pruning is reflected in persisted secret-state.
- **NFR-001** — native OpenMLS ⇄ compiled `cbcl-mls-wasm` interoperate both directions.

The spike confirms the **primitive**, not the spec's **app-level closures**. Those are yours.

## Confirm each closure — and hunt the new gap it might open

1. **R3-05 / REQ-023 (enc-mode pin).** Does pinning the mode actually deprive the hub of the
   downgrade? Trace the pin source: operator intent / pairing-record `enc` / TOFU. **New-gap
   hunt:** first-contact has no prior pin — can the hub serve `:enc false` at the *first* join
   so TOFU pins cleartext? Does REQ-023 force a fail-closed default for an *unknown* channel,
   or does "first-observation TOFU of the mode" let the hub win the first observation exactly
   as the handle-squat does? Is the web client's local-storage pin evictable by the hub?

2. **R3-07 / REQ-017 (every leaf-changing object).** Given the spike proof that Update rebinds
   are accepted by OpenMLS, does REQ-017's clause (c) actually catch *all* of them — Update
   proposal, Remove, AND the committer's own UpdatePath leaf in a Commit? **New-gap hunt:**
   does clause (c) over-block the *legitimate* flagged key-rotation (REQ-011) — i.e. is there a
   consistent rule that admits an authorised rotation but rejects a silent rebind, or do they
   collide? What about a GroupContextExtensions or reinit path?

3. **R3-08 / REQ-012 + REQ-016 (bootstrap + full-tree pin).** Is the genesis assertion
   (`(genesis @room :creator @h …)`, REQ-019-style) actually unforgeable by the hub at first
   contact, or does it reduce to the same TOFU race? Is "first-group-wins + mandatory safety
   number" honestly stated as the fallback? **New-gap hunt:** REQ-012(d) requires the joiner to
   reject a tree with an unpinned key for a *pinned* handle — but at first contact there are no
   pins, so does the all-first-contact path create a join deadlock or a silent downgrade to
   "trust the tree"? Does the creator-handle recorded at `claim` (hub-side state) become a new
   hub-trusted input that re-introduces the very hub authority REQ-016 removes?

4. **R3-06 / REQ-014 (authenticated removal).** Does requiring a signed `bye` or adder-auth
   removal close hub-driven eviction without breaking *liveness* (a crashed member who can
   never send a signed `bye`)? **New-gap hunt:** can a malicious *member* now suppress a
   legitimate removal, or forge a `bye` for someone else (is the `bye` bound to the subject's
   key, not the sender's)?

5. **R3-01/R3-02 / ADR-006 + SPEC-016 REQ-007 (agent AS re-scope).** Is the spec now internally
   consistent that SPAKE2 is capability-only and agent identity is TOFU+safety-number? Check
   for leftover text anywhere still calling the pairing the agent AS. **New-gap hunt:** REQ-024
   gives the agent a safety-number surface — but a headless agent's operator comparing it
   out-of-band is the same human step that may never happen; does the spec over-credit REQ-024?
   Is the `enc`-field now in the pairing record itself authenticated (release-bound-to-K), or
   can the hub strip/alter it (feeding back into R3-05)?

6. **R3-13 / REQ-021 (safety number over epoch authenticator).** Confirm the chosen binding
   object (group_id + epoch + tree hash / epoch authenticator) is one **both** the hark and web
   clients can compute identically and is stable across the comparison window. **New-gap hunt:**
   does binding to `epoch` mean the safety number changes every Commit, making out-of-band
   comparison impractical (a usability failure that nullifies the only first-contact defence)?

7. **Cross-REQ consistency.** REQ-006 (drop-but-count fork signal) ↔ REQ-021 (safety number) ↔
   REQ-012 all-first-contact path — do they form a coherent detection story, or can a hub keep
   a victim below every threshold? Does REQ-013's delete-after-successful-join ordering interact
   badly with REQ-017 (a proposal stored, then a later Commit rejected — is the init key state
   well-defined across that)?

## Also look for

- **Anything v0.6 marks closed that the threat model says isn't** — especially first-contact.
- **Self-contradictions** introduced by the new REQs against the scope section or each other.
- **Requirements unimplementable on the actual wire** (round-2's BUG-010 shape) — e.g. does the
  genesis assertion or the enc-mode pin require a frame the wire does not carry?
- **OQ-001** — the bare-payload signer retirement condition: is it actually scheduled, or still
  a live raw-bytes signing oracle on the identity key?

## Output format

Per finding: **ID + severity** (Critical/High/Medium/Low; Critical = breaks confidentiality or
authenticity under the threat model) · **Where** (`file:line` / `REQ/ADR/OQ-###`) · **the attack
or defect** (concrete attacker, action, gain) · **disposition** · **whether it is a regression
of a v0.6 fix, a brand-new gap the fix opened, or an unclosed round-3 item.**

Then a **verdict**, explicitly one of:

- **Gate may clear** (subject to human crypto sign-off) — only if no Critical/High survives that
  the design doesn't already track, AND you list the residual risks the human signer must accept
  (start from: first-contact TOFU winnable by the hub; last-resort forward-secrecy residual; hub
  fan-out availability; durable-provider on-disk delete fidelity; `cbcl_ristretto` validation).
- **Gate stays BLOCKED** — with the must-fix list.

End with **what you could NOT assess**, so the human sign-off knows the boundary of this round.
