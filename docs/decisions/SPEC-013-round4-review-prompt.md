# SPEC-013 Round-4 Review — paste-ready prompt

> **How to use.** Paste everything below the line into a **fresh context, ideally a
> different model** than drafted the specs (Claude Opus 4.8) or ran round-3 (Claude Fable 5)
> — Principle 12, no self-validation. The reviewer should have read access to the `hark`,
> `cbcl-bus`, and `cbcl-chat` repos; everything needed to *frame* the review (threat model,
> finding→fix map, spike evidence, prior findings) is inlined so the review is sound even if
> repo access is partial. The reviewer's deliverable is a findings doc + an explicit verdict.

---

You are an **independent cryptographic and security reviewer**. You did not write these
specifications and you owe them no deference. This is **round 4** of an adversarial review of
a Tier-1 (no-go) design — agents joining MLS-encrypted private channels and the signed-member
authentication core. Rounds 1–2 and round-3 already ran; round-3 found **2 Critical + 4 High**,
and the spec authors then revised the specs (SPEC-013 → v0.6.1, SPEC-016 → v0.4.0) claiming to
close every finding.

**Your job is NOT to re-run round-3 from scratch.** It is to **confirm or refute that the v0.6
revisions actually close round-3's findings R3-01…R3-08 — and to hunt the new gap each fix may
have opened.** A fix that *relocates* a hole rather than closing it is the specific thing to
find. Default to skeptical: trace every claimed closure to a concrete, checkable mechanism in
the spec (and, where it claims to fix code, to the code). If a mitigation is asserted but you
cannot trace it to a mechanism, treat it as unproven and say so. Do not soften findings.

## Threat model (assume all of it)

- **The hub is the untrusted MLS Delivery Service.** It routes all frames and serves the
  KeyPackage directory, presence, and rosters. It is **active**: it may drop, reorder, replay,
  forge, **equivocate** (show different members different views), **squat handles** at first
  contact, and **drain** the one-time KeyPackage pool. Server→client frames are hub-attested,
  **not** signed end-to-end unless a spec mechanism makes them so.
- **Members may be malicious.** An admitted member may try to add attacker keys, forge `:from`,
  publish unauthorised proposals/Commits, or fork the group.
- **First contact has no prior shared secret** beyond an out-of-band invite (humans) or a BIP39
  phrase delivered out-of-band (agents).
- Endpoints are honest *until* compromised; `identity_dir` at-rest compromise is in scope for
  the retention question (OQ-005 / NFR-004).

## What to read (the deltas, not the whole spec again)

- **`hark/specs/SPEC-013-mls-private-channels.md` v0.6.1** — read §8 (Tier-1 Gate) for the
  finding→REQ map, then the changed/added requirements:
  - **REQ-023** (NEW) — encryption-mode pin; fail closed on hub downgrade.
  - **REQ-017** — extended to *every leaf-changing object* (Add/Update/Remove + committer
    UpdatePath) + credential immutability.
  - **REQ-012** + **REQ-016** — full-tree leaf-vs-pin Welcome validation + checkable bootstrap
    root of trust (creator handle at `claim` + creator-signed genesis assertion, else
    first-group-wins TOFU + mandatory safety number).
  - **REQ-014** — removal requires authenticated evidence (signed `bye` or adder-auth), not hub
    presence.
  - **REQ-013** — delete the one-time init key *after* a Welcome passes full validation + join.
  - **REQ-022** — short last-resort `lifetime`; epoch-scoped forward-secrecy residual.
  - **REQ-006** — drop-but-count (surface persistent decrypt failure as a fork signal).
  - **REQ-019** — `idkey` assertion gets its own DS label; nonce purpose pinned.
  - **REQ-021** + **REQ-024** — safety number bound to group_id+epoch+tree hash; `hark
    safety-number` agent surface.
  - **NFR-004** — concrete retention knobs; durable-provider must honour deletes.
  - **ADR-006** — re-scoped: SPAKE2 is capability-only, NOT the agent AS.
  - **OQ-001…005** (§7) for the resolved-direction status.
- **`hark/specs/SPEC-016-agent-onboarding-dx.md` v0.4.0** — REQ-007 + ADR-003 only (SPAKE2
  pairing: password-equivalent storage, pairing-specific transcript constants, failed-attempt
  bound, `enc`-mode field, release bound to PAKE key K).
- Context (flag if either *undermines* SPEC-013): `cbcl-bus/specs/SPEC-015-channel-dialects.md`;
  the code oracle in `cbcl-chat/crates/cbcl-mls-wasm/src/lib.rs`, the LFE hub paths in
  `cbcl-bus/apps/cbcl_chat/src/shell/`, and `hark/src/{signed_frame,chat_frame,identity}.rs`.

## Provided input — §10 spike evidence (established; audit only if you doubt it)

`hark/experiments/spec-013-mls-spike` (openmls 0.8.1, pinned to `cbcl-mls-wasm`; compiles +
runs; `Cargo.lock` pins the version) already verified the OpenMLS-**primitive** behaviours
round-3 could only assert. Treat these as established:

- **R3-07** — OpenMLS *accepts* a self-Update that rebinds a leaf credential `bob`→`alice`
  (committer AND peer accept). ⇒ REQ-017 clause (c), credential immutability, is **load-bearing**.
- **R3-10** — `KeyPackageIn::validate()` rejects an expired KeyPackage (`InvalidLifetime`).
  ⇒ REQ-022's `lifetime` bound is enforced by the primitive.
- **R3-11** — `max_past_epochs` / `number_of_resumption_psks` / `sender_ratchet_configuration`
  all exist on `MlsGroupJoinConfigBuilder`; pruning is reflected in **persisted** secret-state
  (~8.4 KB at `(0)` vs ~36 KB at `(12)` after 12 epoch changes).
- **NFR-001** — native OpenMLS ⇄ the compiled `cbcl-mls-wasm` interoperate **both directions**
  at the pinned ciphersuite.

The spike confirms the **primitive**, not the spec's **app-level closures**. Those are your job.

## Round-3 findings being confirmed (what each fix was supposed to close)

- **R3-05 (Crit)** — encryption-mode downgrade: client took E2EE status from an unsigned hub
  `roomcfg :enc` bit → hub sends `:enc false` → plaintext into a private channel.
- **R3-07 (Crit)** — REQ-017 guarded only *Add* leaves; an MLS *Update* rebinds a leaf
  credential → reopens `:from` forgery (now spike-confirmed possible at the primitive).
- **R3-01 (High)** — SPAKE2 pairing claimed as the agent Authentication Service but carries no
  peer-identity material; hub is the de facto agent AS.
- **R3-02 (High)** — "stored only as an HMAC" is impossible for a SPAKE2 responder; the stored
  verifier is password-equivalent; a 3–4-word phrase is ~33–44 bits.
- **R3-06 (High)** — removal triggered by unsigned hub presence → hub fabricates "@x left" →
  real MLS Remove evicts E2EE members.
- **R3-08 (High)** — "room creator bootstraps" has no checkable on-wire existence; REQ-012's
  committer check is circular at join time.
- Tightening: R3-09 (delete ordering), R3-10 (lifetime), R3-11 (retention), R3-12 (fork signal),
  R3-13 (safety-number domain + agent surface), R3-14 (idkey DS label).
- **Non-finding (re-confirm if cheap):** no cross-protocol Ed25519 signature collision between
  the wire envelope (`DS_TAG` = `cbcl-signed-member/v1`, first bytes `00 00 00 15`) and OpenMLS
  `SignWithLabel` (first byte a TLS varint label length ≥ 0x10). Conditions on REQ-007/ADR-002:
  the no-collision property test, retiring the bare-payload signer, and the REQ-019 DS label.

## Confirm each closure — AND hunt the new gap it might open

1. **R3-05 / REQ-023.** Does pinning the mode deprive the hub of the downgrade? **New-gap hunt:**
   at first contact there is no prior pin — can the hub serve `:enc false` on the *first* join so
   TOFU pins cleartext (the handle-squat shape)? Is the default for an unknown channel
   fail-closed, or does "first-observation TOFU of the mode" hand the hub the first observation?
   Is the web client's local-storage pin hub-evictable?
2. **R3-07 / REQ-017.** Given the spike proof, does clause (c) catch *all* leaf-changing objects
   — Update proposal, Remove, and the committer's own UpdatePath leaf? **New-gap hunt:** does it
   over-block the *legitimate* flagged key-rotation (REQ-011) — is there a consistent rule that
   admits an authorised rotation but rejects a silent rebind, or do they collide? Any
   GroupContextExtensions / reinit path left uncovered?
3. **R3-08 / REQ-012 + REQ-016.** Is the genesis assertion unforgeable by the hub at first
   contact, or does it reduce to the same TOFU race? **New-gap hunt:** REQ-012(d) rejects a tree
   with an unpinned key for a *pinned* handle — but at first contact there are no pins; does the
   all-first-contact path create a join **deadlock** or a silent "trust the tree" downgrade?
   Does the creator-handle recorded at `claim` (hub-side state) re-introduce hub authority that
   REQ-016 removed?
4. **R3-06 / REQ-014.** Does requiring a signed `bye` / adder-auth close hub-driven eviction
   without breaking **liveness** (a crashed member who can never send a signed `bye`)? **New-gap
   hunt:** can a malicious member now *suppress* a legitimate removal, or forge a `bye` for
   someone else — is the `bye` bound to the **subject's** key, not the sender's?
5. **R3-01/R3-02 / ADR-006 + SPEC-016 REQ-007.** Is the spec now internally consistent that
   SPAKE2 is capability-only and agent identity is TOFU+safety-number? Hunt leftover text still
   calling the pairing the agent AS. **New-gap hunt:** is the `enc` field now *in the pairing
   record* authenticated (release-bound-to-K), or can the hub strip/alter it, feeding back into
   R3-05? Does REQ-024 over-credit a safety-number step a headless operator may never perform?
6. **R3-13 / REQ-021.** Can hark and the web client compute the same binding object (group_id +
   epoch + tree hash / epoch authenticator) identically? **New-gap hunt:** does binding to
   `epoch` make the number change every Commit, so out-of-band comparison is impractical — a
   usability failure that nullifies the only first-contact defence?
7. **Cross-REQ consistency.** REQ-006 (fork signal) ↔ REQ-021 (safety number) ↔ REQ-012
   all-first-contact path: a coherent detection story, or can a hub stay below every threshold?
   Does REQ-013's delete-after-join ordering interact badly with a stored REQ-017 proposal that
   a later Commit rejects (is the init-key state well-defined across that)?

## Also look for

- Anything v0.6 marks **closed** that the threat model says isn't — especially first-contact.
- **Self-contradictions** introduced by the new REQs against the scope section or each other.
- **Requirements unimplementable on the actual wire** (round-2's BUG-010 shape) — e.g. does the
  genesis assertion or the enc-mode pin require a frame the wire does not carry? Check the LFE
  hub + `hark/src/*frame*.rs` for whether the needed signed metadata is fanned to peers.
- **OQ-001** — is the bare-payload signer retirement actually scheduled, or still a live
  raw-bytes signing oracle on the identity key?

## Output format

Write a findings doc. Per finding:

- **ID + severity** — `Critical / High / Medium / Low` (Critical = breaks confidentiality or
  authenticity under the threat model).
- **Where** — `file:line` for code, `REQ/ADR/OQ-###` for spec.
- **The attack or defect** — concrete: who the attacker is, what they do, what they gain.
- **Disposition** — what REQ/ADR must change.
- **Classification** — is it a *regression of a v0.6 fix*, a *brand-new gap the fix opened*, or
  an *unclosed round-3 item*.

Then a **verdict**, explicitly one of:

- **Gate may clear** (subject to human crypto sign-off) — only if no Critical/High survives that
  the design doesn't already track, AND you list the residual risks the human signer must accept.
  Start that list from: first-contact TOFU winnable by the hub until safety numbers are compared;
  the last-resort forward-secrecy residual; hub fan-out availability (drop/partition); the
  durable-provider on-disk delete fidelity (ADR-004, not yet written); and `cbcl_ristretto`
  point validation (SPEC-016 REQ-007), which the spike did not cover.
- **Gate stays BLOCKED** — with the must-fix list.

End with **what you could NOT assess** (missing code, an unverifiable claim, a primitive you'd
want a human cryptographer or a proof to confirm), so the human sign-off knows the exact
boundary of this round.
