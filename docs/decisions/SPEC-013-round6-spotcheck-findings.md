# SPEC-013 Round-6 Spot-Check — Findings (condition K)

**Date:** 2026-06-10
**Reviewer:** GPT-5.x (OpenAI) — fresh context, non-Anthropic, per Principle 12 and
[[SPEC-013-tier1-signoff]] condition K (round 5 was same-model-family as the fix author).
**Prompt:** [[SPEC-013-round6-spotcheck-prompt]].
**Scope:** the three round-5 closures the same-model reviewer confirmed (R5-01, R5-02,
R5-03) + independent endorsement of the two design calls (D-1, D-2).

**Outcome: CONDITION K SATISFIED.** No re-block; two carries bound into IMPL tests
(below). The gate moves from CONDITIONALLY CLEARED to **CLEARED for implementation**
(IMPL-bound conditions A-t, I, J unchanged).

---

## Verdicts (reviewer's findings, verbatim)

### Check 1 — R5-01: CLOSED WITH CAVEAT

> Exact epoch, no tolerance window closes the stale-evidence replay, including re-add:
> prior bye/remover evidence is for an old epoch and old leaf. The binding set is
> sufficient if "current leaf" means the concrete MLS leaf identity, not only handle.
>
> Caveat: concurrent/remapped MLS commits still need retry/rebase behavior. If evidence
> minted at epoch N loses a race to another Commit and validators are now at N+1,
> rejection is correct. Honest removal then needs fresh evidence from the subject or an
> authorized remover. That is an availability/retry cost, not a replay hole.

### Check 2 — R5-02: CONFIRMED CLOSED

> The text now states the real grant: creator can evict any member. The surrounding spec
> also repeats that this is unilateral eviction authority, so I do not see a surviving
> liveness-only implication.
>
> The bounds are basically true: creator evidence is attributable if signed under the
> removal DS label by the pinned creator key, and eviction is membership-visible because
> it changes the member set and therefore the identity safety number. A malicious creator
> plus hub can cause availability/integrity harm, partitioning, and first-contact TOFU
> attacks, but I do not see a path from this removal authority alone to silent
> attacker-key addition or confidentiality break after pins/Welcome validation are
> enforced.

### Check 3 — R5-03: CONFIRMED CLOSED

> Given the stated probe evidence, the durable delivery mechanism is sound: genesis in
> GroupContext reaches joiners through the MLS-authenticated Welcome, can be inspected
> pre-finalize, and remains immutable if GroupContextExtensions/ReInit/external joins are
> rejected by the allowlist.
>
> The capability requirement is an interop break for old/default clients, but it is
> flagged and fail-closed is the right direction. The delayed creator-side failure is
> adequately handled at spec level by requiring create config capabilities plus a
> negative test; implementation should still add a local guard/assert so bad creator
> config fails before first real Commit.

### D-1 — ENDORSE

> The load-bearing failure direction holds: a locally honest client pins enc=true from
> its own cap/invite presentation before first send. The hub can strip/suppress and cause
> fail-closed, or lie in roomcfg, but cannot turn that path into plaintext without
> controlling the client code. The web-served-JS residual remains real and documented.

### D-2 — ENDORSE

> Creator unilateral eviction is a serious authority grant, but it is now documented as
> such and bounded to attributable, membership-visible shrink authority. I endorse it as
> an accepted design call, not as a cryptographic necessity.

### Re-block?

> No, nothing here rises to a new design blocker. Carry the Check 1 retry/rebase behavior
> and Check 3 creator-capability guard into IMPL tests.

### Could not assess

> Actual production implementation conformance, UI surfacing of safety-number changes,
> and whether deployed web code preserves the cap-before-send invariant.

— all three are implementation-conformance items, exactly what IMPL-013's TEST trace and
the [[SPEC-013-tier1-signoff]] IMPL conditions exist to cover; none touches the design.

---

## Dispositions (folded into SPEC-013 v0.8.1)

- **K-1 (from Check 1)** — REQ-014 clarified: the evidence's "leaf" binding is the
  **concrete MLS leaf** (leaf index + leaf signature key at the evidence epoch), not the
  handle alone; and the race behaviour is named — evidence that loses an epoch race to a
  concurrent Commit is correctly rejected and removal is **retried with fresh evidence**
  (availability/retry cost, documented; subject `bye` retry is automatic re-mint by the
  leaving client; remover-path retry re-signs at the new epoch). §9 gains an IMPL test:
  the remove-race retry path.
- **K-2 (from Check 3)** — §9/§10 gain an IMPL guard: hark and the web client SHALL
  assert at group-creation time that the create config carries the genesis-extension
  capability (fail before the first real Commit, not at it).
- **D-1/D-2** — independent endorsements recorded; the [[SPEC-013-tier1-signoff]]
  ratifications stand un-reopened.
- **Gate** — condition K satisfied; [[SPEC-013-tier1-signoff]] updated; SPEC-013
  review-gate → **CLEARED for implementation** (A-t, I, J remain bound inside
  IMPL-013/IMPL-016).
