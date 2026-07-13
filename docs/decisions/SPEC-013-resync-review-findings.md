---
id: SPEC-013-resync-review-findings
title: SPEC-013 v0.9.0 — Principle-12 review of the fork-recovery (resync) additions
status: folded (v0.9.1)
tier: 1
last-updated: 2026-07-13
---

# SPEC-013 v0.9.0 resync additions — adversarial review findings

Fresh-context, defect-seeking review of the four normative artefacts the v0.9.0 draft added
for the [[SPEC-013-mls-private-channels#REQ-025|resync]] fork-recovery protocol — REQ-025,
REQ-026, ADR-007, OQ-006 — traced against the shipped web implementation
(`cbcl-bus apps/cbcl_chat/priv/web/mls.js`). Mandated by [[PROTO-001]] Principle 12 (an
artefact is not validated by the session that produced it).

## AI detection context ([[PROTO-001]] AI Trust Boundaries)

- **Generating model:** Claude Fable 5 (v0.9.0 draft, this session).
- **Reviewing model:** Claude (fresh general-purpose sub-agent), **same family** — so
  independence is **cross-context, not cross-model**. A **cross-model** pass is still
  REQUIRED before REQ-025/026 leave normative-DRAFT (recorded in the v0.9.1 changelog).
- **Method:** spec + the four artefacts + the reference `mls.js` only; mandate to find defects
  across ambiguity/atomicity, security (attack as the untrusted hub / malicious member),
  contradiction, and faithfulness-to-implementation.
- **Disposition:** all eight findings **accepted and folded into v0.9.1**.

## Findings (severity uses a crypto-spec lens; all CONFIRMED against the code)

| # | Sev | Artefact | Defect | Fold (v0.9.1) |
|---|-----|----------|--------|---------------|
| **F1** | High | REQ-026 / OQ-006 | The v0.9.0 `:resync` frame was **unsigned**; a hub could forge one for a live victim and drive a real [[SPEC-013-mls-private-channels#REQ-014]] Remove. Forge the resync **and** drop the re-add Welcome → **durable committed eviction** of a healthy member — re-opens the REQ-014 "fabricated leave → eviction" vector OQ-006 mis-scoped as "availability-only churn". | Auth upgraded SHOULD→**SHALL**: [[SPEC-013-mls-private-channels#REQ-025]](b) signs the request (REQ-019 machinery), [[SPEC-013-mls-private-channels#REQ-026]](a) verifies **before** minting evidence. OQ-006 rewritten. |
| **F2** | High | OQ-006 / REQ-025 | A hub that equivocates Commit order forks an **honest** member; each heal consumes a one-time [[KeyPackage]] → drain to the [[SPEC-013-mls-private-channels#REQ-022]] last-resort key → **weakened forward secrecy**. `RESYNC_CAP` resets on each success, so churn is unbounded over time. "Availability-only" understated. | `RESYNC_RATE` creator-side bound as SHALL ([[SPEC-013-mls-private-channels#REQ-026]](e)); member SHOULD replenish the pool on resync; OQ-006 states the FS linkage. |
| **F3** | Med-High | REQ-026 vs REQ-004/016 | Heal needs the re-provisioner to be **both** creator (mints evidence) and elected owner (commits); the code enforces both. Any group admitting a member lexicographically before the creator shifts the elected owner away → heal **never** available there. Never stated. | [[SPEC-013-mls-private-channels#REQ-026]](b) states the creator∧elected-owner precondition; divergent case falls to manual re-entry (deferred, [[SPEC-013-mls-private-channels#ADR-007]]). |
| **F4** | Med | REQ-025 vs impl | The bounded-retry/terminal machinery is **unreachable dead code**: after `dropGroup` the member is groupless, no more decrypt failures accrue, so `resyncAttempts` maxes at 1 and `terminal` never fires — one-shot-then-silence, not retry-then-terminal. A dropped re-add Welcome leaves the member silently dead. | [[SPEC-013-mls-private-channels#REQ-025]](c) rewritten as re-request-while-groupless-on-timeout → terminal, reachable; cbcl-bus dead-code bug filed at [[#F4]] below. |
| **F5** | Med | REQ-026 (atomicity) | Remove-then-add is **non-atomic** with no rollback: if the re-add fails (stale pin after a legit [[SPEC-013-mls-private-channels#REQ-011]] rotation whose `rekey` was dropped; keyget MISS; pool exhausted) the victim is **evicted with no re-add**. | [[SPEC-013-mls-private-channels#REQ-026]](c) mandates **validate-then-remove-then-add**: no Remove unless a pin-valid KeyPackage is already in hand. |
| **F6** | Med | TEST-026 vs impl | The v0.9.0 test claimed a resync for a non-member is "ignored"; the code **falls through to a routine Add** (`requestAdd`). Test would fail against the implementation. | TEST-026 negative-input corrected ([[SPEC-013-mls-private-channels#REQ-026]](d)): no *remove-then-add*; a routine Add is acceptable. |
| **F7** | Med | REQ-025/026 (PROTO-001) | Unmeasurable predicates ("fork threshold", "small attempt cap") + ~6 bundled obligations per REQ defeat single-clause failure attribution. | Named constants `FORK_THRESHOLD=3`, `RESYNC_CAP=3`, `RESYNC_RATE=3`; obligations split into lettered atomic clauses (a)–(e). |
| **F8** | Med | REQ-025(a) vs impl | "Fully discard … including the provider's persisted storage" over-claims — the web code discards only **group-scoped** records (`g.discard`). A literal hark impl wiping the whole provider destroys its own unconsumed [[KeyPackage]] init keys → the re-admission Welcome becomes undecryptable → resync **permanently bricks**. | [[SPEC-013-mls-private-channels#REQ-025]](a) scoped to the `group_id`'s records; identity keystore + unconsumed init keys explicitly **preserved**. |

**Axes that yielded nothing real (recorded, not padded):** downgrade-via-discard (the
[[SPEC-013-mls-private-channels#REQ-023]] mode pin persists independently of MLS state, so
discard→rejoin cannot be steered to plaintext); attacker-key seating via forged resync
(the re-add runs full [[SPEC-013-mls-private-channels#REQ-008]] pin validation — impossible).
OQ-006's confidentiality/authenticity claim holds for **key-seating**; what it understated was
the **eviction** (F1) and **FS-erosion** (F2) impact.

## Re-review of the v0.9.1 folds (#1–#5, folded in v0.9.2)

A second fresh-context adversarial pass (Claude, different tier — still **same family**;
a cross-vendor pass remains outstanding) reviewed the v0.9.1 folds against the shipped
code. Findings, all folded into v0.9.2:

| # | Sev | Defect | Fold (v0.9.2) |
|---|-----|--------|---------------|
| **#1** | High | The F1 signature closed forgery but **not replay**: the resync nonce was the signer's pin epoch (constant absent a rotation) and nothing tracked a last-seen value, so the hub could **capture a genuine signed `:resync` and replay it** to evict a healthy member. | **Fixed + deployed + tested.** Requester nonce made strictly-monotonic ([[SPEC-013-mls-private-channels#REQ-025]](b)); creator rejects a nonce ≤ the last honored for that handle ([[SPEC-013-mls-private-channels#REQ-026]](a)). cbcl-bus `9bb7848` (`nextResyncNonce` + `lastResync`); integration scenario **S6** captures-and-replays a genuine resync and asserts zero second Removes. |
| **#2** | Med-High | `RESYNC_RATE` "per (member, epoch-window)" is self-resetting — each honored resync bumps the epoch, so the window resets on its own trigger and the bound is vacuous. | [[SPEC-013-mls-private-channels#REQ-026]](e) redefined to a **wall-clock** window (or epoch-independent counter). Enforcement is a follow-on (the web does not yet rate-limit; #1's monotonic nonce already blocks the replay path). |
| **#3** | Med | Remove-then-add is non-atomic: `key_package_addable` is not a full dry-run, so a merged+fanned Remove followed by an Add that fails for an MLS-level reason cannot be rolled back. | [[SPEC-013-mls-private-channels#REQ-026]](c) now states the residual explicitly; the [[SPEC-013-mls-private-channels#REQ-025]](c) bounded retry/terminal is the backstop; single-Commit remove+add is the SHOULD upgrade. |
| **#4** | Low | REQ-025(b) duplicated REQ-026(a)'s verifier obligation (atomicity). | The verifier obligation now lives solely in [[SPEC-013-mls-private-channels#REQ-026]](a); REQ-025(b) states only the requester's signing/nonce obligation. |
| **#5** | Low | The retry wait had no named constant. | Named `RESYNC_WAIT_MS` in [[SPEC-013-mls-private-channels#REQ-025]](c). |

The re-review **confirmed F3/F4/F8 correct** and ruled out attacker-key seating via the
replay path (the re-add stays [[SPEC-013-mls-private-channels#REQ-008]]-pin-validated —
replay forces churn/eviction, never key substitution).

## F4 — cbcl-bus bug (dead terminal path)

`mls.js` `onDeliver` fork path drops the group at `n >= FORK_THRESHOLD`; thereafter the member
is groupless (`if (!g) return null`), so no further failures accrue and `resyncAttempts` cannot
exceed `RESYNC_CAP` — the `terminal` branch never fires and a dropped re-admission Welcome yields
silent death, not the operator-visible terminal the design intends. **Fix:** drive resync retry
on a groupless timeout (not on further decrypt failures), bounded, then surface terminal. To be
filed as a numbered BUG against cbcl-bus and fixed in the resync-hardening pass.
