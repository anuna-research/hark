# SPEC-013 / SPEC-016 — Tier-1 Human Security Sign-off Record

**Date:** 2026-06-10
**Signer:** project owner
**Subject:** [[SPEC-013-mls-private-channels]] v0.7.2 (MLS private channels) and the
Tier-1 portion of [[SPEC-016-agent-onboarding-dx]] v0.5.1 (SPAKE2 pairing handshake).
**Basis:** five rounds of adversarial review (rounds 1–2 cross-model; round 3
cross-model; round 4 confirmation; round 5 confirmation —
[[SPEC-013-round5-review-findings]]), the §10 experiment spike including the
executed R5-03 genesis-extension probe, and the structured residual walk-through
recorded here. Decisions were taken interactively by the project owner on
2026-06-10; the framing was prepared by Claude Fable 5 (the same model that
authored the v0.7 fixes — see condition K, which exists precisely because of that
conflict).

**Outcome: gate CONDITIONALLY CLEARED** — upgraded to **CLEARED for implementation
the same day**: condition K was satisfied by the round-6 GPT-5.x spot-check
([[SPEC-013-round6-spotcheck-findings]] — R5-01/02/03 confirmed, D-1/D-2
independently endorsed, no re-block). All design residuals are explicitly accepted
(A–H below); D-1 and D-2 are ratified as project-owner calls. Conditions A-t, I, J
bind inside IMPL as stated, joined by the round-6 carries **K-1** (remove-race
retry test) and **K-2** (creator-capability creation-time guard).

---

## Block 1 — Cryptographic design accepts

| # | Decision | Disposition |
|---|---|---|
| **A** | **Ed25519 key reuse** (wire envelope + MLS leaf, ADR-002/OQ-001) on the byte-disjoint domain-separation argument (envelope byte-0 `00 00 00 15‖DS_TAG` vs MLS `SignWithLabel` TLS-varint ≥ 0x10; all app DS labels distinct; bare-payload signer retired in code, R4-06). | **ACCEPTED, with condition A-t**: the no-collision property/regression test SHALL land in IMPL-013 before REQ-007 is treated as verified. |
| **B** | **First-contact TOFU + safety numbers as the Authentication Service** (ADR-006/OQ-002). An active hub CAN win any uncompared first contact; the guarantee is detection-after-comparison, not prevention. Humans may never compare; agents depend on the REQ-024 workflow. | **ACCEPTED.** |
| **C** | **Last-resort forward-secrecy residual** (REQ-022/OQ-004): a pool-draining hub forces last-resort use; captured Welcome + later init-key compromise exposes that epoch forward until the next key-updating Commit. Bounded by short `lifetime` (primitive-enforced, spike-confirmed) + replenishment. | **ACCEPTED.** |
| **D** | **At-rest compromise model** (NFR-004/OQ-005): an `identity_dir` reader obtains identity + current/future decryption; past exposure bounded by `max_past_epochs` (pruning reaches persisted state, spike-confirmed). | **ACCEPTED.** |

## Block 2 — Authority & availability accepts

| # | Decision | Disposition |
|---|---|---|
| **E** | **Creator-as-removal-authority (D-2 / R5-02)**: the room creator can unilaterally evict ANY member (not only crashed ones) — a single-party membership-shrink power, bounded by key-attribution + REQ-021(a) visibility; plus the orphaned-creator availability case (an unresponsive member whose adder and creator are gone persists in the group). | **ACCEPTED.** |
| **F** | **Hub availability powers**: drop, partition, evidence-suppression — the hub can block removals/joins/messages but can never forge membership or content. | **ACCEPTED.** |
| **G** | **Detection split** (REQ-021/R4-04 residual): transient membership equivocation between two identity-number comparisons escapes iff operators do not re-compare on a flagged membership change; tree-level forks are caught by the epoch hash + REQ-006 decrypt-failure signal. | **ACCEPTED.** |
| **H** | **Hub-served-JS limit** (REQ-023 residual): web members' security floor is the hub's code-delivery honesty; client-side pinning defends against malicious configuration, not malicious served code. The locally-installed hark agent does not share this. | **ACCEPTED.** |

## Design-call ratifications (PROPOSED → APPROVED)

- **D-1 — admission-path encryption pin** (REQ-023(a) / SPEC-016 REQ-007):
  **APPROVED.** Rationale: the hub cannot forge the client's own act of presenting
  a cap, so every hub move lands in the safe failure direction (fail-closed /
  availability), never a cleartext send. The no-cap returning-member cost (R5-07)
  is documented and accepted.
- **D-2 — creator as removal-authority liveness fallback** (REQ-014(b)):
  **APPROVED**, with the R5-02 authority expansion documented and accepted (E above).

## Block 3 — Conditions (binding, not blocking the design)

| # | Condition | Binds where |
|---|---|---|
| **A-t** | No-cross-protocol-signature-collision property/regression test (wire envelope vs `SignWithLabel` vs the `idkey`/`rekey`/`remove` DS labels). | IMPL-013, before REQ-007 verification. |
| **I** | ADR-004 durable StorageProvider: on-disk delete/fsync-fidelity test (superseded epoch secrets + consumed init keys absent from disk after merge/consume). | IMPL-013, with the provider. |
| **J** | `cbcl_ristretto` point-validation audit (SPAKE2 dependency). | **SATISFIED 2026-06-11** — audit run ([[SPEC-013-condition-J-ristretto-audit]]): no blocking finding; non-canonical/invalid encodings rejected by `ristretto255_frombytes`, K forced non-identity by the `scalarmult` zero-output check; verdict ratified by the project owner after a live re-run of the decisive probes. Carries → J-a, J-b below. |
| **J-a** | Fix the J-3 `ct-equal?` strict-`and` defect (wrong-length peer MAC must return `mac_mismatch` and bump the failed-attempt counter, not crash the handler — the N=3 deletion is a load-bearing REQ-007 control). | IMPL-016 / cbcl-bus, before `hark pair` ships. |
| **J-b** | Negative-test suite from the audit §6: K-=-identity abort, wrong-length MAC (no crash + counter bump), M/N known-answer pin. | IMPL-016 / cbcl-bus, with the handshake. |
| **K** | **Round-6 independent-model spot-check** of R5-01 (evidence epoch freshness), R5-02 (creator authority documentation), R5-03 (genesis capabilities obligation), and the D-1/D-2 endorsements — by a model that is neither Claude Fable nor Claude Opus (Principle 12; round 5 was cross-context but same-model-family). Prompt: [[SPEC-013-round6-spotcheck-prompt]]. | **SATISFIED 2026-06-10** — run on **GPT-5.x**; all three confirmed (R5-01 with the retry-cost caveat), D-1/D-2 endorsed, explicit no-re-block ([[SPEC-013-round6-spotcheck-findings]]). Carries → K-1, K-2 below. |
| **K-1** | Remove-race retry test: evidence losing an epoch race to a concurrent Commit is rejected; removal succeeds on retry with fresh evidence (auto re-mint of `bye` / re-signed remover order at the new epoch). | IMPL-013 (§9). |
| **K-2** | Creator-capability guard: assert at group-creation time that the create config advertises the genesis-extension capability — fail before the first real Commit, not at it. | IMPL-013 / `cbcl-mls-wasm` (§9, REQ-016). |
| **L** | AI Trust Boundary metadata — recorded below. | Done (this document). |

## AI Trust Boundary metadata (PROTO-001)

- **Drafting:** SPEC-013 v0.1–v0.5 and SPEC-016 v0.1–v0.3 drafted with **Claude
  Opus 4.8** (project-owner-directed dialogue).
- **Adversarial reviews:** rounds 1–3 cross-model (fresh contexts); round 4
  confirmation (fresh context); round 5 confirmation by **Claude Fable 5**
  (cross-context, NOT cross-model — the same model folded v0.6/v0.7; flagged in
  [[SPEC-013-round5-review-findings]] and compensated by condition K).
- **Fix folding:** v0.6 (round-3), v0.7/v0.7.1 (rounds 4–5), v0.7.2 (R5-03 probe
  evidence) by **Claude Fable 5**.
- **Spike evidence:** `experiments/spec-013-mls-spike` (openmls 0.8.1 pinned to
  `cbcl-mls-wasm`): R3-07 rebind-Update, R3-10 lifetime, R3-11 retention/pruning,
  NFR-001 cross-stack interop (real `.wasm`), R5-03 genesis-extension round-trip +
  fail-closed (real `.wasm` negative leg).
- **Review prompts/findings:** `docs/decisions/SPEC-013-*-review-*.md` (rounds 1–5),
  this record, and [[SPEC-013-round6-spotcheck-prompt]].
- **Decision authority:** every accept and ratification above was made by the
  project owner through an explicit per-item walk-through on 2026-06-10; the
  model framed options and recorded outcomes.

## What this sign-off does NOT cover

- The IMPL-bound verifications (A-t, I, J, K-1, K-2) — scheduled, not waived.
- The shared REQ-021(a) cross-stack test vector and the `queued_proposals()` /
  `update_path_leaf_node()` staged-inspection surface — source-confirmed only,
  exercised at IMPL-013.
- Any change to the threat model (e.g. multi-channel transport, key transparency)
  — new Tier-1 review territory.
