---
id: IMPL-018
title: cbcl-bus MLS Interop — closing the SPEC-013 web-side gaps
status: draft
tier: 1
version: 0.1.0
audience: agent, human
author: Anuna Research (drafted with Claude Fable 5)
last-updated: 2026-07-10
spec: SPEC-013
owner-repo: cbcl-bus
affects-repos: cbcl-bus (hub + web client + in-repo cbcl-mls-wasm crate + vendored artifact)
---

# IMPL-018 — cbcl-bus MLS Interop

Implementation plan for the **cbcl-bus side** of [[SPEC-013-mls-private-channels]]. hark's
side (IMPL-013) is complete and live-verified; this plan closes the four interop-breaking
gaps and the lockstep security gaps that [[SPEC-013-cbcl-bus-interop-gap-review]] found,
so a `hark` agent and a web member can share one encrypted private channel. It is the
successor to the vanished `cbcl-chat.spl` `mls-review` gate (gap review BK-2).

## Orientation

Intent:      Make the cbcl-bus web client and hub speak SPEC-013 MLS the way hark already
             does — genesis-bearing groups, pinned identities, validated membership
             changes, a comparable safety number — so agent↔web encrypted channels form
             and stay authentic. hark is the **test oracle**; this plan changes only
             cbcl-bus.
Metaphor:    Fit the second half of a key already cut. hark cut the wire format; cbcl-bus
             must be milled to the same teeth — every acceptance test is "does the web
             side produce/accept exactly the bytes hark's shipped tests expect."
Structure:
```
   ┌─────────────── cbcl-bus ───────────────┐        oracle
   │ web client (app.js / mls.js)           │      ┌─────────┐
   │   ├─ genesis on create      (IG-1) ────┼────▶ │  hark   │
   │   ├─ idkey emit + pin store  (IG-2)    │      │  IMPL-  │
   │   ├─ safety number           (IG-4) ───┼────▶ │  013    │
   │   └─ mode pin / UI claim  (LG-5/8)     │      │ tests + │
   │ cbcl-mls-wasm crate                    │      │ vectors │
   │   ├─ REQ-017 validation layer (LG-1)   │      │ = spec  │
   │   ├─ removal evidence         (IG-3)   │      └─────────┘
   │   └─ single-use ledger        (LG-6)   │
   │ hub (LFE)                              │
   │   └─ keypub/keyget validation (LG-7)   │
   └─────────────────────────────────────────┘
   later: MLS verbs as a SPEC-015 dialect (D-3), cbcl-rs pin bump (DR-1)
```
Decisions:   [[SPEC-013-cbcl-bus-interop-gap-review#D-3]] MLS verbs ship as a content-hashed
             CBCL dialect · genesis-signing seam lives **in the crate** (it holds the
             `SignatureKeyPair`) — RESOLVED, task-genesis · idkey signing/verification also
             **in the crate** for byte-parity — RESOLVED, task-pins-idkey · the web pin
             store is a JS map persisted to **localStorage** (pins are public keys =
             integrity state, not secret material, so not the IndexedDB secret store) —
             RESOLVED, task-pins-idkey.
Load-bearing: [[SPEC-013-mls-private-channels#REQ-016]] genesis · [[SPEC-013-mls-private-channels#REQ-008]]/[[SPEC-013-mls-private-channels#REQ-011]] pins · [[SPEC-013-mls-private-channels#REQ-017]] inbound validation · [[SPEC-013-mls-private-channels#REQ-021]] safety number.
Open:        (task-genesis and task-pins-idkey design questions resolved above.)
Detail:      [[SPEC-013-cbcl-bus-interop-gap-review]], [[SPEC-013-mls-private-channels]], [[IMPL-013-trace]].

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED,
MAY, and OPTIONAL are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when,
and only when, they appear in all capitals.

## Tier-1 note

This plan touches the same [[MLS]] E2EE + authentication core as [[SPEC-013-mls-private-channels]].
The **design gate is already CLEARED** ([[SPEC-013-tier1-signoff]], 2026-06-10) — no new
cross-model review is required to begin. Each task below carries the spec's verification
obligations; the whole-suite gate is task-interop (a live hark↔web round-trip), and the
adversarial-review obligation (Principle 12) attaches to task-validation's fresh-context
review before it is marked complete.

## Architecture & key decisions

The controlling constraint is **NFR-001 wire-byte compatibility**: hark's shipped
implementation is the normative byte layout for every object, so the crate/web work
implements *against fixed targets*, not a fresh design. Concretely:

- **Genesis (IG-1).** The genesis-signing seam belongs in `cbcl-mls-wasm` (Simplicity
  Ladder rung 4→5: the crate already holds the `SignatureKeyPair`; exposing
  `Group::create(provider, identity, genesis_signed_bytes)` or an internal `sign_genesis`
  is a few lines, versus threading raw signing keys out to JS — which would also duplicate
  the DS-label logic and violate "one signer context"). The signed-context byte layout is
  hark's `genesis_signing_bytes` (`src/mls/group.rs:84`).
- **Pins (IG-2/LG-2).** A handle→wire-key pin store is the substrate LG-1..4 all need; it
  lives in IndexedDB beside the existing `cbcl-e2ee` identity store (rung 3: the platform
  store already exists). Pins are set only from verified `cbcl-idkey-assert/v1` self-signed
  frames — never hub-asserted (REQ-011).
- **Validation (LG-1).** `Group::process` (`crates/cbcl-mls-wasm/src/lib.rs:288`) is
  rewritten to inspect every leaf-changing object against pins + the REQ-017(a-e) allowlist
  before merge, and to return the authenticated sender leaf so JS can enforce REQ-018. This
  is the single largest change and the one carrying the Principle-12 review.
- **Dialect (D-3).** Deferred until the versioned cbcl-rs release (DR-1). When it lands, the
  MLS wire verbs become a pinned SPEC-015 dialect; the dialect content hash becomes the
  cross-stack version agreement, discharging LangSec "one parser per language" by
  construction.

Nothing hark-side changes. Where the web client is structurally weaker than hark (it is
**hub-served code**, so it defends against a malicious hub *config*, not malicious JS —
[[SPEC-013-mls-private-channels#REQ-023]] residual), that residual is inherited, documented,
and out of scope here.

## Tasks (execution order = gap-review §6)

Each task's acceptance is a **hark oracle** where one exists. Per-REQ requirement-targeted
decomposition (positive / negative-input / negative-output) is REQUIRED and detailed in the
per-task acceptance in [[impl-018-cbcl-bus-mls-interop|the SPL plan]].

1. **task-genesis (IG-1, [[SPEC-013-mls-private-channels#REQ-016]]).** Web `createGroup`
   builds and passes the creator-signed genesis assertion; crate gains the signing seam and
   injects it into the GroupContext with the `0xF013` capability (K-2 already present).
   *Accept:* a web-created group's Welcome is accepted by hark's
   `create_add_join_roundtrip_with_genesis` shape (`src/mls/group.rs:722`); a genesis-less
   create is rejected by hark exactly as `src/mls/group.rs:492`.
2. **task-pins-idkey (IG-2, [[SPEC-013-mls-private-channels#REQ-019]]/[[SPEC-013-mls-private-channels#REQ-011]]).**
   Web emits `cbcl-idkey-assert/v1` on join + new-peer presence; verifies and pins inbound
   ones; pin store persisted. *Accept:* hark pins a web member from its emitted assertion and
   admits it (REQ-008 passes); a hub-substituted assertion is rejected.
3. **task-safety (IG-4, [[SPEC-013-mls-private-channels#REQ-021]]/[[SPEC-013-mls-private-channels#REQ-024]]).**
   Implement the canonical identity-safety-number frame + epoch state hash; render in the
   web UI. *Accept:* the web number is **byte-identical** to hark's
   `identity_safety_number_vector` (`src/mls/safety.rs:134`) for the same membership — the
   shared NFR-001 vector, and the last open [[SPEC-013-mls-private-channels#9. Verification Strategy|§9]]
   interop item.
4. **task-validation (LG-1 + IG-3, [[SPEC-013-mls-private-channels#REQ-017]]/[[SPEC-013-mls-private-channels#REQ-018]]/[[SPEC-013-mls-private-channels#REQ-014]]).**
   Rewrite `Group::process` for the REQ-017(a-e) allowlist, credential immutability, genesis
   immutability, sender-authenticated `:from`; mint + verify `cbcl-mls-remove/v1` removal
   evidence at merge (the hub already fans it — gap review §1). *Accept:* the R3-07
   credential-rebind oracle is **rejected** web-side; forged `:from` rejected; an
   evidence-free Remove rejected; **fresh-context Principle-12 review** before complete.
5. **task-mode-pin (LG-5, [[SPEC-013-mls-private-channels#REQ-023]]).** Pin `enc=true` from the
   admission path (cap/invite presence), refuse `roomcfg :enc false` downgrade, fail closed on
   unpinnable private mode. *Accept:* a hub `:enc false` on a cap-joined channel does not emit
   plaintext (mirrors hark's `downgrade_refused`, `src/mls/session.rs:240`).
6. **task-ledger (LG-6, [[SPEC-013-mls-private-channels#REQ-013]]).** Durable consumed-`KeyPackageRef`
   ledger + decrypt→validate→join→delete ordering in the crate provider. *Accept:* init key
   survives a failed Welcome, deleted only after successful join; replay is inert.
7. **task-directory-validation (LG-7, [[SPEC-013-mls-private-channels#REQ-015]]).** Hub `keypub`/
   `keyget` input validation (size bounds, base64 well-formedness, structural KeyPackage
   validity) before mutating directory state (LangSec trust boundary). *Accept:* oversized /
   malformed / non-base64 inputs rejected before any mnesia write.
8. **task-ui-claim (LG-8, [[SPEC-013-mls-private-channels#REQ-020]]).** The UI SHALL make no E2EE
   claim the implementation does not back; soften the "end-to-end encrypted" wording until
   tasks 1–5 land, then restore it. *Accept:* no confidentiality/authenticity claim renders
   while any of REQ-012/017/018/023 is unimplemented for that channel.
9. **task-interop (REQ-010, whole-suite gate).** A live hark agent + web client in one private
   channel: create → add → welcome → encrypt/decrypt both ways → remove, with **identical
   REQ-021 safety numbers**. *Accept:* the [[SPEC-013-mls-private-channels#REQ-010]] round-trip
   passes end-to-end; this is the plan's convergence signal.
10. **task-pin-bump (DR-1).** Bump `cbcl-bus/cbcl-rs.sha` + Dockerfile to the revision hark
    builds against; add the two-recogniser chat-frame conformance corpus (interim guard until
    D-3). *Accept:* `scripts/check-cbcl-rs-pin.sh` green at the new SHA; the SPEC-013 verbs
    round-trip through both `cbcl-parser` and `cbcl-erl`.
11. **task-dialect (D-3, deferred — blocked on the versioned cbcl-rs release).** Declare the
    MLS wire verbs as a pinned, content-hashed SPEC-015 dialect; IMPL-013's wire-contract
    `CON-###` reference it as the normative grammar. *Accept:* the dialect hash matches across
    hark, web, and hub; conformance corpus (task-pin-bump) subsumed by the dialect check.

## Verification strategy

Per the [[PROTO-001]] security-critical row and mirroring
[[SPEC-013-mls-private-channels#9. Verification Strategy]]:
- **Shared vectors** (NFR-001): the REQ-021 identity-safety-number vector and the genesis
  round-trip are the byte-exact cross-stack oracles — reproduce hark's, do not invent.
- **Property-based**: MLS roundtrip, election determinism (web-side must agree with hark's
  deterministic election over MLS leaves).
- **Fuzzing**: KeyPackage/Welcome/Commit deserialisation web-side + hub `keypub` input
  (task-directory-validation trust boundary).
- **Adversarial + Principle 12**: task-validation gets a fresh-context review (spec +
  deliverable only) before completion; the credential-rebind and forged-`:from` oracles are
  the must-kill mutants.
- **Live interop**: task-interop is the whole-suite acceptance and convergence signal.

## Traceability

`REQ → TEST → CODE(cbcl-bus) → OBS`, wikilinked and validated by `zetl check --dead-links`.
Findings map: IG-1→task-genesis, IG-2→task-pins-idkey, IG-3→task-validation, IG-4→task-safety,
LG-1→task-validation, LG-5→task-mode-pin, LG-6→task-ledger, LG-7→task-directory-validation,
LG-8→task-ui-claim, DR-1→task-pin-bump, D-3→task-dialect, REQ-010→task-interop. Source:
[[SPEC-013-cbcl-bus-interop-gap-review]].
