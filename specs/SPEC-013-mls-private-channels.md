---
id: SPEC-013
title: hark MLS — Agents in Encrypted Private Channels
status: draft
tier: 1
version: 0.2.0
audience: agent, human
author: Anuna Research (drafted with Claude Opus 4.8)
last-updated: 2026-06-09
owner-repo: hark
affects-repos: cbcl-bus (web client + vendored cbcl-mls-wasm artifact), cbcl-chat (cbcl-mls-wasm crate)
review-gate: not-approved — BLOCKED (round-1 cross-model review: 8 Critical/High findings folded in; re-review required — see docs/decisions/SPEC-013-design-review-findings.md)
---

# SPEC-013 — hark MLS: Agents in Encrypted Private Channels

> **Owner:** `hark`. The capability is hark's; the identity-binding correction it
> requires also touches the `cbcl-bus` web client and the `cbcl-mls-wasm` crate
> (in `cbcl-chat`), tracked here as affected repos.

> **Tier-1 / No-go notice.** This specification touches **[[MLS]] end-to-end
> encryption** and the **[[Signed-Member Wire|signed-member authentication core]]**.
> Per [[PROTO-001]] AI Trust Boundaries, it is a **no-go area** requiring
> **cross-model adversarial review** and a **human security/cryptography
> sign-off** before any implementation. All `ADR-###` below are **PROPOSED**
> (project-owner-directed in design dialogue) and become `APPROVED` only with
> that sign-off. Implementation MUST NOT begin until the gate in [[#Tier-1 Gate]]
> clears.

## 1. Context & Intent

`cbcl-bus` private channels are end-to-end encrypted with [[MLS]] ([[RFC 9420]]);
today only the **web client** participates, via [[OpenMLS]] compiled to WASM. The
`hark` agent client joins *public* channels (plaintext over the
[[Signed-Member Wire]]) but has **no MLS capability**, so an agent cannot join an
encrypted private channel. This spec defines the capability that lets an
**authenticated agent become a member of an encrypted private channel** and
exchange messages there, interoperating with human web members.

**Intent anchor (Principle 13).** This spec is derived from the operator intent
*"add a hark agent to a private, end-to-end-encrypted channel such that its
identity is authentic and its messages are confidential."* It is **not** mined
from the existing `cbcl-mls-wasm` implementation. That implementation is used
only as a **test oracle** and an interop target. Two known properties of the
current implementation are treated as **defects to correct or constraints to
record**, not as requirements:

- **(core, per round-1 review)** MLS membership is anchored to **hub-mediated TOFU and
  unchecked KeyPackages/Welcomes**, NOT to authenticated wire identity — so an untrusted
  hub can substitute keys, inject KeyPackages, or push unsolicited Welcomes to control
  group membership (BUG-001/002/003). This spec must **anchor MLS membership to the
  authenticated wire identity** ([[#REQ-008]], [[#REQ-011]], [[#REQ-012]]);
- the MLS leaf credential uses a **fresh keypair bound to the member only by handle
  string** — not bound to the [[Signed-Member Wire]] [[Ed25519]] identity ([[#REQ-007]]);
- group membership is driven by a **naive lexicographic [[Owner Election]]** over an
  **unsigned hub-provided roster** — exploitable for split groups / committer capture
  (BUG-007, [[#REQ-016]]); and
- **MLS removal is unwired** — leave drops fan-out only, so removed members can still
  decrypt (BUG-005, [[#REQ-014]]).

## 2. Scope

**In scope (MVP):** an agent can be *added to*, *commit members of*, and *remove members
from* **one** encrypted private channel — exactly **one [[MLS]] group per agent
connection** ([[#ADR-005]]); encrypt/decrypt of application messages; KeyPackage
publication with **enforced single-use** ([[#REQ-013]]); **MLS membership anchored to the
authenticated wire identity** — the [[#REQ-007|binding]], [[#REQ-008|adder verification]],
[[#REQ-011|key pinning]], and [[#REQ-012|app-bound Welcome]] requirements; **MLS removal
on room removal** ([[#REQ-014]]); durable group-state persistence; interop with web members.

**Precondition (already works — not in scope): room admission.** Joining a private
channel via a `:cap` or invite token already works in hark: it presents
`--cap <token>` in its signed `hello`, identical to the web client extracting the
token from an invite URL's `#`-fragment, and the hub redeems it on join. The
cap/invite admits the agent to the room's fan-out but carries **no MLS material** —
it is orthogonal to MLS group admission ([[#OQ-002]], [[#OQ-004]]). This spec
assumes the agent is already room-admitted and adds only **MLS group admission** on
top.

**Out of scope (deferred, tracked):** owner-churn / concurrent-owner *liveness* robustness
beyond split-group resistance ([[#OQ-003]]); one-time-KeyPackage replenishment policy
([[#OQ-004]]); **key transparency** — the strong fix for the TOFU first-contact gap
([[#OQ-002]]); the MVP pins from observed signed frames + out-of-band fingerprint;
metadata-privacy hardening against the hub-as-[[Delivery Service]];
**single-identity multi-channel participation** (one agent identity in many
channels over one connection, as the web client does) — deferred to a future hark
multi-channel *transport* spec, on which a per-channel MLS-group registry would
layer. Here, an agent in N channels means **N agent instances** ([[#ADR-005]]).

## 3. Users & Happy Paths

**User profile — Agent Operator.** Runs a `hark` daemon hosting one or more
agents. Wants an agent to participate in a private channel alongside humans.
Constraints: headless (no UI); long-lived daemon (survives restarts);
security-sensitive (the whole point of a private channel is confidentiality +
authentic membership).

**Happy path HP-1 — agent is added to a private channel.**
Pre: the channel exists and is encrypted; the agent holds a valid `:cap` or
**invite token**. An invite URL is `https://<hub>/<channel>#<token>`; the token in
the `#`-fragment *is* the `:cap` value — the operator passes it via hark's existing
`--cap <token>`, and the hub redeems it (consuming one of the invite's bounded
uses) on join. Room admission thus **reuses the current hark flow** and is
**orthogonal to [[MLS]]**: the cap/invite carries **no MLS material**; it admits the
agent to the room's fan-out only.
1. Agent connects `/chat/v1`, sends a signed `hello` with its `:cap`/invite token →
   joins → hub returns `(roomcfg … :enc true)`. → agent recognises encryption.
2. Agent publishes KeyPackages (`keypub`) bound to its wire identity ([[#REQ-002]]).
3. The elected owner (human or agent) adds the agent → Commit + Welcome distributed.
4. Agent processes the Welcome ([[#REQ-001]]) → joins the [[MLS]] group.
Post: agent can decrypt channel traffic; it appears as a member.

**Happy path HP-2 — agent posts and receives encrypted messages.**
Agent encrypts each outbound message as an MLS application message ([[#REQ-005]]);
decrypts inbound ones and advances epoch on Commits ([[#REQ-006]]). No plaintext
content is emitted in the channel ([[#NFR-002]]).

**Happy path HP-3 — agent daemon restarts.**
The daemon restarts; the agent reloads persisted group state ([[#REQ-009]]) and
resumes decrypting the ongoing epoch without re-joining.

**Failure modes:** an **unbound/unauthorised Welcome** (wrong room, unexpected committer,
or one that would replace an existing group) is **rejected**, not joined ([[#REQ-012]]); a
KeyPackage whose target handle or leaf key ≠ the target's **pinned wire key** is
**rejected** ([[#REQ-008]], [[#REQ-011]]); a re-served one-time KeyPackage is an error
([[#REQ-013]]); an undecryptable frame is dropped, session survives ([[#REQ-006]]);
missing/stale persisted state → re-join, logged.

## 4. Requirements

> `SHALL` statements are atomic (one obligation each). Each `REQ` is traced to
> `TEST-###` in Phase 2 (`IMPL-013`); trace links are placeholders until then.

- **REQ-001 — Join via Welcome.** An enrolled agent SHALL join an existing
  encrypted private channel as an [[MLS]] group member by processing the
  [[Welcome]] addressed to it, WITHIN the join handshake, FOR an
  [[#3. Users & Happy Paths|agent operator]], WITH the result that it can decrypt
  subsequent application messages. Trace: `[[#TEST-001]]`.
- **REQ-002 — Publish KeyPackages.** On detecting an encrypted channel
  (`roomcfg :enc true`), the agent SHALL publish to the hub [[KeyPackage]]
  directory one last-resort and ≥1 one-time KeyPackage(s), each carrying the leaf
  credential of [[#REQ-007]]. Trace: `[[#TEST-002]]`.
- **REQ-003 — Commit members when owner.** When the agent is the elected
  [[Owner Election|group owner]], it SHALL add each other present member by
  fetching their KeyPackage, producing a [[Commit]] + [[Welcome]], and
  distributing them per [[#5. Non-Functional Requirements|the wire contract]]. Trace: `[[#TEST-003]]`.
- **REQ-004 — Election agreement.** The agent SHALL compute group ownership by
  the **same deterministic [[Owner Election]]** as peer clients, so exactly one
  committer is agreed across `hark` and web members for a given roster. Trace: `[[#TEST-004]]`.
- **REQ-005 — Encrypt outbound.** In an encrypted channel the agent SHALL encrypt
  every outbound channel message as an [[MLS]] application message and SHALL NOT
  emit channel message content as plaintext. Trace: `[[#TEST-005]]`.
- **REQ-006 — Decrypt / advance epoch.** The agent SHALL decrypt inbound MLS
  application messages and process inbound Commits to advance group epoch; an
  undecryptable frame SHALL be dropped WITHOUT aborting the session. Trace: `[[#TEST-006]]`.
- **REQ-007 — Identity binding.** The agent's MLS leaf credential signature key
  SHALL be its [[Signed-Member Wire]] [[Ed25519]] identity key — NOT a freshly
  generated key. Trace: `[[#TEST-007]]`.
- **REQ-008 — Adder verification (target + key).** Before adding a fetched [[KeyPackage]]
  to a group, the agent SHALL verify BOTH (a) the KeyPackage's credential identity is the
  intended target handle, AND (b) its leaf signature key **equals that handle's pinned wire
  key** ([[#REQ-011]]) — NOT a key asserted by the hub via `keypkg`/`keyget`/presence. Any
  mismatch → reject. Trace: `[[#TEST-008]]`. *(Closes BUG-001.)*
- **REQ-009 — Persist group state.** The agent SHALL persist [[MLS]] group state
  durably and reload it on restart, so a daemon restart does not lose the ability
  to decrypt the ongoing channel epoch. Trace: `[[#TEST-009]]`.
- **REQ-010 — Web interop.** `hark` MLS members SHALL interoperate with
  web-client MLS members in the same channel (shared ciphersuite, wire encoding,
  and election). Trace: `[[#TEST-010]]`.
- **REQ-011 — Authenticated handle→wire-key pinning.** The agent SHALL pin each handle's
  wire [[Ed25519]] key from that handle's **own per-frame-signed messages** (signatures it
  verified), NOT from any hub-asserted source (`keypkg`/`keyget` responses, presence). The
  pin is first-observation [[TOFU]] at minimum; a later observation conflicting with the
  pin SHALL be flagged and the key NOT silently rotated. The residual first-contact gap is
  [[#OQ-002]]. Trace: `[[#TEST-011]]`. *(Closes BUG-003.)*
- **REQ-012 — App-bound Welcome validation.** Before joining a group from a [[Welcome]],
  the agent SHALL verify it is bound to (a) **this** app room/channel, (b) an **authorised
  committer** (the elected owner for the current roster — [[#REQ-004]]/[[#REQ-016]]), and
  (c) does **not silently replace** an existing group for the room. An unbound/unauthorised
  Welcome SHALL be rejected. Trace: `[[#TEST-012]]`. *(Closes BUG-002.)*
- **REQ-013 — Single-use KeyPackages.** One-time KeyPackages SHALL be **enforced
  single-use** (consumed atomically at the directory, not advisory); a re-served one-time
  KeyPackage SHALL be treated as an error. Last-resort KeyPackage reuse SHALL be bounded
  and its forward-secrecy cost documented. Trace: `[[#TEST-013]]`. *(Closes BUG-004; resolves [[#OQ-004]].)*
- **REQ-014 — MLS removal on room removal.** When a member leaves or is removed from a
  room, the group SHALL issue an [[MLS]] **Commit removing that member** — not merely drop
  fan-out — so a removed/compromised member cannot decrypt subsequent traffic. Trace:
  `[[#TEST-014]]`. *(Closes BUG-005.)*
- **REQ-015 — Directory input validation.** `keypub`/`keyget` inputs SHALL be validated
  (size bounds, base64 well-formedness, structural validity) **before** mutating directory
  state; malformed/oversized inputs SHALL be rejected. Trace: `[[#TEST-015]]`. *(Closes BUG-006.)*
- **REQ-016 — Roster/committer authenticity.** The owner-election and add-authority SHALL
  NOT rest on **unsigned hub-provided presence**; the committer/membership determination
  SHALL be robust to a hub serving **divergent rosters** (split-group resistance) — e.g. by
  binding membership changes to the verifiable [[MLS]] group state rather than the hub
  roster. Trace: `[[#TEST-016]]`. *(Closes BUG-007; refines [[#REQ-004]], [[#OQ-003]].)*

## 5. Non-Functional Requirements

- **NFR-001 — Wire-byte compatibility.** MLS objects SHALL serialise to bytes
  accepted by the web client's [[OpenMLS]] at the pinned ciphersuite
  `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` and [[RFC 9420]] (`Mls10`),
  verified by a live cross-client roundtrip ([[#TEST-010]]).
- **NFR-002 — No plaintext leak.** In an encrypted channel, no message *content*
  SHALL traverse the wire unencrypted, verified by frame inspection.
- **NFR-003 — Guarantees preserved.** The [[#REQ-007|binding]] change SHALL NOT
  weaken MLS forward-secrecy / post-compromise-security relative to base [[RFC 9420]].
- **NFR-004 — Group state at rest (compromise model).** Persisted group secrets SHALL be
  protected at rest at least as strongly as the wire identity seed (`0600`, under
  `identity_dir`). The spec SHALL state a **precise compromise model**: a reader of
  `identity_dir` obtains the wire identity **and** MLS group state → current/future
  impersonation + decryption are in scope after local compromise; **past-message exposure**
  is bounded by the OpenMLS **secret-retention policy** ([[#OQ-005]]) — retained ratchet
  material SHALL be minimised to preserve forward secrecy.

## 6. Architecture Decisions (PROPOSED — pending Tier-1 sign-off)

- **ADR-001 — Fix identity binding now, across all three codebases.** Correct the
  unbound-identity defect in lockstep (cbcl-bus web + `cbcl-mls-wasm` crate +
  hark) rather than have hark match the defect for short-term interop.
  *Trade-off:* larger blast radius and a coordinated re-vendor of the WASM
  artifact, vs shipping a known identity-substitution exposure. *Owner direction:*
  fix now.
- **ADR-002 — Bind by reusing the wire [[Ed25519]] key as the MLS leaf signer.**
  The ciphersuite's signature scheme is Ed25519, so the wire-signing key doubles
  as the MLS leaf signature key — the leaf *is* the wire identity. *Trade-off:*
  strongest binding with minimal machinery, **but** one key signs in two contexts
  (wire envelope vs MLS) — a key-reuse question raised as [[#OQ-001]]. Alternative
  (cross-certify separate keys) deferred. *Owner direction:* reuse the key.
- **ADR-003 — OpenMLS native in hark, version-pinned to the crate.** Use
  [[OpenMLS]] as a native Rust dependency, pinned to the exact version the
  `cbcl-mls-wasm` crate builds against, mirroring its group logic. *Trade-off:*
  a different MLS stack (e.g. `mls-rs`) risks subtle wire-incompat; native
  OpenMLS keeps byte-compatibility ([[#NFR-001]]).
- **ADR-004 — Persist group state under `identity_dir`.** Back OpenMLS with a
  durable storage provider writing under `identity_dir` (next to the `.key`),
  because hark is a long-lived daemon — in-memory state (as the web client uses)
  would silently break decryption after a restart. *Trade-off:* a storage-at-rest
  surface ([[#NFR-004]], [[#OQ-005]]) vs restart resilience ([[#REQ-009]]).
- **ADR-005 — Multi-channel via multiple agent instances (one group per
  connection).** hark's model is one agent handle = one `/chat/v1` connection =
  one channel (`config.rs` single `channel`; the daemon keys agents by handle).
  SPEC-013 keeps this: an agent participates in exactly one channel — hence one
  [[MLS]] group — per connection; operating in N channels means running N agent
  instances. *Trade-off:* MLS state, KeyPackage budget, [[Owner Election]], and
  persistence stay **naturally per-agent-per-group** (no cross-channel group
  registry), at the cost that the same operator appears under a **distinct
  identity** (handle + leaf key) in each channel, and N channels cost N
  connections/instances. Single-identity multi-channel (the web-client model) is
  deferred to a future hark multi-channel transport spec. *Owner direction:*
  multiple instances.

## 7. Open Questions (Tier-1 — require human crypto sign-off)

> Updated after round-1 review (see [[SPEC-013-design-review-findings]]).

- **OQ-001 — Cross-context key reuse — RESOLVED (pending test).** Round-1 found **no**
  cross-protocol signature collision (wire `DS_TAG` vs OpenMLS `SignWithLabel`). Reuse
  ([[#ADR-002]]) is acceptable, **conditional on** a regression/property test asserting no
  collision under the pinned labels, required before [[#REQ-007]] is approved (§9).
- **OQ-002 — Authenticated trust root for pinning — OPEN (gating).** [[#REQ-011]] pins from
  the member's own signed frames (not hub assertion), which still has a **first-contact
  TOFU gap** an untrusted hub can exploit. The strong fixes — out-of-band fingerprint
  verification and/or **key transparency** — need design + re-review. The SPAKE2 pairing
  ([[SPEC-016-agent-onboarding-dx#REQ-007]]) may give an authenticated channel to pin an
  agent's key; humans need their own path. **This is the gating question.**
- **OQ-003 — Roster/committer authenticity — OPEN (was "match naive").** Round-1 rejects
  matching the naive election as-is: it rests on unsigned hub presence (split-group /
  committer-capture risk). [[#REQ-016]] requires binding membership to verifiable [[MLS]]
  state; the concrete mechanism (and any web-client change) needs design.
- **OQ-004 — KeyPackage directory — RESOLVED.** Enforce single-use ([[#REQ-013]]); bound +
  document last-resort reuse and its forward-secrecy cost.
- **OQ-005 — Persisted-state retention — OPEN (refined).** Specify the OpenMLS secret
  **retention policy** + migration/versioning so the [[#NFR-004]] compromise window is
  precise (how much past-message material survives a local compromise).

## 8. Tier-1 Gate

**Status: not approved — BLOCKED.** Round-1 cross-model adversarial review is **complete**
(8 Critical/High findings, [[SPEC-013-design-review-findings]]), folded into v0.2.0 as
new/strengthened requirements. **OQ-002 (authenticated trust root) and OQ-003 (roster
authenticity) remain OPEN** and gate sign-off. Per [[PROTO-001]], before implementation:

1. **Re-review** of v0.2.0 (cross-model adversarial, fresh context — Principle 12),
   confirming REQ-008/011/012/013/014/015/016 close BUG-001…007 and that OQ-002/003 resolve.
2. **Human security/cryptography sign-off** resolving OQ-001…OQ-005 (the project
   owner may give this, accepting the cross-model review as basis, as was done for
   `cbcl-bus` `SPEC-012`).
3. **AI Trust Boundary metadata** recorded for the synthesis trajectory (model,
   prompts, drafts, adversarial findings).

## 9. Verification Strategy (Phase 2 — to be detailed in IMPL-013)

Per the [[PROTO-001]] security-critical row, the test specification will select:

- **Property-based**: MLS roundtrip (`decrypt(encrypt(m)) == m`), group-membership
  invariants, election determinism, and a **no-cross-protocol-signature-collision**
  regression (wire envelope vs OpenMLS `SignWithLabel`) — required before [[#REQ-007]] is
  approved ([[#OQ-001]]).
- **Mutation testing**: on the [[#REQ-008|adder-verification]] predicate and the
  [[#REQ-007|binding]] construction (these MUST kill mutants — a surviving mutant
  here is a security hole).
- **Fuzzing**: KeyPackage / Welcome / Commit deserialisation (untrusted input at a
  trust boundary).
- **Formal contracts**: pre/postconditions on add-member (reject-on-mismatch).
- **Adversarial testing** + **live interop test**: a `hark` agent and a web client
  in one private channel exchanging encrypted messages ([[#TEST-010]]).

Each `REQ` gets requirement-targeted decomposition (positive / negative-input /
negative-output) so failures attribute to a single clause.

## 10. Experiment Spike (recommended, pre-IMPL)

One genuine integration unknown warrants a timeboxed spike under Experiment
Governance ([[PROTO-001]]) **before** committing IMPL-013: confirm that hark's
native [[OpenMLS]] (at the pinned version) produces **wire-compatible** bytes with
the web `cbcl-mls-wasm` artifact — a minimal create→add→welcome→encrypt→decrypt
exchange between the two stacks. Isolated (no production writes); findings fold
into [[#NFR-001]] and [[#ADR-003]].

## 11. Traceability

`REQ → TEST → CODE → OBS`, with `CON`/`ADR` linked, encoded as `[[wikilinks]]`
and validated by `zetl check --dead-links`. `CON-###` (the `mls` module interface
and the six wire verbs) and `TEST-###` are produced in Phase 2 (`IMPL-013`).
