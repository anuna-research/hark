---
id: SPEC-013
title: hark MLS — Agents in Encrypted Private Channels
status: draft
tier: 1
version: 0.1.0
audience: agent, human
author: Anuna Research (drafted with Claude Opus 4.8)
last-updated: 2026-06-09
owner-repo: hark
affects-repos: cbcl-bus (web client + vendored cbcl-mls-wasm artifact), cbcl-chat (cbcl-mls-wasm crate)
review-gate: not-approved (no-go area — crypto + auth core)
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

- the MLS leaf credential uses a **fresh keypair bound to the member only by
  handle string** — it is *not* bound to the [[Signed-Member Wire]] [[Ed25519]]
  identity (an identity-substitution exposure); and
- group membership is driven by a **naive lexicographic [[Owner Election]]** with
  no owner-churn or concurrent-owner handling.

## 2. Scope

**In scope (MVP):** an agent can be *added to* and *can commit members of* **one**
encrypted private channel — exactly **one [[MLS]] group per agent connection**
([[#ADR-005]]); encrypt/decrypt of application messages; KeyPackage publication;
the [[#REQ-007|identity binding]] correction and [[#REQ-008|adder verification]];
durable group-state persistence; interop with web members.

**Precondition (already works — not in scope): room admission.** Joining a private
channel via a `:cap` or invite token already works in hark: it presents
`--cap <token>` in its signed `hello`, identical to the web client extracting the
token from an invite URL's `#`-fragment, and the hub redeems it on join. The
cap/invite admits the agent to the room's fan-out but carries **no MLS material** —
it is orthogonal to MLS group admission ([[#OQ-002]], [[#OQ-004]]). This spec
assumes the agent is already room-admitted and adds only **MLS group admission** on
top.

**Out of scope (deferred, tracked):** member removal / leave; owner-churn and
concurrent-owner robustness ([[#OQ-003]]); one-time-KeyPackage replenishment
policy ([[#OQ-004]]); key-transparency / out-of-band identity verification beyond
TOFU; metadata-privacy hardening against the hub-as-[[Delivery Service]];
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

**Failure modes:** wrong-`:for` Welcome (ignored); undecryptable frame
(dropped, session survives — [[#REQ-006]]); KeyPackage whose leaf key ≠ the
target's wire key (**rejected** — [[#REQ-008]]); missing/stale persisted state
(re-join required, logged).

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
- **REQ-008 — Adder verification.** Before adding a fetched [[KeyPackage]] to a
  group, the agent SHALL reject it unless its leaf signature key equals the target
  handle's established wire key ([[TOFU]] reference per [[#OQ-002]]). Trace: `[[#TEST-008]]`.
- **REQ-009 — Persist group state.** The agent SHALL persist [[MLS]] group state
  durably and reload it on restart, so a daemon restart does not lose the ability
  to decrypt the ongoing channel epoch. Trace: `[[#TEST-009]]`.
- **REQ-010 — Web interop.** `hark` MLS members SHALL interoperate with
  web-client MLS members in the same channel (shared ciphersuite, wire encoding,
  and election). Trace: `[[#TEST-010]]`.

## 5. Non-Functional Requirements

- **NFR-001 — Wire-byte compatibility.** MLS objects SHALL serialise to bytes
  accepted by the web client's [[OpenMLS]] at the pinned ciphersuite
  `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` and [[RFC 9420]] (`Mls10`),
  verified by a live cross-client roundtrip ([[#TEST-010]]).
- **NFR-002 — No plaintext leak.** In an encrypted channel, no message *content*
  SHALL traverse the wire unencrypted, verified by frame inspection.
- **NFR-003 — Guarantees preserved.** The [[#REQ-007|binding]] change SHALL NOT
  weaken MLS forward-secrecy / post-compromise-security relative to base [[RFC 9420]].
- **NFR-004 — Group state at rest.** Persisted group secrets SHALL be protected
  at rest at least as strongly as the wire identity seed (file mode `0600`, under
  `identity_dir`).

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

- **OQ-001 — Cross-context key reuse.** Is reusing one [[Ed25519]] key across the
  [[Signed-Member Wire]] envelope-signing context (`DS_TAG = cbcl-signed-member/v1`)
  and the [[MLS]] signing context safe, given each domain-separates its inputs?
  Requires a key-reuse / domain-separation analysis before [[#ADR-002]] is APPROVED.
- **OQ-002 — Authentic handle→wire-key source for [[#REQ-008]].** What does the
  adder check the fetched leaf key *against*? Candidates: [[TOFU]] on first
  KeyPackage per handle; a presence-carried wire key; a cap-bound key. Must
  account for the hub being an untrusted [[Delivery Service]].
- **OQ-003 — Election robustness.** Match the naive lexicographic [[Owner Election]]
  as-is for interop (deferring churn/concurrent-owner handling), or harden it
  (and update the web client)? Affects [[#REQ-004]] and the deferred scope.
- **OQ-004 — KeyPackage directory trust.** Consume-once is advisory, last-resort
  packages are reused, and the hub does no validation. Acceptable for MVP, or does
  the directory need hardening?
- **OQ-005 — Persisted-state format & protection.** Storage provider format,
  versioning/migration, and at-rest protection specifics for [[#REQ-009]]/[[#NFR-004]].

## 8. Tier-1 Gate

**Status: not approved.** Per [[PROTO-001]] this no-go area requires, before
implementation:

1. **Cross-model adversarial review** of this spec (a different model family,
   fresh context, mandate to find defects — Principle 12 / Multi-Model Cognitive
   Diversity), focused on [[#7. Open Questions (Tier-1 — require human crypto sign-off)]]
   and the binding/verification requirements.
2. **Human security/cryptography sign-off** resolving OQ-001…OQ-005 (the project
   owner may give this, accepting the cross-model review as basis, as was done for
   `cbcl-bus` `SPEC-012`).
3. **AI Trust Boundary metadata** recorded for the synthesis trajectory (model,
   prompts, drafts, adversarial findings).

## 9. Verification Strategy (Phase 2 — to be detailed in IMPL-013)

Per the [[PROTO-001]] security-critical row, the test specification will select:

- **Property-based**: MLS roundtrip (`decrypt(encrypt(m)) == m`), group-membership
  invariants, election determinism.
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
