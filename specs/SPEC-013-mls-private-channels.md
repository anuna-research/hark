---
id: SPEC-013
title: hark MLS — Agents in Encrypted Private Channels
status: draft
tier: 1
version: 0.7.1
audience: agent, human
author: Anuna Research (drafted with Claude Opus 4.8; v0.6 folds round-3 findings + §10 spike evidence; v0.7 folds round-4 findings, Claude Fable 5; v0.7.1 folds round-5 tightenings)
last-updated: 2026-06-10
owner-repo: hark
affects-repos: cbcl-bus (web client + vendored cbcl-mls-wasm artifact), cbcl-chat (cbcl-mls-wasm crate)
review-gate: not-approved — BLOCKED (rounds 1–2 folded into v0.3; v0.4 adds the Authentication Service design — ADR-006; v0.5 resolves OQ-004 + OQ-005 client-side — REQ-013/REQ-022; v0.6 folds round-3 cross-model findings; **v0.7 folds the round-4 confirmation review**; **v0.7.1 folds the round-5 spec tightenings** — removal-evidence epoch freshness, creator eviction authority residual, genesis-extension capability requirements + spike, canonical safety-number encoding, and low-risk residual clarifications. Round-5 was cross-context but not cross-model; human crypto sign-off and the Principle-12 spot-check remain before implementation — see docs/decisions/SPEC-013-round5-review-findings.md)
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
  decrypt (BUG-005, [[#REQ-014]]);
- **(round 2)** inbound Commits/proposals are merged without app-level checks (any member
  can inject an Add — BUG-008, [[#REQ-017]]); the **MLS sender** is discarded, so a member
  can **forge `:from`** (BUG-009, [[#REQ-018]]); and REQ-011's pin source is **not
  peer-verifiable** on today's wire (BUG-010, [[#REQ-019]]); and
- **(round 2, operational)** the **live UI still claims E2EE** for private channels while
  implementation is gated and broken (BUG-011, [[#REQ-020]]); and
- **(round 3)** the **channel's encryption mode is read from an unsigned hub `roomcfg`
  bit** — an active hub can send `:enc false` and the client emits plaintext into a
  private channel (R3-05, [[#REQ-023]]); inbound validation guarded only **Add** leaves, so
  an MLS **Update** that rebinds a member's leaf credential reopens `:from` forgery (R3-07,
  [[#REQ-017]]); **removal is triggered by unsigned hub presence**, so a hub can fabricate a
  leave and drive a real MLS Remove to evict E2EE members (R3-06, [[#REQ-014]]); the
  **room-creator root of trust has no checkable existence on the wire** and the Welcome's
  committer check is circular (R3-08, [[#REQ-012]]/[[#REQ-016]]); the **SPAKE2 pairing carries
  no peer-identity material and the hub holds password-equivalent verifier**, so it is not an
  Authentication Service for agents (R3-01/R3-02, [[#ADR-006]], [[SPEC-016-agent-onboarding-dx#REQ-007]]); and
- **(round 4)** the v0.6 fixes relocated four holes rather than closing them: the encryption-mode
  pin still had a **hub-winnable first observation** (mode-TOFU + a hub-authored pairing-record
  `enc` field — R4-01, [[#REQ-023]]); removal evidence gated only the **committer's decision**,
  not the **validators' merge** — a malicious authorized committer could evict anyone (R4-02,
  [[#REQ-014]]/[[#REQ-017]]); the **genesis assertion was itself TOFU** whenever the creator key
  was not already pinned, with no durable delivery to late joiners (R4-03, [[#REQ-016]]); and
  binding the safety number to `epoch` made it **rotate on every Commit**, nullifying out-of-band
  comparison (R4-04, [[#REQ-021]]); the flagged key-rotation exception was undefined and non-leaf
  proposal types unhandled (R4-05, [[#REQ-011]]/[[#REQ-017]]).
- **(round 5)** the v0.7 closures held as design intent, but four predicates were still too
  implicit for implementation: removal evidence needed an exact live-epoch freshness check
  ([[#REQ-014]]/[[#REQ-017]]), the creator fallback needed to document its unilateral eviction
  authority ([[#REQ-014]]/[[#REQ-016]]), the durable genesis GroupContext extension needed
  cross-stack OpenMLS capabilities and a probe ([[#REQ-016]]/[[#REQ-017]]/[[#10-experiment-spike]]),
  and the identity safety number needed byte-exact canonical encoding ([[#REQ-021]]/[[#REQ-024]]).

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
   joins → hub returns `(roomcfg … :enc true)`. The agent has **already pinned the mode
   encrypted before connecting** — presenting a cap/invite IS joining a private (⇒ encrypted)
   channel ([[#REQ-023]]); the hub bit is display/bootstrap only, and a conflicting
   `:enc false` is a refused downgrade.
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
([[#REQ-013]]); an undecryptable frame is dropped but **counted** — a run of failures from a
pinned member is surfaced as a probable-fork/equivocation warning, not silently swallowed
([[#REQ-006]]); a `roomcfg` that **downgrades** a channel known-encrypted to cleartext is
**refused** — the client fails closed and does not emit plaintext — and a private-channel join
whose mode cannot be pinned from the admission path or operator intent **fails closed** too
([[#REQ-023]]); a Remove without valid [[#REQ-014]] evidence is **rejected at merge by every
member** ([[#REQ-017]]); missing/stale persisted state → re-join, logged.

## 4. Requirements

> `SHALL` statements are atomic (one obligation each). Each `REQ` is traced to
> `TEST-###` in Phase 2 (`IMPL-013`); trace links are placeholders until then.

- **REQ-001 — Join via Welcome.** An enrolled agent SHALL join an existing
  encrypted private channel as an [[MLS]] group member by processing the
  [[Welcome]] addressed to it, WITHIN the join handshake, FOR an
  [[#3. Users & Happy Paths|agent operator]], WITH the result that it can decrypt
  subsequent application messages. Trace: `[[#TEST-001]]`.
- **REQ-002 — Publish KeyPackages.** On joining a channel **pinned encrypted**
  ([[#REQ-023]] — the pin, not the raw `roomcfg :enc` bit), the agent SHALL publish to the
  hub [[KeyPackage]] directory one last-resort and ≥1 one-time KeyPackage(s), each carrying
  the leaf credential of [[#REQ-007]]. Trace: `[[#TEST-002]]`.
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
- **REQ-006 — Decrypt / advance epoch (drop-but-count).** The agent SHALL decrypt inbound
  MLS application messages and process inbound Commits to advance group epoch; an
  undecryptable frame SHALL be dropped WITHOUT aborting the session. The agent SHALL,
  however, **count** consecutive decrypt failures attributable to a pinned member and
  **surface** a persistent run (≥ a small threshold) as a **probable fork / equivocation**
  signal feeding the [[#REQ-021]] safety-number comparison — silent drop SHALL NOT mask a
  hub that has forked the group by equivocating Commit order. Trace: `[[#TEST-006]]`.
  *(Closes R3-12.)*
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
- **REQ-011 — Authenticated handle→wire-key pinning (+ rotation ceremony).** The agent SHALL
  pin each handle's wire [[Ed25519]] key from that handle's **own per-frame-signed messages**
  (signatures it verified), NOT from any hub-asserted source (`keypkg`/`keyget` responses,
  presence). The pin is first-observation [[TOFU]] at minimum; a later observation conflicting
  with the pin SHALL be flagged and the key NOT silently rotated. **Key rotation is an
  authenticated ceremony, not a flag**: a pin SHALL be updated from K to K' only on a
  **cross-signed rotation assertion** — `(rekey @handle :old K :new K' :room @room :epoch N)`
  signed by **both** K and K' under its **own domain-separation label** (e.g.
  `cbcl-idkey-rotate/v1`, extending the [[#OQ-001]] no-collision analysis), fanned per
  [[#REQ-019]]; peers verify both signatures and atomically re-pin, and [[#REQ-017]] clause
  (c) admits a leaf Update rebinding `@handle`→K' only after such an assertion verifies
  (R4-05). A member that **lost** K cannot rotate — recovery is **remove + re-add**
  ([[#REQ-014]] authorized removal, then a fresh [[#REQ-008]]-validated Add of the new key),
  which is deliberately membership-visible: it flips the [[#REQ-021]] identity safety number
  rather than slipping a new key under a stable one. This recovery path is only as available
  as an authorized remover: the subject, the agent's `added_by` adder
  ([[SPEC-016-agent-onboarding-dx#REQ-012]]), or the creator fallback in [[#REQ-014]].
  *Compromised-key residual:* if current key K is compromised, the attacker can
  cross-sign a formally valid rotation to attacker-controlled K'; this is inherent to
  current-key compromise, and the mitigation is visibility, not prevention — the rotation
  changes the [[#REQ-021]] identity safety number and must be re-compared. The residual
  first-contact gap is [[#OQ-002]]. Trace: `[[#TEST-011]]`. *(Closes BUG-003; defines the
  rotation path R4-05 found dangling; residuals tightened per R5-05.)*
- **REQ-012 — App-bound Welcome validation (full-tree, pin-checked).** Before joining a
  group from a [[Welcome]], the agent SHALL verify it is bound to (a) **this** app
  room/channel, (b) an **authorised committer** (the elected owner for the current roster —
  [[#REQ-004]]/[[#REQ-016]]), (c) does **not silently replace** an existing group for the
  room, AND (d) **every leaf of the Welcome's ratchet tree** satisfies [[#REQ-008]] where a
  pin exists for that handle — i.e. for each leaf whose handle is already pinned
  ([[#REQ-011]]), the leaf signature key SHALL equal the pinned wire key; a tree containing
  an **unpinned key for a pinned handle** is a **hard reject**. The committer check (b) is
  NOT sufficient alone — it is **circular** when computed over the tree the Welcome itself
  supplies (a fabricated group elects its own fabricated owner consistently); the
  leaf-vs-pin check (d) is the predicate with teeth. For an all-first-contact tree (no pins
  yet), the joiner SHALL pin TOFU and **require [[#REQ-021]] safety-number confirmation**
  before treating the group as authentic. An unbound/unauthorised/pin-violating Welcome
  SHALL be rejected. Trace: `[[#TEST-012]]`. *(Closes BUG-002; closes R3-08 Welcome path.)*
- **REQ-013 — Single-use KeyPackages (client-enforced, delete-after-successful-join).**
  Single-use SHALL be enforced **client-side** (the directory is the untrusted hub). The
  consume sequence SHALL be strictly ordered: **(1) decrypt the Welcome → (2) pass full
  [[#REQ-012]] + [[#REQ-017]] validation → (3) join succeeds → (4) ONLY THEN delete the
  one-time init private key from memory AND persistent storage.** A Welcome that **fails**
  validation SHALL leave the init key **intact** — otherwise a malicious hub/member sends a
  junk Welcome to the victim's package to burn the key and brick the honest committer's
  Welcome (a join-DoS and a hub-chosen "first Welcome wins"). After a successful consume a
  replayed Welcome to the same package is **undecryptable/inert** with no later-compromisable
  key. Clients SHALL keep a **durable** ledger of consumed `KeyPackageRef`s and reject
  re-use; an **in-memory-only** ledger (e.g. the web client before persistence) gives the
  guarantee only within a session and SHALL be documented as such. `KeyPackageRef`s SHALL be
  **transcript-visible** so the group rejects an Add reusing a ref ([[#REQ-017]]). Trace:
  `[[#TEST-013]]`. *(Closes BUG-004; resolves [[#OQ-004]]; closes R3-09.)*
- **REQ-014 — MLS removal on *authenticated* room removal (peer-verifiable evidence).** When
  a member leaves or is removed from a room, the group SHALL issue an [[MLS]] **Commit removing
  that member** — not merely drop fan-out — so a removed/compromised member cannot decrypt
  subsequent traffic. The removal trigger SHALL be **authenticated evidence**, NOT unsigned hub
  presence. Evidence SHALL be a **signed removal-evidence object** bound to the removal it
  authorises — `(room, group_id, epoch, target handle + leaf)` — under its **own
  domain-separation label** (e.g. `cbcl-mls-remove/v1`, the [[#REQ-019]] pattern, so it cannot
  be transplanted across rooms, groups, epochs, or targets), signed by one of:
  - **(a) the subject's pinned key** — a self-signed `bye` for a voluntary leave, which the
    leaving client SHALL **fan to the room as evidence**. Because `bye` is a reserved hub
    performative today, this is not just "add a new verb": implementation SHALL change the
    reserved-verb interception so the verified payload and signature are preserved and fanned
    room-wide as peer-verifiable evidence (today's `bye` only drives local leave + unsigned
    hub presence — `cbcl-chat-session-ws.lfe` — an affected-repo wire change); or
  - **(b) an authorized remover's pinned key** — the agent's `added_by` adder
    ([[SPEC-016-agent-onboarding-dx#REQ-012]]) or, as the **liveness fallback** for a crashed
    member that can never sign a `bye`, the **room creator** (the [[#REQ-016]] genesis
    principal). The creator fallback is **not mechanically restricted to crashed or
    unresponsive members**: the creator can evict any member. This is an accepted
    single-party membership-shrink authority only because the evidence is signed by the
    creator's pinned key, attributable to that creator, and membership-visible via the
    [[#REQ-021]] identity safety number; it does not let the creator add attacker keys or
    break confidentiality by itself. *(Residuals, documented: if the creator is itself gone,
    an unresponsive member persists in the group until an authorized remover is available —
    availability-class; a malicious creator can unilaterally evict live members —
    authority/integrity-class. Both are PROPOSED for sign-off.)*
  The evidence epoch is the **current MLS group epoch before applying the Remove Commit**.
  Evidence is valid only in that exact epoch: validators SHALL reject stale or future
  evidence, with no tolerance window. A re-added member is a new leaf in a later epoch, so
  any prior `bye` or remover evidence for the old leaf is invalid and cannot remove the
  re-added member without fresh evidence.
  Every Remove proposal/Commit SHALL **carry or reference** this evidence so each member can
  verify it independently; verification is REQUIRED **at merge time by every validator**
  ([[#REQ-017]] clause (d)) — NOT only at the committer's decision — otherwise a malicious
  *authorized committer* evicts arbitrary members with an evidence-free but
  otherwise-well-formed Commit (R4-02). Unsigned hub presence/leave events MAY only **prompt**
  a removal decision; they SHALL NOT by themselves cause a Remove Commit — otherwise an active
  hub fabricates "@x left" and drives the deterministic committer to evict arbitrary E2EE
  members, churn epochs, and drain one-time KeyPackages toward the [[#REQ-022]] last-resort
  residual. (The hub retains the power to drop/partition fan-out — an **availability** loss,
  not an authenticity one; this residual is documented, not closed.) Trace: `[[#TEST-014]]`.
  *(Closes BUG-005; closes R3-06 and R4-02.)*
- **REQ-015 — Directory input validation.** `keypub`/`keyget` inputs SHALL be validated
  (size bounds, base64 well-formedness, structural validity) **before** mutating directory
  state; malformed/oversized inputs SHALL be rejected. Trace: `[[#TEST-015]]`. *(Closes BUG-006.)*
- **REQ-016 — Authority from verifiable MLS state (resolves OQ-003).** The committer and
  add/remove authority SHALL derive from the **MLS group's ratchet tree** (authenticated,
  consistent across members), NOT hub presence: the deterministic committer is computed
  over the **MLS leaves**, and admitting a new member requires (a) a current MLS member
  (the room creator bootstraps — see below), (b) the addee's key validated
  ([[#REQ-008]]/[[#REQ-011]]/[[#REQ-017]]), and (c) a valid cap. The hub cannot **grow**
  MLS membership it does not hold; the hub alone cannot **shrink** MLS membership either,
  because every Remove requires [[#REQ-014]] evidence. The design does, however, grant the
  room creator a signed, attributable, membership-visible unilateral eviction authority as
  documented in [[#REQ-014]]. **Bootstrap root of trust (honest about its limit).** The "room
  creator" SHALL be a concrete principal: the creator SHALL emit a **creator-signed
  group-genesis assertion** (the [[#REQ-019]] self-signed pattern:
  `(genesis @room :creator @h :group <group-id> :key K …)` signed by K). Its authority SHALL
  be stated at its true strength: the assertion is **authoritative only when K is already
  pinned ([[#REQ-011]]) or independently authenticated out-of-band**; when K is first observed
  *from the assertion itself*, it is **self-signed TOFU** — the hub can present an attacker
  creator handle/key and a self-consistent signed genesis, so the assertion only relocates the
  first-contact race (R4-03). In that case the design IS the **documented first-group-wins
  TOFU + mandatory [[#REQ-021]] safety-number confirmation** — the spec SHALL NOT claim the
  hub cannot stand up a rival group at first contact (it can; the safety number is the catch).
  **Out-of-band anchor (SHOULD):** invite links and pairing records, minted/shared by a
  member's client out-of-band, SHOULD carry the **creator-key fingerprint** alongside the
  token — upgrading genesis from TOFU to authenticated for every invited joiner without key
  transparency. **Durable delivery:** the genesis assertion SHALL travel a **durable,
  peer-verifiable path that reaches late joiners** — carried in the group's **GroupContext as
  an application extension** (every [[Welcome]] then conveys it inside the MLS-authenticated
  object; it is immutable thereafter — [[#REQ-017]] clause (e)); room fan-out alone is
  insufficient (encrypted rooms have **no history/backfill** — `cbcl-chat-room.lfe` — and the
  hub can drop a fanned frame). **OpenMLS capabilities obligation:** the genesis extension
  SHALL have a pinned application extension type, and every hark and web-client
  (`cbcl-mls-wasm`) KeyPackage / leaf node SHALL advertise that type in its OpenMLS
  `Capabilities`; group-creation configuration SHALL include the extension. A stack that
  omits the capability must fail closed during Add/Welcome validation rather than silently
  joining a group whose genesis extension it cannot process. This is a load-bearing
  cross-repo requirement for both `hark` and `cbcl-mls-wasm`, and [[#10-experiment-spike]]
  requires an explicit round-trip probe before IMPL-013 treats the mechanism as verified.
  At channel `claim` the hub SHALL record a **creator handle**
  (today `cbcl-room` stores none — affected-repo change), but that record is **bookkeeping,
  not trust** — it is hub-asserted. The hub cannot fabricate MLS membership inside an
  established group, so it cannot create a divergent valid group **undetected** once pins +
  safety numbers exist ([[#REQ-021]] catches equivocation). Trace: `[[#TEST-016]]`.
  *(Closes BUG-007; resolves [[#OQ-003]]; refines [[#REQ-004]]; closes R3-08 bootstrap as
  re-scoped by R4-03.)*
- **REQ-022 — KeyPackage replenishment + bounded last-resort.** The publisher SHALL
  maintain a pool of one-time KeyPackages, replenishing it (publish fresh, delete-on-use per
  [[#REQ-013]]) as packages are consumed, and SHALL prefer one-time packages for every Add.
  A **last-resort** KeyPackage MAY be used only when the one-time pool is exhausted; its
  reuse is **bounded by a mechanism, not only prose**: the last-resort leaf SHALL carry a
  short MLS **`lifetime`**, and [[#REQ-008]]/[[#REQ-017]] SHALL **reject an expired
  KeyPackage**. The §10 spike confirmed `KeyPackageIn::validate()` already rejects an expired
  KeyPackage on openmls 0.8.1 (`InvalidLifetime`; `experiments/spec-013-mls-spike`,
  `r3_10_expired_keypackage_rejected`) — so setting a short `lifetime` suffices; expiry is
  enforced by the primitive at add time. The forward-secrecy residual SHALL be recorded at its **true
  scope**: a hub that **drains** the one-time pool can force last-resort use, and because a
  Welcome carries the joiner's **epoch secrets**, a captured Welcome plus a *later* init-key
  compromise exposes the **group's message confidentiality for that epoch and forward until
  the next key-updating Commit** — not merely "that Welcome." This residual is **accepted and
  documented**, not silently incurred, and is bounded by the `lifetime` + replenishment.
  Trace: `[[#TEST-022]]`. *(With [[#REQ-013]], resolves [[#OQ-004]]; scope corrected per R3-10.)*
- **REQ-017 — Inbound membership-change validation (every leaf-changing object).** Before
  merging any inbound [[MLS]] Commit or storing any standalone proposal, the agent SHALL
  inspect **every object that adds, replaces, or mutates a leaf node** — not only Adds:
  **Add**, **Update**, and **Remove** proposals AND the **committer's UpdatePath leaf**. For
  each such leaf: (a) its credential identity SHALL satisfy [[#REQ-008]] (target handle), (b)
  its leaf signature key SHALL equal that handle's **pinned wire key** ([[#REQ-011]]), and (c)
  **credential identity SHALL be immutable per member** — an Update that changes a member's
  handle, or rebinds an existing handle to a different key, SHALL be rejected unless a
  **verified [[#REQ-011]] rotation assertion** authorises exactly that handle→new-key rebind
  (never a silent rebind). This closes the Update-path bypass: MLS does NOT enforce credential
  continuity across Update (RFC 9420 §7.3/§12.1.2), so without (c) a member could publish an
  Update rebinding their leaf to read `@alice`, after which [[#REQ-018]]'s sender check passes
  for a forged `:from @alice`. **The §10 spike confirmed this empirically against openmls
  0.8.1**: a self-Update rebinding a leaf credential from `bob` to `alice` was accepted by both
  the committer and the peer (`experiments/spec-013-mls-spike`,
  `r3_07_self_update_credential_rebind`) — so clause (c) is **load-bearing, not
  defence-in-depth**. Further: (d) **Remove evidence at merge** — a Remove proposal/Commit
  SHALL be merged only after verifying the [[#REQ-014]] removal-evidence object it carries or
  references (signature by the subject's or an authorized remover's pinned key; binding to
  this room, group, target handle + current leaf, and the validator's **current epoch before
  merge**); stale or future-epoch evidence SHALL be rejected, including any evidence from
  before the target was removed and later re-added. A Remove lacking valid fresh evidence
  SHALL be rejected **by every validator**, not only weighed by the committer (R4-02/R5-01).
  And (e) **fail-closed proposal allowlist** — ONLY Add, Update, and Remove proposals plus the
  committer's UpdatePath leaf, each validated as above, are accepted; **every other proposal or
  external-join object** — ReInit, PreSharedKey, GroupContextExtensions, ExternalInit/external
  Commits, and any future proposal type — SHALL be **rejected** unless a spec revision defines
  explicit app-level validation for it; in particular a GroupContextExtensions proposal that
  would alter the [[#REQ-016]] genesis extension SHALL be rejected (the genesis is immutable).
  Validators SHALL also reject Adds/Welcomes/Updates whose leaf capabilities do not advertise
  the pinned [[#REQ-016]] genesis-extension type, because openmls 0.8.1 treats that unknown
  extension as a member capability requirement. The current wasm glue merges/stores protocol
  messages with **no** app checks
  (`cbcl-mls-wasm/src/lib.rs`) — a defect this REQ corrects (R4-05). Commits SHALL originate
  from an **authorised committer** ([[#REQ-016]]); unauthorised or unvalidated proposals SHALL
  NOT be stored or merged. Trace: `[[#TEST-017]]`. *(Closes BUG-008; closes R3-07 — reopened
  `:from` forgery via the Update path; closes R4-02 at the validator and R4-05's open
  proposal surface.)*
- **REQ-018 — Sender-authenticated `:from`.** The agent SHALL obtain the **authenticated
  MLS sender leaf** for each decrypted application message and SHALL **reject** (not render)
  a message whose inner CBCL `:from` does not match that sender's **pinned handle**
  ([[#REQ-011]]). Trace: `[[#TEST-018]]`. *(Closes BUG-009 — `:from` forgery by a member.)*
- **REQ-019 — Self-signed key-assertion frame.** A member SHALL broadcast a **key
  assertion** — `(idkey @handle :key K :room @room :nonce N)` **signed by K** over a
  peer-verifiable context that is **independent of the per-connection envelope** (so a hub
  cannot strip/replay/transplant it across rooms or connections). The signed context SHALL
  carry **its own domain-separation label** — distinct from the wire envelope's
  `DS_TAG = "cbcl-signed-member/v1"` (e.g. `"cbcl-idkey-assert/v1"`) — so an `idkey`
  signature can never be confused with, or transplanted into, a wire-envelope signature
  (this extends the [[#OQ-001]] no-collision analysis to the assertion). The **room binding**
  is load-bearing (prevents cross-room transplant) and SHALL stay. The **nonce N** does
  **not** by itself defeat the dangerous attack — hub *substitution* of a different
  self-signed assertion is unaffected by N (replaying an honest assertion merely re-asserts
  the honest binding). N's defined purpose is to **bind the assertion to the current pin
  epoch**, so a stale assertion cannot re-pin a key after a flagged rotation ([[#REQ-011]]);
  the spec SHALL state who generates N and what a peer checks it against, or drop the
  replay-bound claim. The hub fans it; peers **verify the signature themselves** (not hub
  attestation) and pin handle→K ([[#REQ-011]], TOFU) — making REQ-011 implementable. Trace:
  `[[#TEST-019]]`. *(Closes BUG-010; enables [[#REQ-011]]; tightened per R3-14.)*
- **REQ-020 — No unbacked E2EE claim in the UI (until the gate clears).** Until the
  [[#8. Tier-1 Gate]] clears, the product UI SHALL NOT present private channels as providing
  confidentiality or authenticity (E2EE); wording SHALL make no security claim the
  implementation does not back. Trace: `[[#TEST-020]]`. *(Closes BUG-011; **immediate action
  on the live deployment**.)*
- **REQ-021 — Safety number: a stable identity number + a volatile state hash.** Clients
  SHALL derive **two** values, with distinct jobs (a single number binding `epoch` rotates on
  every Commit, making out-of-band comparison impractical for humans and headless operators —
  exactly where [[#ADR-006]] leans on it; R4-04):
  - **(a) the identity safety number** — the **out-of-band comparison surface** — commits to
    the **group identity and membership bindings**: `group_id` plus the sorted set of
    (handle, leaf-signature-key) pairs. It changes ONLY on membership change or an
    authenticated [[#REQ-011]] rotation — never on a pure ratchet Commit (under [[#REQ-017]]
    clause (c) the binding set is stable across them) — so one comparison at first contact
    stays valid through normal operation. Two distinct rooms with the same member set get
    distinct numbers (`group_id`); membership equivocation flips it.
  - **(b) the epoch state hash** — `epoch` + the **epoch authenticator / tree hash** — the
    **fork-debugging diagnostic**, surfaced on demand and whenever [[#REQ-006]]'s
    decrypt-failure signal fires or (a) mismatches. It commits to full tree state, so
    tree-level equivocation that preserves the membership set — invisible to (a) by
    construction — is caught **here**, paired with the [[#REQ-006]] signal (forked groups
    cannot decrypt each other's traffic).
  **Canonical encoding for (a):** the digest input SHALL be exactly:
  `u32be(len("cbcl-mls-identity-safety/v1")) || "cbcl-mls-identity-safety/v1" ||
  u32be(len(group_id_bytes)) || group_id_bytes || u32be(member_count) || members...`.
  `group_id_bytes` are the MLS GroupId opaque bytes with no MLS TLS length prefix. Each member
  entry is `u32be(len(handle_utf8)) || handle_utf8 || u32be(32) || ed25519_pubkey_bytes`,
  where `handle_utf8` is the canonical CBCL handle string including `@`, encoded as UTF-8, and
  `ed25519_pubkey_bytes` is the 32-byte raw verification key that [[#REQ-007]] also uses as
  the leaf signature key. Members are sorted lexicographically by `handle_utf8` bytes, with
  `ed25519_pubkey_bytes` as the tie-breaker. The identity safety-number bytes are
  `SHA-256` of that frame; the human-facing representation SHALL be 64 lowercase hex
  characters displayed as eight groups of eight separated by spaces (comparisons ignore
  spaces and ASCII case). Implementations SHALL include a cross-stack test vector before
  treating [[#REQ-024]] as satisfied. A keys-only fingerprint remains insufficient (R3-13):
  (a) carries the group binding and the handle↔key bindings; the tree-state property R3-13
  demanded lives in (b). **Comparison workflow:** compare (a) once at first contact and again
  whenever the client flags a membership change or rotation; consult (b) only when
  investigating a fork signal. A mismatch
  in either indicates hub equivocation / MITM / fork (the confirmation [[#REQ-006]] and
  [[#REQ-012]]'s all-first-contact path defer to). This is the first-contact mitigation
  alongside the invite anchor ([[#OQ-002]], [[#ADR-006]]). The agent surface is [[#REQ-024]].
  Trace: `[[#TEST-021]]`. *(Strengthened per R3-13; split per R4-04 so the comparison surface
  survives normal Commits.)*
- **REQ-023 — Encryption-mode pin derived from the admission path (fail closed).** A client
  SHALL NOT take a channel's E2EE status from the unsigned hub `roomcfg :enc` bit, and SHALL
  NOT pin the mode by **first-observation TOFU of that bit** — at first contact the hub owns
  the first observation, so mode-TOFU hands an active hub a cleartext pin into a private
  channel (R4-01). The mode SHALL be pinned only from **hub-independent evidence of intent**,
  available on every path into a private channel:
  - **(a) the admission path** — presenting a `:cap`/invite token (hark `--cap`, an invite
    URL `#`-fragment, or a pairing record carrying a `cbcl-chat-invite` cap —
    [[SPEC-016-agent-onboarding-dx#REQ-007]]) **is** joining a private channel, and private ⇒
    encrypted: the client SHALL pin `enc=true` from the token's presence **before the first
    frame is sent**, regardless of what `roomcfg` later says;
  - **(b) explicit operator intent** — hark config, a `:create private` channel creation, or
    the web client's create-private action.
  A `roomcfg :enc false` (or any signal that would route content as plaintext) on a channel
  pinned encrypted SHALL be treated as a **downgrade attack**: the client SHALL **refuse to
  send** (fail closed) and surface the conflict — it SHALL NEVER fall back to emitting channel
  content as plaintext. A join into a channel believed private but whose mode the client cannot
  pin from (a)/(b) SHALL also **fail closed** (no plaintext send). This creates an accepted
  availability cost: a legitimate returning human member on a fresh device or cleared storage
  who no longer has an invite/cap must be re-invited or re-paired to re-derive the pin; the
  client SHALL NOT guess plaintext to preserve convenience. `roomcfg :enc true` on an
  unpinned channel MAY trigger MLS bootstrap (encrypting is never the downgrade direction) but
  SHALL NOT serve as evidence of cleartext in any later conflict. The web client SHALL persist
  pins (local storage), noting persistence is best-effort — re-presenting the invite re-derives
  the pin under (a). *Documented residual:* the web client is **hub-served code**, so
  client-side pinning defends against a malicious hub *configuration*, not a hub serving
  malicious JS; that residual is inherent to web delivery and out of scope here (the hark
  agent, locally installed, does not share it). Trace: `[[#TEST-023]]`.
  *(Closes R3-05 and R4-01 — mode-TOFU removed; unknown private mode fails closed.)*
- **REQ-024 — Agent safety-number surface.** hark SHALL expose **both [[#REQ-021]] values**
  for the agent's group — e.g. `hark safety-number <@channel>` printing the identity safety
  number (the value to compare against the web UI's) and the epoch state hash (labelled as
  diagnostic) — so a headless agent operator can compare out-of-band. Because the identity
  number is **stable across normal Commits** ([[#REQ-021]](a)), the operator compares once at
  pairing time and again only when hark reports a membership change or rotation — a workflow a
  headless deployment can actually follow (R4-04). Without this surface the agent cannot
  participate in the one mechanism that catches first-contact MITM, on which [[#ADR-006]]
  relies for agents. Trace: `[[#TEST-024]]`. *(Closes R3-13; workflow made practical per R4-04.)*

## 5. Non-Functional Requirements

- **NFR-001 — Wire-byte compatibility.** MLS objects SHALL serialise to bytes
  accepted by the web client's [[OpenMLS]] at the pinned ciphersuite
  `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` and [[RFC 9420]] (`Mls10`),
  verified by a live cross-client roundtrip ([[#TEST-010]]). App-level cryptographic
  comparison surfaces that cross the hark/web boundary — especially the [[#REQ-021]]
  identity safety number — SHALL also be byte-compatible under their pinned canonical
  encodings, with shared test vectors.
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
  material SHALL be minimised to preserve forward secrecy. The retention policy SHALL be
  named by **concrete OpenMLS knobs**, not principle alone: `max_past_epochs` (bound the
  retained epoch-secret history), `SenderRatchetConfiguration{out_of_order_tolerance,
  maximum_forward_distance}` (bound the in-epoch decryption window), and an explicit
  **resumption-PSK policy** — the `ResumptionPskStore` retains past-epoch resumption PSKs
  **independently** of message secrets and SHALL be bounded too (it is otherwise an
  unaddressed past-secret reservoir). Because all OpenMLS pruning is delegated to the
  `StorageProvider`'s delete calls and [[#ADR-004]] has hark writing a **new durable
  provider**, the provider SHALL actually honour deletes; a provider that no-ops deletes
  silently retains every superseded secret with no API symptom. A TEST SHALL assert that,
  after a Commit merge / Welcome consume, superseded epoch secrets and consumed init keys
  are **absent from disk** ([[#OQ-005]]). The §10 spike established the upstream half: all
  three knobs exist on `MlsGroupJoinConfigBuilder` (openmls 0.8.1), and OpenMLS prunes
  superseded epoch secrets from the **persisted state** — persisted secret-state was ~8.4 KB
  under `max_past_epochs(0)` vs ~36 KB under `(12)` after 12 epoch changes
  (`experiments/spec-013-mls-spike`, `r3_11_storage_prunes_superseded_epoch_secrets`). The
  **residual** the durable provider's own test must close: that ADR-004's on-disk provider
  actually honours those delete calls (fsync fidelity). *(Concretised per R3-11; upstream half confirmed by the §10 spike.)*

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
- **ADR-006 — Authentication Service: TOFU + safety numbers; SPAKE2 anchors *capability*, not
  identity (re-scoped per R3-01).** The MLS AS — the missing piece, since the hub is the
  untrusted DS — is **first-observation TOFU pins + safety-number confirmation** ([[#REQ-019]],
  [[#REQ-021]], [[#REQ-024]]) for **both humans and agents**. The agent's [[SPEC-016-agent-onboarding-dx#REQ-007]]
  **SPAKE2 pairing is NOT the agent AS** — it anchors **capability + name delivery** to the
  intended agent against third parties, but it carries **no peer-identity material** (no member
  keys, no group fingerprint) and the hub holds a **password-equivalent verifier** (plain
  SPAKE2 is not an augmented PAKE — R3-02), so it cannot authenticate peer identity *against*
  the hub. Consequently, **for agents the first-contact root is hub-mediated TOFU**, and the
  compensating control is the **mandatory safety-number surface** ([[#REQ-024]]) compared
  out-of-band; the spec SHALL NOT claim the agent first-contact gap is "anchored" by the
  phrase. **Not admin-rooted** — a central authority vouching for identities re-introduces a
  hub-like trusted party, antithetical to peer E2EE (the `auth_shell` chain is right for agent
  *capability*, not human *identity*). **Not key transparency** for the MVP — deferred as the
  strong upgrade; TOFU pins are forward-compatible with a future log. *Rationale:* private
  channels are small & invite-only, where Signal-style TOFU+safety-numbers fits, and the
  out-of-band invite anchors first contact. *Residual (must be accepted by the human signer):*
  first-contact TOFU is **winnable by an active hub by construction** until safety numbers are
  actually compared — for humans (who may never compare) and for agents (structurally). *Owner
  direction:* A, with the agent-AS claim re-scoped.

## 7. Open Questions (Tier-1 — require human crypto sign-off)

> Updated after round-1 review (see [[SPEC-013-design-review-findings]]).

- **OQ-001 — Cross-context key reuse — RESOLVED (pending test + signer hygiene).** Rounds 1–3
  independently found **no** cross-protocol signature collision: the wire envelope begins
  `00 00 00 15` (u32-be length of the 21-byte `DS_TAG`), whereas RFC 9420 `SignWithLabel`
  signs `SignContent` whose first byte is a TLS varint label length **≥ 0x10, never 0x00**,
  and MLS verifiers **reconstruct** the expected label rather than parsing attacker bytes —
  so the signed-byte domains are disjoint at byte 0. Reuse ([[#ADR-002]]) is acceptable,
  **conditional on**: (1) the regression/property test asserting no collision under the pinned
  labels (§9); (2) **retiring the legacy bare-payload signer — DONE 2026-06-10 (R4-06)**:
  `chat_frame::encode_frame` (the one public API that signed raw CBCL with the identity key
  under **no** domain separation) is removed from the live tree; the identity key now signs
  only the domain-separated `signed_frame::envelope` via `SignedConn`, and any future
  raw-bytes signing oracle with the identity key is **prohibited**; (3) giving the
  [[#REQ-019]] `idkey` assertion its own DS label (R3-14) — and now the [[#REQ-011]] `rekey`
  and [[#REQ-014]] removal-evidence labels, all distinct (the same analysis applies: every
  app-signed context carries a label disjoint from the wire envelope and from MLS
  `SignWithLabel`). SPAKE2 ([[SPEC-016-agent-onboarding-dx#REQ-007]]) involves no Ed25519 —
  no interaction.
- **OQ-002 — Authenticated trust root — RESOLVED-direction (PROPOSED; re-scoped round-3).**
  The Authentication Service is **TOFU pins + safety-number confirmation** for **both humans
  and agents** ([[#REQ-019]], [[#REQ-021]], [[#REQ-024]]) — [[#ADR-006]]. The **SPAKE2 pairing
  anchors capability + name, not peer identity** (R3-01/R3-02): for agents the first-contact
  root is hub-mediated TOFU, with the safety number as the compensating control. Not
  admin-rooted; key transparency is the documented strong-future. **Accepted residual** (for
  human sign-off): first-contact TOFU is winnable by an active hub until safety numbers are
  compared out-of-band — humans may never compare; agents structurally depend on [[#REQ-024]].
  The [[#REQ-021]] identity number now has a pinned canonical encoding so this comparison can be
  byte-identical across hark and the web client; the residual is user/process adherence, not an
  encoding ambiguity.
- **OQ-003 — Roster/committer authenticity — RESOLVED (PROPOSED, round-3).** Authority
  derives from the verifiable [[MLS]] ratchet tree, not hub presence ([[#REQ-016]]); the
  concrete election mechanism + any web-client change are confirmed at round-3. Round 5 adds
  an explicit accepted residual for [[#REQ-014]]/[[#REQ-016]]: the room creator can
  unilaterally evict any member, not only crashed members. That authority is key-attributable
  and membership-visible via [[#REQ-021]], but it is still a single-party membership-shrink
  power the human signer must accept.
- **OQ-004 — KeyPackage replay defence — RESOLVED (PROPOSED, round-3).** Enforcement moves
  **client-side** (the directory is the untrusted hub): **delete-on-use** of the one-time
  init private key from memory + storage, a **consumed-`KeyPackageRef` ledger**, and
  **transcript-visible refs** so the group rejects an Add reusing a ref ([[#REQ-013]],
  [[#REQ-017]]). Prefer one-time + **replenish** ([[#REQ-022]]); a bounded, documented
  **last-resort** carries an explicit, accepted residual (a draining hub can force
  last-resort → a later init-key compromise weakens forward secrecy for those Welcomes).
  The §10 spike confirmed `validate()` rejects an expired KeyPackage (`InvalidLifetime`), so
  the last-resort `lifetime` bound ([[#REQ-022]]) is enforced by the primitive. **Round-4
  confirms** the ref-visibility mechanism (transcript-visible `KeyPackageRef`) + the
  residual's acceptability.
- **OQ-005 — Persisted-state retention — RESOLVED (PROPOSED, round-3).** Same
  retention-minimisation principle as [[#NFR-004]]: the agent SHALL retain only the secret
  material OpenMLS needs for the **current** epoch (plus a bounded out-of-order decryption
  window), **prune superseded epoch secrets** promptly to preserve forward secrecy, and
  treat a storage-format **version bump as a re-join** (no silent migration of stale secret
  state). This bounds the [[#NFR-004]] past-message window to the retained window. The §10
  spike **confirmed the concrete knobs** (`max_past_epochs`, `number_of_resumption_psks`,
  `sender_ratchet_configuration` on `MlsGroupJoinConfigBuilder`) and that pruning is reflected
  in **persisted** secret-state (~8.4 KB at `(0)` vs ~36 KB at `(12)`). **Round-4 / the durable
  provider's own test** confirms only the on-disk delete fidelity of ADR-004's provider.

## 8. Tier-1 Gate

**Status: not approved — BLOCKED.** Rounds 1–2 folded into v0.3.0; v0.4.0 added the
**Authentication Service design** ([[#ADR-006]]); v0.5.0 resolved OQ-004 + OQ-005
client-side. The **round-3 cross-model review** (docs/decisions/SPEC-013-round3-review-findings.md)
found **two Critical + four High** findings; **v0.6.0 folds their dispositions**:

- **R3-05 (Critical) → [[#REQ-023]]** — encryption-mode pin; fail closed on hub downgrade.
- **R3-07 (Critical) → [[#REQ-017]]** — validate every leaf-changing object (Add/Update/Remove
  + UpdatePath); credential immutability; closes the reopened `:from` forgery.
- **R3-01/R3-02 (High) → [[#ADR-006]]** + [[SPEC-016-agent-onboarding-dx#REQ-007]] — re-scope the
  agent AS (SPAKE2 = capability, not identity; verifier is password-equivalent).
- **R3-06 (High) → [[#REQ-014]]** — authenticated removal evidence, not hub presence.
- **R3-08 (High) → [[#REQ-012]]/[[#REQ-016]]** — checkable bootstrap root + full-tree leaf-vs-pin.
- **R3-15 (High, operational) → [[#REQ-020]]** — live-UI E2EE claim **removed in the live tree
  2026-06-10** (index.html), independent of the gate.
- Tightening: R3-09 → [[#REQ-013]], R3-10 → [[#REQ-022]], R3-11 → [[#NFR-004]], R3-12 →
  [[#REQ-006]], R3-13 → [[#REQ-021]]/[[#REQ-024]], R3-14 → [[#REQ-019]]/[[#OQ-001]].

**§10 experiment spike — DONE** (`experiments/spec-013-mls-spike`, openmls 0.8.1 pinned to
`cbcl-mls-wasm`). It converted three of the round-3 "could-not-assess" items into evidence
and confirmed NFR-001 cross-stack: **R3-07** — OpenMLS *accepts* a credential-rebinding
self-Update (REQ-017 clause (c) is load-bearing); **R3-10** — `validate()` rejects an expired
KeyPackage (REQ-022 lifetime bound enforced); **R3-11** — `max_past_epochs` bounds *persisted*
secret-state, all named knobs exist (NFR-004); **NFR-001** — native OpenMLS ⇄ the compiled
`cbcl-mls-wasm` interoperate both directions at the pinned ciphersuite. Residuals it could not
close: the durable provider's on-disk delete fidelity, and `cbcl_ristretto` point validation.

The **round-4 confirmation review ran** (findings:
docs/decisions/SPEC-013-round4-review-findings.md). It **confirmed R3-01/R3-02 closed** and
found **1 Critical + 3 High + 1 Medium + 1 Low** — three unclosed round-3 items and one new
gap opened by the R3-13 fix. **v0.7.0 folds their dispositions:**

- **R4-01 (Critical) → [[#REQ-023]]** — mode pin derived from the **admission path**
  (cap/invite ⇒ private ⇒ encrypted, pinned pre-send) or explicit operator intent;
  first-observation mode-TOFU **removed**; unknown private mode fails closed. SPEC-016
  REQ-007/ADR-003: the pairing `enc` field is advisory; the invite-cap presence is the signal.
- **R4-02 (High) → [[#REQ-014]]/[[#REQ-017]](d)** — a signed, room/group/epoch/target-bound
  removal-evidence object, verified **at merge by every validator**, not only the committer;
  the `bye` is fanned as evidence (affected-repo wire change).
- **R4-03 (High) → [[#REQ-016]]** — genesis authoritative only with a pinned/independently
  authenticated creator key, else documented first-group-wins TOFU; durable delivery via a
  **GroupContext extension**; invite links SHOULD carry the creator-key fingerprint.
- **R4-04 (High) → [[#REQ-021]]/[[#REQ-024]]** — the comparison surface split into a **stable
  identity safety number** (membership-bound) and a volatile **epoch state hash** (fork
  diagnostic), so out-of-band comparison survives normal Commits.
- **R4-05 (Medium) → [[#REQ-011]]/[[#REQ-017]](e)** — cross-signed `rekey` rotation ceremony;
  fail-closed proposal **allowlist** (ReInit/PSK/GroupContextExtensions/external joins
  rejected).
- **R4-06 (Low) → [[#OQ-001]]** — the bare-payload signer **retired in the live tree
  2026-06-10**.

The **round-5 confirmation review ran** (findings:
docs/decisions/SPEC-013-round5-review-findings.md). It found no surviving Critical and no
surviving High confidentiality/authenticity hole, but it also carried a Principle-12 caveat:
the reviewer was the same model family that folded v0.7, so independence is cross-context,
not cross-model. **v0.7.1 folds the required pre-IMPL tightenings:**

- **R5-01 → [[#REQ-014]]/[[#REQ-017]](d)** — removal evidence is fresh only for the exact
  current pre-merge epoch; stale evidence cannot remove a re-added member.
- **R5-02 → [[#REQ-014]]/[[#REQ-016]]/[[#OQ-003]]** — creator-as-removal-authority is documented
  as unilateral eviction authority, not merely liveness recovery.
- **R5-03 → [[#REQ-016]]/[[#REQ-017]]/[[#10-experiment-spike]]** — the genesis GroupContext
  extension requires cross-stack OpenMLS capabilities and a pre-IMPL round-trip probe.
- **R5-04 → [[#REQ-021]]/[[#REQ-024]]/[[#NFR-001]]** — the identity safety-number canonical
  encoding, sort order, hash, and display representation are pinned.
- **R5-05/R5-06/R5-07** — residual/scoping clarifications for compromised-key rotation,
  `bye`'s reserved-verb implementation, and no-cap returning-member availability.

What remains to gate implementation, per [[PROTO-001]]:

1. **Human security/cryptography sign-off** resolving OQ-001…OQ-005 and explicitly accepting
   the residuals now documented: first-contact TOFU, last-resort forward-secrecy loss, hub
   fan-out/evidence-suppression availability, durable-provider on-disk delete fidelity,
   `cbcl_ristretto` point validation, creator unilateral eviction, hub-served-JS limits,
   the identity-number/state-hash detection split, and the R5-03 feasibility-pending spike.
2. **Principle-12 spot-check** by a genuinely independent model or human cryptographer for at
   least R5-01, R5-02, and R5-03, because the round-5 reviewer was not cross-model independent.
3. **AI Trust Boundary metadata** recorded for the synthesis trajectory (model, prompts,
   drafts, adversarial findings).

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
- **Round-5 interop vectors**: a shared [[#REQ-021]] identity safety-number vector for hark
  and the web client, plus a genesis-extension capabilities round-trip probe before IMPL-013
  treats [[#REQ-016]] durable delivery as empirically verified.

Each `REQ` gets requirement-targeted decomposition (positive / negative-input /
negative-output) so failures attribute to a single clause.

## 10. Experiment Spike (pre-IMPL)

The initial OpenMLS interop spike is **DONE** (§8): hark-native OpenMLS and the
web `cbcl-mls-wasm` artifact round-tripped create→add→welcome→encrypt→decrypt at the
pinned ciphersuite. Round 5 adds one remaining timeboxed probe under Experiment
Governance ([[PROTO-001]]) **before** committing IMPL-013: create a group with the
[[#REQ-016]] genesis assertion in a pinned `Unknown`/application GroupContext extension,
publish hark and `cbcl-mls-wasm` KeyPackages whose leaf capabilities advertise that
extension type, and confirm cross-stack Add→Welcome→read succeeds while omitting the
capability fails closed. Until this probe passes, the durable genesis mechanism is
source-confirmed but **feasibility-pending-verification**.

## 11. Traceability

`REQ → TEST → CODE → OBS`, with `CON`/`ADR` linked, encoded as `[[wikilinks]]`
and validated by `zetl check --dead-links`. `CON-###` (the `mls` module interface
and the six wire verbs) and `TEST-###` are produced in Phase 2 (`IMPL-013`).
