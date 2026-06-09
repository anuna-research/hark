---
id: SPEC-014
title: Agent Identity — Host Delegation Convention
status: superseded
superseded-by: SPEC-016 (added-by provenance replaces host attribution)
tier: 1
version: 0.1.0
audience: agent, human
author: Anuna Research (drafted with Claude Opus 4.8)
last-updated: 2026-06-09
owner-repo: hark
affects-repos: cbcl-bus (web client verifies + displays; hub relays the announce)
review-gate: not-approved (no-go area — authentication core)
---

# SPEC-014 — Agent Identity: Host Delegation Convention

> ⛔ **SUPERSEDED (2026-06-09)** by [[SPEC-016-agent-onboarding-dx]]. The chat model
> dropped the host/owner concept: an agent is identified by its **own key + handle**
> (TOFU, per-frame verified) and attributed by **`added by`** (the member who brought
> it into the channel) — not by a verifiable "acts for" delegation. The spoofing
> problem this spec addressed does not arise without a "whose agent" claim. Retained
> for history; **do not implement**. A future need for a cryptographically verifiable
> agent↔principal link could revive these ideas.

> **Owner:** `hark`. The host issues the delegation and the agent advertises it on
> `announce` — both hark actions. The hub stays a pure relay (it does not validate,
> [[#REQ-007]]); cbcl-bus's stake is the **web client** verifying + displaying the
> attribution, tracked here as an affected repo. Sibling to
> [[SPEC-013-mls-private-channels]] (both are agent capabilities riding `announce`).

> **Tier-1 / No-go notice.** This specification defines an **authentication-core**
> convention (a signed delegation over identity). Per [[PROTO-001]] AI Trust
> Boundaries it requires **cross-model adversarial review** and a **human security
> sign-off** before implementation. All `ADR-###` are **PROPOSED** until that
> sign-off. See [[#8. Tier-1 Gate]].

## 1. Context & Intent

On the [[Signed-Member Wire]], every frame is authentic (per-frame [[Ed25519]]),
but the model answers *"is this key valid?"* — not *"whose agent is this, and is
it an agent at all?"* Today:

- **Agent-ness is self-asserted and ephemeral.** A handle becomes "an agent" only
  when it emits the `announce` performative (`apps/cbcl_chat/priv/web/app.js:497`),
  which carries `:agent`/`:from` and **no host attribution**.
- **No host attribution exists.** The router's `principal` *is* the agent's own id
  (`apps/cbcl_router/src/cbcl-agent-ws.lfe:207`); nothing links an agent to the
  human/principal that runs it. Handles are opaque `@name`; the per-channel
  multi-instance model ([[SPEC-013-mls-private-channels#ADR-005]]) makes them more
  opaque (`@aria-research`, `@aria-builds`).

**Intent.** *"A reader of a channel should be able to verify that an agent acts on
behalf of a named host — cryptographically, not by a label anyone can type."* This
spec defines a **host-signed delegation** binding an agent's wire key to a host's
wire key, advertised on `announce` and verified end-to-end.

**Prior art reused (not mined as spec source — Principle 13):** the convention
mirrors shapes the system already ships — the router's admin-signed
`(grant @pubkey (caps …))` ([[SPEC-007]]), the `svc:`-namespaced principal ids
(`cbcl-auth.lfe`), and the webhook door's **on-behalf / untrusted-external**
provenance tag. These are precedents for structured principals and "acting on
behalf of," not the source of this spec's requirements.

## 2. Scope

**In scope:** a host-signed [[Delegation]] binding *agent wire key → host wire key*
with an expiry, conveying **identity attribution only**; its carriage on the
`announce` performative; its **end-to-end verification** by any client (web, agent,
or the hub acting only as relay); and its surfacing in the roster as verifiable
host attribution.

**Out of scope (deferred / other specs):** **capability delegation** — *what* an
agent may do stays with the admin-grant model ([[SPEC-007]]); see [[#REQ-006]].
Key-transparency for host keys (TOFU for MVP — [[#OQ-001]]); revocation lists
([[#OQ-002]]); delegation chains / sub-delegation ([[#OQ-005]]); display of the
host's *handle* vs *key* trust ([[#OQ-004]]).

## 3. Users & Happy Paths

**User profile — Agent Operator / Host.** A human principal (a `cbcl-bus` member)
who runs one or more agents and wants them to be **recognisably and verifiably
theirs** in a channel.

**HP-1 — host issues a delegation.** The host, holding its wire key `H`, signs a
delegation `D = (deleg :agent A_pub :host H_pub :exp T)` → `sig_H`. `D + sig_H` is
handed to the agent (out of band / via the operator's tooling). One-time, offline.

**HP-2 — agent advertises it.** On joining a room the agent emits
`(announce @room :agent @aria :deleg "<b64 D>" :sig "<b64 sig_H>")` ([[#REQ-002]]).

**HP-3 — a reader verifies.** Any client checks `Verify(H_pub, D, sig_H) == ok`,
that `A_pub` equals the announcing agent's **live wire-signing key**, and that `T`
is not past ([[#REQ-003]], [[#REQ-005]]). On success the roster shows
*"aria — @hugo's agent ✓"* ([[#REQ-004]]).

**Failure modes:** absent/invalid/expired delegation → the agent is shown as an
agent but **without** verified host attribution (never as host-backed —
[[#REQ-004]]); a delegation whose `A_pub` ≠ the live signer → rejected
([[#REQ-003]]); a delegation purporting capabilities → ignored ([[#REQ-006]]).

## 4. Requirements

- **REQ-001 — Issue.** A host SHALL be able to produce a delegation binding an
  agent wire key to its own wire key with an expiry, signed by the host wire key,
  WITHOUT contacting the hub. Trace: `[[#TEST-001]]`.
- **REQ-002 — Advertise.** An agent SHALL carry its delegation on the `announce`
  performative (`:deleg` + `:sig`). Trace: `[[#TEST-002]]`.
- **REQ-003 — Verify.** A verifier SHALL accept a delegation ONLY IF its signature
  validates against the host key AND its delegated agent key equals the
  announcing agent's live wire-signing key; otherwise it SHALL reject it. Trace: `[[#TEST-003]]`.
- **REQ-004 — Surface, fail-closed.** A verifier SHALL show host attribution ONLY
  for a delegation that passed [[#REQ-003]]; an absent/invalid/expired delegation
  SHALL NOT render any host attribution. Trace: `[[#TEST-004]]`.
- **REQ-005 — Expiry.** A verifier SHALL reject a delegation whose expiry is in the
  past. Trace: `[[#TEST-005]]`.
- **REQ-006 — Identity only.** A delegation SHALL NOT confer capabilities;
  authorization remains the admin-grant's ([[SPEC-007]]) responsibility, and a
  verifier SHALL ignore any capability-like fields in a delegation. Trace: `[[#TEST-006]]`.
- **REQ-007 — Hub stays relay.** Verification SHALL be end-to-end by clients; the
  hub SHALL NOT be required to validate or store delegations (it MAY, but trust
  SHALL NOT rest on it). Trace: `[[#TEST-007]]`.

## 5. Non-Functional Requirements

- **NFR-001 — Offline-verifiable.** A delegation SHALL be self-contained: verifiable
  from `(D, sig_H, H_pub, the live agent key)` with no network call and no hub trust.
- **NFR-002 — No bearer.** A delegation SHALL NOT be a bearer credential — it is
  inert without the agent proving possession of `A_priv` via the normal per-frame
  wire signature ([[Signed-Member Wire]]).
- **NFR-003 — Bounded size.** The `announce` `:deleg`/`:sig` payload SHALL be
  bounded so it cannot bloat presence/announce traffic.

## 6. Architecture Decisions (PROPOSED — pending Tier-1 sign-off)

- **ADR-001 — Cryptographic delegation, not a display label.** Host attribution is
  a **signed binding**, not a self-asserted `:host` string — consistent with the
  bus's no-bearer, per-frame-authentic posture. *Owner direction:* option 2.
- **ADR-002 — Identity attribution only.** The delegation answers "whose agent",
  not "what may it do"; capabilities stay in the admin-grant ([[SPEC-007]]), so the
  two models do not overlap or need precedence rules. *Owner direction:* identity only.
- **ADR-003 — Carry on `announce`.** Reuse the existing agent-class carrier rather
  than a new performative; the same `announce` that earns agent treatment carries
  the attribution. (Ties to hark needing to emit `announce` at all.)
- **ADR-004 — End-to-end verification; hub stays [[Delivery Service|relay]].** Any
  client verifies; the hub neither validates nor is trusted for it ([[#REQ-007]]).
- **ADR-005 — Delegation format mirrors the admin grant.** A symbolic-expression
  object `(deleg :agent <pubkey> :host <pubkey> :exp <unixtime>)` signed by the host
  key, parallel to `(grant @pubkey (caps …))`. *Pending* the signing-context
  decision in [[#OQ-003]].

## 7. Open Questions (Tier-1 — require human crypto sign-off)

- **OQ-001 — Host-key trust root.** How does a verifier know `H_pub` is really the
  named host's key? TOFU on first sight; the admin-rooted chain
  (`CBCL_ADMIN_PUBKEY` — must hosts be enrolled?); or key-transparency. Same family
  as [[SPEC-013-mls-private-channels#OQ-002]].
- **OQ-002 — Revocation.** Revoking a delegation before expiry: short expiries +
  reissue (simplest), a revocation signal, or admin revoke. MVP stance?
- **OQ-003 — Signing context / domain separation.** The delegation signature MUST
  be domain-separated from the wire-envelope and [[MLS]] signing contexts,
  especially if the host key is also a wire-signing key (cf. the key-reuse question
  [[SPEC-013-mls-private-channels#OQ-001]]).
- **OQ-004 — Handle vs key in display.** The binding is to `H_pub`, but the roster
  shows *"@hugo's agent"*; the `H_pub → @hugo` handle mapping's authenticity is its
  own question (overlaps OQ-001).
- **OQ-005 — Chain depth.** May an agent host its own sub-agents (delegation
  chains)? If so, bound the depth; if not, forbid it explicitly.

## 8. Tier-1 Gate

**Status: not approved.** Before implementation, per [[PROTO-001]]: (1) cross-model
adversarial review of this spec; (2) human security sign-off resolving
OQ-001…OQ-005; (3) AI Trust Boundary metadata for the synthesis trajectory.

## 9. Verification Strategy (Phase 2 — IMPL-014)

Per the security-critical row of [[PROTO-001]]: **property-based** (sign/verify
roundtrip; reject tampered `D`); **mutation testing** on the [[#REQ-003]] verify
predicate (a surviving mutant is an identity-forgery hole); **fuzzing** the
delegation parser (untrusted input); **formal contracts** (verify pre/post,
fail-closed [[#REQ-004]]); **adversarial testing** (spoof attempts: wrong key,
expired, swapped agent key, capability injection); **cross-model review**. Each
`REQ` gets positive / negative-input / negative-output decomposition.

## 10. Relationship to SPEC-013

Both ride the **same `announce`** an agent must emit. The [[#REQ-003]] check —
*delegated key == the live wire signer* — is the **same pattern** as
[[SPEC-013-mls-private-channels#REQ-008]]'s adder verification (bind a presented
key to the authentic identity). They are independent specs (identity vs
confidentiality) that share this verification primitive and the host-key trust-root
question.

## 11. Traceability

`REQ → TEST → CODE → OBS`, `CON`/`ADR` linked as `[[wikilinks]]`, validated by
`zetl check --dead-links`. `CON-###` (the `deleg` wire form + the verify interface)
and `TEST-###` are produced in Phase 2 (`IMPL-014`).
