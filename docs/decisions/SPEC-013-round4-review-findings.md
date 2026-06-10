# SPEC-013 — Tier-1 Adversarial Review Findings (Round 4)

Round-4 confirmation review of [[SPEC-013-mls-private-channels]] **v0.6.1** and
[[SPEC-016-agent-onboarding-dx]] **v0.4.0**, against the brief in
`SPEC-013-round4-review-brief` / prompt in `SPEC-013-round4-review-prompt`
(fresh context, cross-model per Principle 12). The round's job was to confirm or
refute the v0.6 closures of R3-01…R3-08 and hunt the new gap each fix may have
opened. Code verified against: `cbcl-bus` (live tree), `cbcl-chat/crates/cbcl-mls-wasm`,
`hark/src`. The §10 spike evidence was treated as established (primitive behaviour only).

**Verdict: Gate stays BLOCKED.** One Critical and three High findings survive —
three unclosed round-3 items and one brand-new gap opened by the R3-13 fix —
plus one Medium that would otherwise become an implementer-dependent auth
decision, and one Low hygiene item. R3-01/R3-02 are confirmed closed.

**Disposition:** every finding below is folded into **SPEC-013 v0.7.0** /
**SPEC-016 v0.5.0** (same-day); the per-finding `Disposition (v0.7)` lines record
where. A **round-5 confirmation** of the v0.7 closures + the human crypto
sign-off remain to clear the gate.

---

## R4-01 (Critical) — encryption-mode pin still has a hub-winnable first observation

**Where:** SPEC-013 REQ-023; SPEC-016 REQ-007 + ADR-003;
`cbcl-bus/apps/cbcl_chat/priv/web/app.js:514`.
**Attack:** the active hub serves `roomcfg :enc false` on first contact. REQ-023
permits first-observation TOFU of the mode, and SPEC-016 pins `enc` from a pairing
record whose contents ADR-003 itself admits cannot be authenticated against the
hub. The agent/web client can therefore pin cleartext and send plaintext into a
private channel.
**Disposition:** remove hub `roomcfg` first-observation as an acceptable source
for private/invite joins; require explicit operator intent or an
adder/agent-authenticated source not authored by the hub. Unknown private mode
must fail closed.
**Classification:** unclosed R3-05; new gap in the v0.6 fix.
**Disposition (v0.7):** REQ-023 rewritten — the pin derives from the **admission
path** (cap/invite/pairing-cap ⇒ private ⇒ encrypted, pinned before the first
send) or explicit operator intent; mode-TOFU removed; unknown private mode fails
closed. SPEC-016 REQ-007/ADR-003: the record's `enc` field is advisory; the
binding signal is the **invite-cap presence**, which the hub can strip
(availability) but not use to cause a cleartext send.

## R4-02 (High) — removal evidence is not bound to the MLS Remove validation path

**Where:** SPEC-013 REQ-014, REQ-017;
`cbcl-bus/apps/cbcl_chat/src/shell/cbcl-chat-session-ws.lfe:273`.
**Attack:** a malicious authorized committer issues a Remove for a victim without
a subject-signed `bye` or adder-auth proof. REQ-014 says removals need evidence,
but REQ-017 does not require validators to verify evidence before merging a
Remove. Current `bye` only drives local leave and hub presence; it is not fanned
as peer-verifiable evidence.
**Disposition:** require every Remove proposal/Commit to carry or reference
room/group/epoch/target-bound evidence, signed by the subject's pinned key or an
authorized remover's key, and require peers to reject Removes lacking it.
**Classification:** unclosed R3-06.
**Disposition (v0.7):** REQ-014 defines the signed removal-evidence object (own
DS label, bound to room/group/epoch/target; subject `bye` fanned to peers, or
adder/creator removal order); REQ-017 gains clause (d): evidence is verified **at
merge time by every member**, Removes without it are rejected.

## R4-03 (High) — genesis assertion is still TOFU unless the creator key is already pinned, and the current wire has no durable delivery path

**Where:** SPEC-013 REQ-012, REQ-016;
`cbcl-bus/apps/cbcl_chat/src/shell/cbcl-chat-roomcfg.lfe:17`,
`cbcl-bus/apps/cbcl_chat/src/shell/cbcl-chat-room.lfe:83`.
**Attack:** at first contact the hub can present an attacker creator handle/key
and a self-consistent signed genesis. If no creator key is already pinned out of
band, the assertion only moves the TOFU race. The current room config stores no
creator, and encrypted joins receive no history, so a room-fanned genesis
assertion is not guaranteed to reach late joiners.
**Disposition:** state that genesis is authoritative only when the creator key is
already pinned or independently authenticated; otherwise it is first-group-wins
TOFU. Put genesis evidence in the Welcome/group context or another durable,
peer-verifiable delivery path.
**Classification:** unclosed R3-08.
**Disposition (v0.7):** REQ-016 states the authority condition plainly (pinned /
independently authenticated creator key, else documented first-group-wins TOFU +
mandatory safety number); genesis rides the **GroupContext as an app extension**
(reaches late joiners inside the MLS-authenticated Welcome); invite links /
pairing records SHOULD carry the creator-key fingerprint as the out-of-band
anchor; the hub-recorded creator handle is bookkeeping, not trust.

## R4-04 (High) — safety number rotates with every Commit, weakening the only first-contact defence

**Where:** SPEC-013 REQ-021, REQ-024.
**Defect:** binding the safety number to epoch and tree hash / epoch
authenticator makes it change on every Commit. That makes out-of-band comparison
impractical for humans and headless-agent operators — exactly where ADR-006
relies on it to catch first-contact hub MITM.
**Disposition:** split the UX into a stable identity/membership safety number and
a separate epoch/state hash for fork debugging, or define a practical comparison
workflow that survives normal commits.
**Classification:** brand-new gap opened by the R3-13 fix.
**Disposition (v0.7):** REQ-021 split: (a) a **stable identity safety number**
(group_id + sorted (handle, leaf-key) bindings — changes only on membership
change / authenticated rotation) as the comparison surface; (b) a **volatile
epoch state hash** (epoch + epoch authenticator) as the fork-debugging
diagnostic, paired with the REQ-006 decrypt-failure signal. REQ-024 surfaces both.

## R4-05 (Medium) — REQ-017 closes the Update rebind but leaves key rotation and non-leaf proposals under-specified

**Where:** SPEC-013 REQ-017, REQ-011;
`cbcl-chat/crates/cbcl-mls-wasm/src/lib.rs:187`.
**Defect:** the new Add/Update/Remove/UpdatePath coverage is the right shape, but
the "flagged key-rotation" exception is not defined in REQ-011. Also
ReInit/GroupContextExtensions/external-join-style proposal handling is not
explicitly rejected or validated. Current wasm glue merges/stores protocol
messages without app checks.
**Disposition:** define an authenticated key-rotation ceremony, and fail closed
on every unsupported proposal type unless it has explicit app-level validation.
**Classification:** new gap in the R3-07 fix.
**Disposition (v0.7):** REQ-011 defines the **cross-signed rotation assertion**
(`rekey` signed by both old and new key, own DS label, room+epoch bound; lost key
⇒ remove + re-add, membership-visible); REQ-017 gains clause (e): a fail-closed
**proposal allowlist** (only validated Add/Update/Remove + committer UpdatePath;
ReInit/PSK/GroupContextExtensions/external joins rejected; the genesis extension
is immutable).

## R4-06 (Low) — bare-payload identity signing oracle still exists

**Where:** `hark/src/chat_frame.rs:29`, `hark/src/identity.rs:94`.
**Defect:** production paths now use `SignedConn`, but the public
`chat_frame::encode_frame(payload, signer)` still signs arbitrary bare payload
bytes with the identity key. OQ-001 says this legacy signer must be retired.
**Disposition:** remove or privatize the bare-payload signing API; expose only
typed/domain-separated signing contexts.
**Classification:** unclosed R3 tightening / OQ-001 hygiene.
**Disposition (v0.7):** executed in the live tree 2026-06-10 —
`chat_frame::encode_frame` + `NullSigner` removed; the only identity-key signing
path is `SignedConn` over the domain-separated `signed_frame::envelope`; the live
responder test bootstraps the signed-member wire like production. OQ-001
condition (2) done; (1) property test and (3) `idkey` DS label land with IMPL-013.

---

## Confirmed closures

**R3-01/R3-02** are textually corrected: SPEC-013 and SPEC-016 now consistently
say SPAKE2 is capability/name delivery, not the agent Authentication Service, and
they acknowledge password-equivalent verifier storage. **R3-07**'s narrow Update
credential-rebind hole is addressed in spec wording, subject to R4-05.

## Verdict

**Gate stays BLOCKED.** Must-fix: **R4-01, R4-02, R4-03, R4-04** before Tier-1
clearance. **R4-05** should be fixed before implementation because it will
otherwise become an implementer-dependent auth decision.

## Could not assess

- The OpenMLS primitive behaviour already covered by the §10 spike was not
  re-proven.
- Durable-provider delete fidelity (ADR-004 — provider not yet written).
- `cbcl_ristretto` point validation (SPEC-016 REQ-007 dependency).
- Whether future OpenMLS APIs expose all staged validation data needed by hark
  and the web client (REQ-017 staged-proposal inspection) without additional
  binding work.
