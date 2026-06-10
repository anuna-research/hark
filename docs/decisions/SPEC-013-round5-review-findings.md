# SPEC-013 — Tier-1 Adversarial Review Findings (Round 5)

Round-5 confirmation review of [[SPEC-013-mls-private-channels]] **v0.7.0** and
[[SPEC-016-agent-onboarding-dx]] **v0.5.0**, against the prompt in
`SPEC-013-round5-review-prompt`. The round's job: confirm or refute that the v0.7
revisions actually close R4-01…R4-05, hunt the new gap each fix may have opened,
and endorse/reject the two fix-author design calls (D-1, D-2). Code verified
against the live trees: `hark/src`, `cbcl-bus/apps/cbcl_chat`,
`cbcl-chat/crates/cbcl-mls-wasm`, and the pinned **openmls 0.8.1** source. The §10
spike evidence was treated as established (primitive behaviour only).

> **Principle-12 meta-caveat (read first).** The prompt asked for a reviewer
> *"ideally a different model than… folded rounds 3–4 (Claude Fable 5)."* This
> review was run by **Claude Fable 5** — the same model that authored the v0.7
> dispositions. The independence this round is supposed to provide is therefore
> **partial**: cross-context, not cross-model. Every "confirmed closed" below
> should be weighed with that conflict in mind, and a genuinely independent model
> (or the human cryptographer) should spot-check at least R5-01, R5-02, and R5-03
> before sign-off.

**Verdict: Gate MAY CLEAR, subject to human crypto sign-off** and a short
**pre-IMPL spec-tightening list** (R5-01…R5-04). No surviving Critical, and no
surviving High that breaks confidentiality or authenticity which the design does
not already track. R4-01…R4-05 are confirmed closed **as design intent**, and all
five are **implementable on the actual wire / openmls 0.8.1** — but four of the
fixes are under-specified or impose unstated cross-repo obligations that must be
nailed down in spec text (not re-designed) before IMPL, and the v0.7 closures live
**in spec text only** — the live web client and wasm glue still contain the
pre-fix behaviour (expected; IMPL-gated). Residual accept-list for the human signer
is at the end.

---

## D-1 — admission-path encryption pin — **ENDORSE**

REQ-023(a) / SPEC-016 REQ-007 derive the E2EE pin from the client's own act of
**presenting a cap/invite**, not from a hub-authored field. This is sound, and
sound specifically in the **safe failure direction**:

- The hub cannot forge "the client presented a cap" — that fact is local to the
  client. So the hub cannot *cause* a cleartext pin; the worst it can do is strip
  the cap (availability loss) or serve `:enc false` on a cap-pinned channel (a
  downgrade the client **refuses**, REQ-023). Confidentiality is never traded for
  the hub's word.
- Over-pinning is benign. I confirmed in the hub that a cap presented to a
  **public** room is silently accepted-and-ignored (no redemption, no error) —
  `cbcl-core-cap.lfe:9-13` short-circuits `'public ⇒ 'true` before inspecting the
  token, and the invite-redeem branch is gated on `(=:= vis 'private)`
  (`cbcl-chat-room.lfe:70-73`). So the hub provides **no "cap ⇒ private"
  invariant**; the inference is purely client-side. But the failure direction is
  safe: a client that pins encrypted on a channel the hub treats as public simply
  **fails closed** (refuses plaintext, tries an MLS bootstrap that finds no group)
  — an availability loss, never a cleartext leak. A hub adding a cap to a public
  pairing record lands in the same benign place.

Endorsed. The residuals (no-cap join paths must fail closed — R5-07; the
hub-served-JS limit on web pinning, REQ-023's own documented residual) are real
but are availability/inherent-delivery costs, not confidentiality holes.

## D-2 — creator as removal-authority liveness fallback — **ENDORSE, conditional on documenting the authority expansion (R5-02)**

The mechanism is acceptable *because* the creator is already the genesis root of
trust (REQ-016) and every removal is **signed by the creator's pinned key** and
**membership-visible** (it flips the REQ-021(a) identity number) — so a malicious
creator can evict, but cannot do so **invisibly or unattributably**, and cannot use
this power to break confidentiality or impersonate. That bounds the grant to
attributable, visible eviction of honest members — an integrity/availability
concern on a principal the threat model already treats as a potential adversary at
first contact. **Conditional:** the spec currently documents only the *orphaned-creator
availability* residual; it must also explicitly document the *malicious-creator
authority* expansion (R5-02). With that, endorse.

---

## R5-01 (Medium) — removal-evidence epoch-freshness is not pinned: stale evidence can re-remove a re-added member

**Where:** SPEC-013 REQ-014, REQ-017 clause (d).
**The defect.** Evidence is "bound to `(room, group_id, epoch, target)`" and
verified "at merge time by every validator." What is **not** stated is the
relationship the validator must enforce between the evidence's `epoch` field and
the **live merge epoch**. Concrete attack: Alice self-signs a voluntary `bye` at
epoch N (bound to epoch N). She leaves; she is later re-added at epoch N+2 (a fresh
REQ-008-validated Add she consents to). A malicious authorized committer (any
member, via deterministic election) now **replays Alice's epoch-N `bye`** in a
Remove Commit at epoch N+3. If validators only check "evidence is well-formed,
signed by the subject's pinned key, names this room/group/target" — all true — but
do **not** require `evidence.epoch == current epoch` (or a tightly-bounded window),
the stale `bye` re-evicts the re-added Alice without any fresh authorization. This
is a targeted forced-eviction / re-join DoS, and chained with attacker-controlled
re-adds it can be used to keep an honest member out while the group churns.
**Disposition.** REQ-014 / REQ-017(d) SHALL state the freshness predicate
explicitly: removal evidence is valid **only at the epoch it names** (no tolerance
window, or a justified ±1 with a stated reason), so it cannot be replayed after the
target has re-joined. State whether a re-add resets the binding (it should: the
re-added member is a new leaf at a new epoch). A charitable reading of "bound to
epoch" already intends this, which is why this is Medium and a *tightening*, not a
hole — but it is currently ambiguous enough that an implementer could ship the
replayable version.
**Classification:** under-specified clause in the R4-02 fix (brand-new-gap
potential).

## R5-02 (High, tracked-but-under-documented) — D-2 turns "the hub cannot shrink membership" into "the creator can evict anyone," and only the availability half is documented

**Where:** SPEC-013 REQ-014 clause (b), REQ-016.
**The concern.** Round 4's removal model scoped authority tightly: the **subject**
(self-signed `bye`) or **that member's own adder** (SPEC-016 REQ-012). REQ-014(b)
adds the **room creator** as a fallback remover — but nothing in the mechanism
restricts the creator to *unresponsive* members. A malicious creator can mint valid
removal evidence for **any live member**, not just crashed ones. That is a genuine
authority expansion: the round-4 invariant "no single party can shrink membership"
becomes "one member (the creator) can." The spec frames REQ-014(b) purely as a
**liveness fallback** and documents only the *orphaned-creator availability*
residual ("if the creator is itself gone, an unresponsive member persists"). It does
**not** document the *authenticity/authority* residual: that a dishonest creator now
has unilateral eviction power over the whole membership.
**Why it does not block.** The power is bounded — eviction is signed by the
creator's pinned key (attributable) and flips REQ-021(a) (visible to everyone who
compares), and the creator is already the trust root the threat model lets be
malicious. It cannot be used to add attacker keys (REQ-008/017 gate Adds) or break
confidentiality. So it is a documented-residual-class grant, not a design hole.
**Disposition.** REQ-014(b) / the residual list SHALL state plainly: *"the creator
can evict any member, not only unresponsive ones; this is a single-party
membership-shrink authority, accepted because it is key-attributable and
membership-visible (REQ-021(a)). It is not restricted to liveness recovery by any
mechanism."* This is the explicit endorsement condition for **D-2**.
**Classification:** brand-new gap opened by the D-2 fix (bounded; documentation
fix).

## R5-03 (Medium) — the REQ-016 genesis GroupContext extension imposes an unstated, spike-untested cross-repo capabilities obligation

**Where:** SPEC-013 REQ-016 (durable delivery), REQ-017 clause (e);
`cbcl-mls-wasm/src/lib.rs:71-79, 112-120`.
**Feasibility verdict: implementable on openmls 0.8.1 — but with a load-bearing
condition the spec omits.** The audit of the pinned openmls source confirms a group
*can* be created with a custom `Extension::Unknown(u16, …)` in the GroupContext, a
joiner *can* read it from the Welcome (`StagedWelcome::group_context()`), and
rejecting `GroupContextExtensions` proposals (017(e)) *does* make it immutable
(`apply_proposals.rs` has the only extension-mutating path; no ReInit branch
touches current-group extensions). **However:** an `Unknown(_)` extension is not a
"default" extension, so openmls 0.8.1 requires **every member's leaf node to
advertise that extension type in its `Capabilities`**, or it rejects the operation:
Add proposals (`validation.rs:392-405`, valn0502 `InsufficientCapabilities`),
Updates (valn0602), Welcome join (`creation.rs:313-328`, valn1415
`UnsupportedExtensions`), and received path commits (`staged_commit.rs:150-161`,
valn1210). The current wasm glue sets **neither** the GC extension **nor** the
capabilities (`lib.rs` `create`/`key_package`). So REQ-016's durable-delivery
mechanism silently requires a new, coordinated change across **both** repos: hark
*and* the web client must build every KeyPackage / create config to advertise
`ExtensionType::Unknown(N)`. If one side omits it, joins fail closed. This obligation
appears nowhere in the spec, and the §10 spike **did not exercise** unknown GC
extensions or capabilities (it tested rebind-Update, lifetime, and `max_past_epochs`
only) — so the feasibility claim is source-read, not empirically confirmed.
**Disposition.** REQ-016 SHALL state the capabilities obligation as a concrete
affected-repo requirement for both hark and `cbcl-mls-wasm`, and IMPL-013 SHALL add
a spike probe: create a group with a genesis `Unknown` extension, publish KeyPackages
advertising it, and confirm a cross-stack Add→Welcome→read round-trips. Until that
probe runs, treat R4-03's durable-delivery mechanism as **feasible-pending-verification**.
**Classification:** unstated cross-repo obligation in the R4-03 fix
(implementability — round-2 BUG-010 shape, caught early).

## R5-04 (Medium) — REQ-021(a)'s identity safety number has no pinned canonical encoding, so hark and the web client cannot be guaranteed byte-identical

**Where:** SPEC-013 REQ-021(a), REQ-024, NFR-001.
**The defect.** (a) commits to "`group_id` plus the sorted set of
(handle, leaf-signature-key) pairs." For a headless agent operator to compare the
hark value against the web UI's, the two stacks must compute the **same bytes** —
but the spec pins neither the **sort key** (by handle? by raw leaf-key bytes? by the
encoded pair?), the **encoding** of each pair, the **separator/framing**, nor the
**hash/representation** presented to the human. REQ-021(a) is the *only* first-contact
MITM defence for agents (ADR-006 leans on it via REQ-024); if hark and web disagree
on encoding, every comparison mismatches and operators learn to ignore it — which
silently disables the defence. NFR-001 pins wire-byte compatibility for MLS objects
but says nothing about this app-level digest.
**Disposition.** Pin the canonical construction in the spec (or bind it to a named
IMPL-013 contract): exact field encoding, sort order, domain-separation/framing, and
the human-facing representation. This is IMPL-blocking but mechanical — no re-design.
**Classification:** under-specified clause in the R4-04 fix.

## R5-05 (Low) — REQ-011 rotation honesty + lost-key recovery coupling

**Where:** SPEC-013 REQ-011.
**Two honesty gaps.** (1) The ceremony correctly handles a *lost* key (remove +
re-add), but a **compromised current key K** lets the attacker cross-sign a rotation
to their own K' — inherent to key compromise, but the spec doesn't say so outright.
It should, alongside the mitigation that already exists: the rotation flips
REQ-021(a), so a hijacked rotation is at least **membership-visible** to anyone who
re-compares. (2) "Recovery is remove + re-add" inherits an availability dependency
the spec doesn't flag: the remove needs an authorized remover (the member's adder,
SPEC-016 REQ-012, or the creator, REQ-014(b)). A member whose adder is gone and who
is not the creator can be **neither removed nor re-keyed** — it couples the
lost-key recovery path to the D-2 orphaned-creator residual.
**Disposition.** State the compromised-K-rotates residual + its REQ-021(a)
visibility; note that lost-key recovery is only as available as the member's
adder/creator (cross-link the orphaned-adder residual).
**Classification:** honesty/completeness tightening of the R4-05 fix.

## R5-06 (Low) — `bye`-as-evidence touches a reserved verb, and the live web/wasm code still embodies the pre-fix behaviour

**Where:** `cbcl-bus/apps/cbcl_chat/src/shell/cbcl-chat-session-ws.lfe:162-172,
273-278`; `priv/web/app.js:512-516`; `cbcl-mls-wasm/src/lib.rs:178-206`.
**Two notes.** (1) The spec records "fan the `bye` as evidence" as an affected-repo
wire change — correct, but it under-states it: `bye` is a **reserved performative**
intercepted in the hub's `route` **before** the generic fan-out path (and
`do-bye` discards the verified payload+signature, broadcasting only an unsigned
`presence` frame). Fanning it as peer-verifiable evidence means **modifying the
reserved-verb interception**, not merely "adding a verb" — a deeper change than the
new `idkey`/`rekey`/`genesis` frames, which *do* already transit untouched via the
`route` catch-all → `do-publish` with the member signature preserved
(`session-ws.lfe:172`, `cbcl-chat-room.lfe:98-106`). Worth flagging so IMPL scopes it
correctly. (2) The v0.7 closures are **spec-only** today: the web client still takes
`enc` straight from the unsigned `roomcfg` bit and **silently accepts an `:enc false`
downgrade** (`app.js:514` deletes the room from `roomEnc`) — R4-01's exact attack is
still live in shipped code — and the wasm glue still merges staged commits and stores
proposals (including external-join proposals, `lib.rs:199-204`) with **no app
checks**. Expected for a gated, pre-IMPL spec, but the gate must not be read as "the
code is safe now."
**Classification:** scoping/clarity (hub) + status note (client). Not a design hole.

## R5-07 (Low, availability) — fail-closed no-cap private join locks out a legitimate returning member

**Where:** SPEC-013 REQ-023 ("a join into a channel believed private but whose mode
the client cannot pin from (a)/(b) SHALL also fail closed").
**The cost.** A human member who returns from a fresh device / cleared localStorage
**without the invite in hand** presents no cap and has no operator-intent signal, so
REQ-023 mandates fail-closed (no plaintext send) — correct for confidentiality, but
it locks the legitimate member out of a channel they belong to. The spec's remedy
("re-presenting the invite re-derives the pin") under-discusses that humans rarely
retain a consumed invite. The hark agent is less exposed (its cap is in config /
the SPEC-016 pairing record and is re-presented automatically — confirmed
`app.js:835` `capRecall` for web, config-cap for hark). The creator's first join is
covered by operator intent (REQ-023(b)).
**Disposition.** Acknowledge the returning-member availability cost and point at the
recovery path (re-pair / re-invite). Not a blocker; a documented UX residual.
**Classification:** documented-residual completeness of the R4-01 fix.

---

## Confirmed closures (with the new-gap hunt result for each)

- **R4-01 / REQ-023 (D-1) — CLOSED (design).** Pin derives from cap-presence, a
  hub-unforgeable local fact; mode-TOFU removed; unknown private mode fails closed.
  New-gap hunt surfaced R5-07 (no-cap availability) and the hub's missing "cap ⇒
  private" invariant — both in the **safe** direction (over-pin / fail-closed,
  never a cleartext leak). Live web client not yet conformant (R5-06).
- **R4-02 / REQ-014 + REQ-017(d) — CLOSED (design), with R5-01.** Evidence verified
  at merge by every validator is **implementable**: openmls 0.8.1 exposes the
  staged proposals before merge (`StagedCommit::{add,remove,update}_proposals()`,
  `queued_proposals()`, `update_path_leaf_node()`) and lets the app drop a commit
  cleanly (epoch/tree untouched until `merge_staged_commit`). The
  availability-vs-authenticity split is stated honestly (the hub can suppress
  evidence → availability loss, not a forged removal). Residual epoch-replay window
  is R5-01.
- **R4-03 / REQ-016 — CLOSED (design), with R5-03.** The GroupContext-extension
  durable-delivery path is implementable on openmls 0.8.1 and is immutable once
  GCE proposals are rejected (017(e)); ReInit cannot alter current-group extensions
  and is detectable pre-merge. Caveat: the unstated capabilities obligation +
  spike-untested status (R5-03). The invite-fingerprint SHOULD has **no teeth**
  today (invites carry a single opaque token, no fingerprint field —
  `cbcl-chat-invite.lfe:13`, `app.js:537/800`) and does **not** quietly become
  load-bearing — the spec is honest that without it genesis is first-group-wins
  TOFU caught by the safety number.
- **R4-04 / REQ-021 + REQ-024 — CLOSED (design), with R5-04.** The split restores a
  comparison surface stable across normal Commits. Detection allocation holds:
  membership equivocation flips (a); membership-preserving tree equivocation is
  caught by (b) + the REQ-006 decrypt-failure signal. The **transient-equivocation
  window** is real and documented-class: a hub that flips membership between two
  (a) comparisons and reverts it stays below threshold **iff** the operator does
  not re-compare on the flagged membership change — i.e. it depends on the
  comparison discipline ADR-006 already lists as a residual. Byte-identical (a)
  across stacks is **not yet guaranteed** (R5-04).
- **R4-05 / REQ-011 + REQ-017(e) — CLOSED (design), with R5-05.** The fail-closed
  allowlist is **enforceable** on openmls 0.8.1 in both stacks: the app can see and
  reject each proposal type before merge, control standalone-proposal storage
  (`store_pending_proposal` is explicit, not automatic), and detect external
  commits via `Sender::NewMemberCommit` / `Proposal::ExternalInit`. Requires new
  wasm exports (the glue does none of this today — R5-06). Rotation honesty +
  lost-key coupling is R5-05.
- **R4-06 / OQ-001 — CLOSED.** `hark/src` confirms `chat_frame::encode_frame` and
  `NullSigner` are gone (commit `3dec43a`); the sole production signing path is
  `SignedConn::sign_frame` over the domain-separated, fully length-prefixed
  envelope (`signed_frame.rs:28-43`, `DS_TAG = "cbcl-signed-member/v1"`), verified
  byte-for-byte against the LFE hub vector. The live responder test bootstraps the
  signed-member wire like production. **Residual hygiene (Low):** the `FrameSigner`
  trait and its `ChatIdentity` impl are `pub` and unsealed (`identity.rs:93-97`,
  `lib.rs` `pub mod`), so a *library consumer* (not a wire/API caller) could sign
  arbitrary bytes with the identity key. Outside the wire threat model, but if
  "no public raw signer" is meant as an enforced invariant, seal the trait or make
  the impl `pub(crate)`.

---

## Cross-REQ consistency

No self-contradiction found among the touched requirements. Spot-checks:
REQ-023's pin ↔ REQ-002's keypub trigger (REQ-002 now keys off the REQ-023 pin, not
the raw `roomcfg` bit) ↔ HP-1 step 1 (pins encrypted pre-connect from cap presence)
— consistent. REQ-014 evidence ↔ REQ-017(d) merge-time check ↔ REQ-016 creator
authority — consistent modulo R5-01/R5-02. REQ-011 rotation ↔ REQ-017(c)
rebind-on-verified-assertion ↔ REQ-021(a) membership-visible stability —
consistent. The failure-modes list (§3) matches REQ-023's fail-closed clauses. No
requirement was found unimplementable on the actual wire (the BUG-010 shape):
new signed app frames transit the hub's generic fan-out untouched; the items that
*do* need affected-repo work (fanned `bye`, creator handle at `claim`, invite
fingerprint, pairing record, web pin persistence, wasm validation exports, the
genesis-extension capabilities) are enumerated below and in R5-03/R5-06.

## Affected-repo changes the spec asserts but that do not exist today

Confirmed absent in the live trees (each must be a tracked affected-repo change,
not asserted into existence):

1. `bye` fanned room-wide as signed removal evidence — today intercepted/discarded
   (`session-ws.lfe:166, 273-278`); reserved-verb change (R5-06).
2. Creator handle recorded at `claim` — `(defrecord cbcl-room name visibility cap
   encrypted)` has no creator field (`cbcl-chat-roomcfg.lfe:17`).
3. Creator-key fingerprint in invites — `(defrecord cbcl-invite token room expires
   uses)` has none; link is `#<token>` (`cbcl-chat-invite.lfe:13`, `app.js:537`).
4. SPEC-016 pairing record — **wholly absent** from `cbcl_chat`; only the router's
   agent-enrolment SPAKE2 exists, carrying router capabilities, no chat fields/cap.
5. Web-client enc pin persistence + fail-closed downgrade — today enc is recomputed
   from the unsigned `roomcfg` bit and `:enc false` is silently honoured
   (`app.js:514-516`).
6. wasm staged-proposal inspection + GroupContext-extension read/write exports +
   leaf capabilities for the genesis type — none today (`lib.rs:178-206`, R5-03).

---

## Verdict — **Gate MAY CLEAR (subject to human crypto sign-off)**

R4-01…R4-05 are confirmed closed as design intent and implementable on the actual
wire and openmls 0.8.1; R4-06 is closed in code. No surviving Critical; no surviving
High that breaks confidentiality or authenticity which the design does not already
track. The new findings are **spec tightenings and a feasibility probe**, not
re-designs.

**Pre-IMPL must-fix (spec text, before IMPL-013 — none gate-blocking re-design):**
- **R5-01** — pin removal-evidence epoch-freshness (no stale-evidence re-removal).
- **R5-02** — document the malicious-creator unilateral-eviction authority (the D-2
  endorsement condition).
- **R5-03** — state the genesis-extension capabilities obligation as a cross-repo
  requirement; add the IMPL-013 spike probe.
- **R5-04** — pin REQ-021(a)'s canonical encoding so hark/web are byte-identical.

**Residual risks the human signer must accept** (the prompt's starting list,
confirmed and extended):
1. First-contact TOFU is winnable by an active hub until safety numbers are compared
   out-of-band (humans may never compare; agents structurally depend on REQ-024).
2. Last-resort forward-secrecy residual (a draining hub forces last-resort use;
   a later init-key compromise exposes that epoch forward to the next key-updating
   Commit) — bounded by `lifetime` + replenishment.
3. Hub fan-out availability: drop / partition / **evidence-suppression** — an
   authenticity-preserving but availability-losing power the hub keeps.
4. Durable-provider on-disk delete fidelity (ADR-004 — provider not yet written).
5. `cbcl_ristretto` point validation (SPEC-016 REQ-007) — not covered by the spike.
6. **Creator-as-removal-authority (D-2)** including the orphaned-creator
   availability case **and** the malicious-creator unilateral-eviction authority
   (R5-02) — bounded by key-attribution + REQ-021(a) visibility.
7. Hub-served-JS limit on web-client pinning (REQ-023's own residual): client-side
   pinning defends against a hub *configuration*, not a hub serving malicious JS.
8. The identity-number / state-hash **detection split**: the transient-equivocation
   window between two (a) comparisons, which closes only if the operator re-compares
   on every flagged membership change (R4-04 / REQ-021).
9. The genesis-extension durable-delivery path is **feasibility-pending** until the
   R5-03 spike probe runs (source-confirmed, spike-untested).
10. **Principle-12:** this round was run by the same model (Fable 5) that folded
    round 4 — independence is cross-context, not cross-model.

## What I could NOT assess

- **Independence (Principle 12):** I am Fable 5, the model that wrote the v0.7
  dispositions. This review is not the cross-model check the protocol intends.
- **The genesis GroupContext-extension round-trip on openmls 0.8.1** — confirmed by
  source reading (the `Unknown` extension + capabilities-validation paths), **not**
  by execution. The §10 spike did not exercise unknown GC extensions, leaf
  capabilities, `queued_proposals()`, or `update_path_leaf_node()`. R5-03's probe
  is required to convert this from source-read to evidence.
- **The OpenMLS primitive behaviour already covered by the §10 spike** was not
  re-proven (rebind-Update acceptance, expired-KeyPackage rejection, persisted-state
  pruning, cross-stack interop) — treated as established input.
- **`cbcl_ristretto` point validation** (SPEC-016 REQ-007 dependency) — not in any
  reviewed code path.
- **Durable-provider (ADR-004) on-disk delete fidelity** — provider not yet written.
- **The byte-exactness of REQ-021(a) across stacks** — cannot be confirmed because
  the canonical construction is unpinned (R5-04); needs a cross-stack vector once
  pinned.
- Whether a human cryptographer concurs that the documented residuals (esp. #1, #2,
  #6, #8) are acceptable for a Tier-1 deployment — that is the sign-off's call, not
  this round's.
