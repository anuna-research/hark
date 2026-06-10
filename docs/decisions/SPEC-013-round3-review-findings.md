# SPEC-013 — Tier-1 Adversarial Review Findings (Round 3)

Cross-model adversarial review of [[SPEC-013-mls-private-channels]] **v0.5.0** (primary)
and [[SPEC-016-agent-onboarding-dx]] **REQ-007 + ADR-003** (SPAKE2 pairing), against the
brief in `SPEC-013-review-brief`. Reviewer model: **Claude Fable 5** (specs drafted with
Claude Opus 4.8 — different model, same vendor; noted per Principle 12). Code verified
against: `cbcl-bus` (live tree: `apps/cbcl_chat`, `apps/cbcl_bus`, `apps/cbcl_router`),
`cbcl-chat/crates/cbcl-mls-wasm` (OpenMLS pinned `0.8`), `hark/src`.

**Verdict: Gate stays BLOCKED.** Two Critical and four High findings, plus the round-2
REQ-020 action still unexecuted on the live tree. The v0.4/v0.5 design genuinely closes
the round-1/2 findings *as enumerated*, but the closure opened or exposed adjacent gaps:
two hub-attested triggers (`:enc`, leave) sit underneath the new authenticated spine, the
Update-proposal path reopens `:from` forgery, and the SPEC-016 pairing cannot deliver the
Authentication-Service role ADR-006 assigns it.

---

## R3-01 (High) — ADR-006's agent-AS claim is unsubstantiated: SPAKE2 pairing carries no peer identity material

**Where:** SPEC-013 ADR-006 / OQ-002; SPEC-016 REQ-007.
**Defect:** The pairing record is `{agent-name, channel, cbcl-chat-invite cap, adder,
dialects, exp}` — no member keys, no group fingerprint, no adder pin. After pairing, the
agent's handle→key pins still come exclusively from hub-fanned `idkey` frames (REQ-019),
i.e. raw TOFU with the hub controlling fan-out. Moreover the record is hub-stored and
hub-released: with plain SPAKE2 the hub holds password-equivalent material (see R3-02),
so record contents can never be authenticated *against* the hub by phrase-derived keys.
The phrase therefore anchors **capability delivery to the intended agent against third
parties** — it anchors nothing about peer identity, and the hub remains the de facto AS
for agents. ADR-006's claim that SPAKE2 resolves OQ-002 for agents does not hold under
the stated threat model.
**Disposition:** Either (a) re-scope ADR-006 honestly — SPAKE2 anchors capability + name
only; agent first-contact identity is hub-TOFU; the agent's compensating control is a
mandatory safety-number surface (see R3-13) — or (b) redesign so the *adder* commits the
record contents end-to-end (requires an augmented PAKE or a high-entropy phrase; with
plain SPAKE2 + low-entropy phrase the hub can always forge). The spec must stop claiming
the residual first-contact gap is "anchored" for agents.
**Regression/new:** New (first Tier-1 review of this piece).

## R3-02 (High) — "stored only as an HMAC" is impossible for a SPAKE2 responder; stored verifier is password-equivalent and offline-crackable

**Where:** SPEC-016 REQ-007, OQ-001 decision; `cbcl-bus/apps/cbcl_router/src/crypto_core/cbcl-crypto-spake2.lfe:143-165`.
**Defect:** `init-responder` requires `password_bytes` to derive `w` — the responder
cannot run SPAKE2 from a one-way digest. Whatever the hub stores to execute the handshake
(the phrase, `w`, or HMAC-as-password-input) is **password-equivalent**: SPAKE2 (RFC 9382)
is not an augmented PAKE. A reader of the hub's pairing table can complete the pairing as
either side. Additionally a 3–4-word BIP39 phrase is 33–44 bits; even a genuine one-way
digest would fall to offline search in minutes–days. The practical delta is small (a hub
DB reader already holds the record + cap), but the spec's storage claim is false as
written and will mislead the human signer.
**Attack:** attacker with hub-DB read access recovers the phrase/`w`, races the operator's
agent to redeem the pairing, joins the channel under the adder-chosen name.
**Disposition:** Rewrite REQ-007: state that the stored verifier is password-equivalent
(or adopt SPAKE2+), and bound the exposure with single-use + short TTL + attempt counter
(R3-04). Delete "stored only as an HMAC" or qualify it as integrity-only.
**Regression/new:** New.

## R3-03 (Medium) — SPAKE2 reuse silently imports enrolment-specific transcript constants

**Where:** SPEC-016 REQ-007/ADR-003; `cbcl-crypto-spake2.lfe:8-9,148,160` (idB =
`"cbcl-router:" ++ deployment_id`), `:77-79` (salt `"CBCL-enrollment-v1"`), `:115-121`
(MAC labels `cbcl-agent-confirm`/`cbcl-router-confirm`), `:7` (password encoding is
3-word/5-byte `<<i1:11,i2:11,i3:11,0:7>>`).
**Defect:** The module hard-codes router-enrolment identities and context strings. Reused
as-is for chat pairing, a pairing transcript is domain-indistinguishable from an enrolment
transcript, `agent_id` is undefined for pairing, and the 4-word phrase the spec promises
does not fit the 5-byte encoding. The brief's question — "any binding/transcript
assumption that doesn't hold?" — answer: yes, the identity binding.
**Disposition:** REQ-007 SHALL pin pairing-specific identity strings (e.g. idB =
`"cbcl-chat-pair:" ++ hub_id`, defined idA), a pairing-specific HKDF salt/info, and an
encoding covering 4 words; and SHALL bind the record release to the PAKE output (release
encrypted/MAC'd under K, not merely "after success").
**Regression/new:** New.

## R3-04 (Medium) — Online-guess bounding is asserted, not mechanized

**Where:** SPEC-016 REQ-007 ("Single-use, short TTL"); OQ-001 decision.
**Defect:** Single-use fires on *success*; nothing in the spec bounds **failed** attempts
within the TTL. A 3-word phrase is 2^33; "one online guess per run" is a property of each
run, not a budget. Nothing prevents many runs against one record.
**Disposition:** REQ-007 SHALL specify a failed-attempt bound (e.g. delete the record
after 3 failed MAC verifications) and hub-side rate limiting, with tests.
**Regression/new:** New.

## R3-05 (Critical) — Encryption-mode downgrade: REQ-005's trigger is a hub-attested bit

**Where:** SPEC-013 REQ-002/REQ-005/HP-1 ("hub returns `(roomcfg … :enc true)` → agent
recognises encryption"); `cbcl-bus/apps/cbcl_chat/src/shell/cbcl-chat-room.lfe:90-93`
(roomcfg fanned with `zero-sig`), `cbcl-chat-roomcfg.lfe:74-79`.
**Attack:** The active hub sends the agent `(roomcfg @room :enc false)` on join. REQ-005
applies only "in an encrypted channel", so the agent (and the web client, identically)
emits **plaintext** into the private channel. The hub reads every message that member
sends. No round-1/2 REQ touches this: the entire new spine authenticates *membership*,
but the decision "is this channel E2EE at all" still rests on an unsigned hub frame.
The SPEC-016 pairing record does not carry the mode either.
**Disposition:** New REQ — the client SHALL pin the channel's encryption mode from
operator intent (hark config / the pairing record gains an `enc` field) or
first-observation TOFU; on a downgrade observation the client SHALL refuse to send
(fail closed), never fall back to plaintext. Web client: same pin in local storage.
**Regression/new:** Genuinely new (worst finding of this round).

## R3-06 (High) — REQ-014's removal trigger is hub-attested → hub-controlled eviction of E2EE members

**Where:** SPEC-013 REQ-014; `cbcl-chat-room.lfe:126-136,153-167` (leave/DOWN → unsigned
presence broadcast).
**Attack:** Leave/removal is observed via unsigned presence/leave events. An active hub
fabricates "@alice left" → the deterministic committer (REQ-016) dutifully issues a real
MLS Remove Commit → the hub evicts arbitrary members from the cryptographic group, churns
epochs at will, forces re-adds that drain one-time KeyPackages toward the last-resort
residual (REQ-022), and can partition who is in the group. This contradicts REQ-016's
claim that "the hub cannot fabricate MLS membership" — it cannot *grow* it, but it can
*shrink* it by fiat.
**Disposition:** Removal SHALL require authenticated evidence: a member-signed `bye`
fanned to peers (the REQ-019 pattern), or adder-authorized removal (SPEC-016 REQ-012);
hub presence MAY only *prompt* a removal decision, never constitute it. Document the
remaining hub power (it can always partition fan-out — availability, not authenticity).
**Regression/new:** New.

## R3-07 (Critical) — REQ-017 validates Add leaves only; the Update path rebinds a handle and reopens `:from` forgery

**Where:** SPEC-013 REQ-017 ("every **Add** leaf"), REQ-018; RFC 9420 §7.3/§12.1.2 (leaf
credential MAY change on Update; continuity is the application/AS's job);
`cbcl-mls-wasm/src/lib.rs:193-204` (proposals stored unchecked today).
**Attack:** Member @mallory publishes an Update proposal (or a self-committed Commit with
an update path) replacing her leaf node with one whose BasicCredential identity reads
`@alice` — MLS-valid; credential continuity across Update is explicitly not the
protocol's job. REQ-017 as written inspects only Add leaves, so the change merges. Now
REQ-018 resolves Mallory's sender leaf → credential says `@alice` → pinned-handle check
**passes** for a forged `:from @alice`. The round-2 fix for BUG-009 is bypassed end-to-end.
**Disposition:** REQ-017 SHALL validate **every leaf-changing object**: Add, Update,
Remove proposals and the committer's UpdatePath leaf — credential identity SHALL be
immutable per member; leaf signature key SHALL equal the pinned wire key; a key change is
only acceptable through the flagged-rotation path of REQ-011, never silently.
**Regression/new:** Regression-shaped — reopens BUG-009 through a path round 2 did not
enumerate.

## R3-08 (High) — REQ-016's bootstrap root of trust ("the room creator") has no verifiable existence

**Where:** SPEC-013 REQ-016, REQ-012(b); `cbcl-chat-roomcfg.lfe:17` (record is
`name/visibility/cap/encrypted` — **no creator field**); `cbcl-mls-wasm/src/lib.rs:25`
(web MLS storage is in-memory — creator state evaporates on refresh).
**Defect:** Nothing on the wire or in hub state records who created a room, and the spec
provides no creator-signed group announcement. "The room creator bootstraps" is therefore
unimplementable as a *checkable* rule (the BUG-010 failure shape): a malicious member —
or the hub at first contact — can stand up a rival group claiming creatorship, and a
joiner cannot distinguish them except via pins + safety number, i.e. the same TOFU
residual. Compounding this, REQ-012(b)'s "authorised committer (the elected owner for the
current roster)" is **circular at join time**: the joiner computes the election over the
tree *the Welcome itself provides*, so a fabricated group elects its own fabricated owner
consistently. The check with actual teeth is leaf-vs-pin validation, which REQ-012 never
states.
**Disposition:** (a) Define bootstrap concretely: a creator principal minted at `claim`
plus a creator-signed group announcement (REQ-019-style), or explicitly document
first-group-wins + mandatory safety-number confirmation as the accepted bootstrap. (b)
Amend REQ-012: the joiner SHALL validate **every leaf** of the Welcome's ratchet tree
against its pins where pins exist (not just identify a committer), and SHALL treat a tree
containing an unpinned key for a pinned handle as a hard reject.
**Regression/new:** New instance of the round-2 BUG-010 pattern.

## R3-09 (Medium) — Delete-on-use ordering: a rejected Welcome must not burn the init key; "first Welcome wins" is hub-chosen

**Where:** SPEC-013 REQ-013 ("on consuming a one-time KeyPackage (Welcome processed) …
delete its init private key"), REQ-012.
**Attack:** If "processed" means structurally-decrypted, a malicious hub or member sends
a Welcome to the victim's package that *fails* REQ-012 validation — the key is deleted,
the package is burned, and the honest committer's Welcome to the same package is now
permanently inert (DoS on join, and the hub chooses which of two racing Welcomes wins —
steering the victim toward an attacker group while bricking the honest one).
**Disposition:** REQ-013 SHALL pin the sequence: decrypt → full REQ-012/REQ-017
validation → join succeeds → **then** delete (memory + storage); a rejected Welcome SHALL
leave the init key intact. NFR-004 SHALL note that unconsumed init keys persist at rest
(part of the compromise window). Note also the consumed-ref ledger is in-memory on the
web client (lost on refresh) — state that the ledger guarantee is durable-client-only.
**Regression/new:** New (refines the OQ-004 resolution).

## R3-10 (Medium) — Last-resort residual is understated and bounded only by prose

**Where:** SPEC-013 REQ-022, OQ-004.
**Defect:** (a) The exposure is not "Welcomes encrypted to a reused last-resort package"
— a Welcome contains the joiner's epoch secrets, so a captured Welcome + later init-key
compromise yields **the group's message confidentiality for that epoch and forward until
the next key-updating Commit**. (b) "Rotated on a documented schedule" is policy with no
mechanism. MLS leaf nodes carry a `lifetime`; expiry can be protocol-enforced.
**Disposition:** REQ-022 SHALL state the epoch-level consequence, SHALL mandate a short
`lifetime` on last-resort KeyPackages, and REQ-008/REQ-017 SHALL reject expired
KeyPackages (confirm OpenMLS 0.8's lifetime validation is on, or check explicitly).
**Regression/new:** New (refines OQ-004).

## R3-11 (Medium) — OQ-005 retention: the knobs exist, but the new storage provider is the real enforcement point, and resumption PSKs are unaddressed

**Where:** SPEC-013 OQ-005 / NFR-004 / ADR-004; OpenMLS `0.8`
(`cbcl-mls-wasm/Cargo.toml:25`).
**Defect:** OpenMLS exposes `max_past_epochs` and
`SenderRatchetConfiguration{out_of_order_tolerance, maximum_forward_distance}` — the
"current epoch + bounded window" shape is implementable. But: (a) the **ResumptionPskStore
retains past-epoch resumption PSKs independently** of message secrets — the spec never
mentions it; (b) all OpenMLS "pruning" is delegated to the `StorageProvider`'s delete
calls — and ADR-004 has hark writing a **new durable provider**. A provider that ignores
deletes silently retains every superseded secret at rest, defeating OQ-005 with no
API-level symptom.
**Disposition:** NFR-004/OQ-005 SHALL name the concrete config (`max_past_epochs`, the
ratchet window values, resumption-PSK policy) and add a TEST asserting superseded epoch
secrets and consumed init keys are **absent from disk** after a Commit merge / Welcome
consumption. Flag the exact OpenMLS 0.8 retention semantics for human confirmation.
**Regression/new:** New (refines OQ-005; partially what the brief asked round-3 to confirm).

## R3-12 (Medium) — REQ-006's silent drop conflicts with fork/equivocation detection

**Where:** SPEC-013 REQ-006, REQ-016, REQ-021.
**Defect:** A hub that equivocates Commit ordering forks the group; the observable
symptom on each side is persistent decrypt failure — which REQ-006 mandates dropping
silently. The one detection signal the design has is suppressed by its own requirement.
**Disposition:** Drop-but-count: REQ-006 SHALL require surfacing persistent decrypt
failure (N consecutive failures from a pinned member) as a probable-fork warning, feeding
the REQ-021 comparison.
**Regression/new:** New.

## R3-13 (Medium) — REQ-021 safety number: wrong domain, and no agent surface

**Where:** SPEC-013 REQ-021; SPEC-016 (no corresponding REQ).
**Defect:** (a) A fingerprint "over the group members' pinned wire keys" does not bind
group identity or state: two rooms with identical members share a number, and tree-level
equivocation with the same key set is invisible. MLS already gives the right object — the
**epoch authenticator / tree hash** commits to group_id, epoch, and every leaf. (b)
Agents are headless and ADR-006 leans on safety numbers as the catch-all mitigation, yet
no REQ anywhere gives hark a safety-number surface — the agent cannot participate in the
only mechanism that catches first-contact MITM.
**Disposition:** Derive the safety number from group_id + epoch + tree hash (or the epoch
authenticator); add a REQ (SPEC-013 or 016) for `hark safety-number` so the operator can
compare against the web UI.
**Regression/new:** New.

## R3-14 (Low) — REQ-019's nonce is decorative as specified

**Where:** SPEC-013 REQ-019.
**Defect:** Replaying an honest `idkey` re-asserts the same honest binding — harmless.
The dangerous primitive is hub *substitution* of a different self-signed assertion, which
no nonce prevents. The spec does not say who generates N or what a peer checks it
against, so the "replay-bound" claim is unverifiable. (The room binding, by contrast, is
real and SHALL stay.)
**Disposition:** Specify N's purpose (e.g. bind to the current connection epoch to
prevent re-pinning a stale key after a flagged rotation) or remove the implied security
claim. Confirmed: REQ-019 is implementable on the wire (unlike round-2's REQ-011) because
the signature context is self-contained — `DS_TAG' ‖ room ‖ nonce ‖ key`, independent of
`conn_nonce`/`seq`; pin a distinct DS label for it so it cannot be confused with the
envelope (extends the OQ-001 analysis).
**Regression/new:** New (tightening of the round-2 fix).

## R3-15 (High, operational) — REQ-020's "immediate action" is still not executed

**Where:** `cbcl-bus/apps/cbcl_chat/priv/web/index.html:504` ("private · invite-only ·
end-to-end encrypted"), `:517` ("**Private channels** are **end-to-end encrypted**");
`app.js:13-43` still boots MLS into live rooms.
**Defect:** Round 2 (BUG-011) demanded the live claim come down immediately,
independent of the gate; SPEC-013 v0.5.0 encodes this (REQ-020) — and the live tree
still makes the claim. The spec is internally consistent; the deployment is not
compliant with it.
**Disposition:** Ship the wording change now. It is gated on nothing.
**Regression/new:** Regression — an unexecuted round-2 required action.

---

## Non-finding — OQ-001 key reuse: independently re-derived, no collision (third confirmation, sharper argument)

The wire envelope (`hark/src/signed_frame.rs:34-43`) always begins
`0x00 0x00 0x00 0x15` (u32-be length of the 21-byte `DS_TAG`). RFC 9420 `SignWithLabel`
signs `SignContent = opaque label<V> ‖ opaque content<V>` where the label is
`"MLS 1.0 " ‖ Label` — so the first byte is a TLS varint label length **≥ 0x10 and never
0x00**. The two signed-byte domains are disjoint at byte 0, and MLS verifiers
*reconstruct* the expected label rather than parsing it, so no byte string can verify in
both contexts. Also checked: the legacy bare-payload signer
(`hark/src/chat_frame.rs:24-35`, `identity.rs:93-97`) signs raw CBCL with the same key —
no collision either (an agent only signs payloads it constructs, beginning `(` = 0x28,
and a verifier-reconstructed `"MLS 1.0 …"` label can never match), **but** it is the one
context without domain separation. Conditions for approving REQ-007/ADR-002: (1) the
already-required no-collision property test; (2) retire the bare-payload signer when
slice-6 lands and **prohibit any future raw-bytes signing oracle** with the identity key;
(3) give the REQ-019 `idkey` context its own DS label (R3-14). SPAKE2 involves no Ed25519
— no interaction.

---

## Verdict — **Gate stays BLOCKED**

Must-fix before re-review:

1. **R3-05** — pin the channel encryption mode client-side; refuse-to-send on downgrade (Critical).
2. **R3-07** — extend REQ-017 to all leaf-changing proposals/paths; credential immutability (Critical).
3. **R3-01** — re-scope or redesign ADR-006's agent-AS claim (High).
4. **R3-02** — correct REQ-007's storage claim; document password-equivalence (High).
5. **R3-06** — authenticated leave/removal evidence for REQ-014 (High).
6. **R3-08** — implementable bootstrap root of trust + leaf-vs-pin validation in REQ-012 (High).
7. **R3-15** — execute the live-UI fix now (High, operational, gate-independent).

R3-03/04/09/10/11/12/13/14 are spec-tightening that should fold into the same revision;
none independently blocks, but R3-09 (delete ordering) and R3-11 (storage-provider
deletes) will become security holes in IMPL if left unstated.

**Where the design is sound** (stated against the threat model, not as deference): the
membership spine REQ-019→011→008→017→012→018 is the right shape — once R3-07/R3-08 close
it, every inbound and outbound membership change and message is checked against a
peer-verified pin, and the hub is left with only first-contact substitution and fan-out
partition. REQ-007/ADR-002's key reuse is safe under the pinned encodings (above).
Client-side delete-on-use (REQ-013) is the correct response to round-2's R2-4 — the
publisher is the only party that can enforce single-use against an untrusted directory.
The residual a human signer must accept: **first-contact TOFU remains winnable by the hub
by construction** for both humans (until safety numbers are actually compared) and agents
(structurally, until R3-01 is re-scoped); and the hub retains full availability power
(drop/partition), which no requirement claims otherwise.

## What this review could NOT assess

- **OpenMLS 0.8 exact behavior**: default leaf-`lifetime` validation, Update-path
  credential checks, `ResumptionPskStore` retention defaults, and whether
  `merge_staged_commit` issues storage deletes for superseded epoch secrets — asserted
  here from general OpenMLS knowledge, not verified against the pinned minor version's
  source. A human should confirm before sign-off (R3-10/R3-11 depend on it).
- **`cbcl_ristretto` NIF correctness** (point validation, identity-element rejection in
  SPAKE2 — a non-canonical or low-order msg_A/msg_B must be rejected; `from_hash`/
  `scalar_reduce` assumed sound). Wants a human cryptographer or test vectors.
- **The web client's full pin/rendering path** (`app.js` spot-checked only at the MLS
  boot and `:from` rendering sites named by rounds 1–2).
- **The live Fly deployment** — reviewed the repo tree, not the deployed artifact;
  R3-15 assumes the deploy matches the tree.
- **SPAKE2 composition with the WS transport** — whether the record release is
  cryptographically bound to the PAKE-derived K (flagged in R3-03) cannot be checked
  because the pairing wire flow has no spec'd frames yet.
- **No formal/machine-checked analysis** of the MLS AS substitution (R3-01/R3-08
  reasoning is manual); the safety-number-over-epoch-authenticator recommendation
  (R3-13) deserves a cryptographer's confirmation that the epoch authenticator is the
  right binding object for cross-client comparison.

---

## Disposition status (folded 2026-06-10)

All findings folded into **SPEC-013 v0.6.0** and **SPEC-016 v0.4.0**:

- R3-05 → SPEC-013 REQ-023 (new). R3-07 → REQ-017 (extended to all leaf-changing objects).
- R3-01/R3-02 → ADR-006 re-scoped + SPEC-016 REQ-007/ADR-003 rewritten. R3-03/R3-04 →
  SPEC-016 REQ-007 (pairing transcript constants + failed-attempt bound).
- R3-06 → REQ-014 (authenticated removal). R3-08 → REQ-012 + REQ-016 (bootstrap + full-tree pin).
- R3-09 → REQ-013 (delete ordering). R3-10 → REQ-022 (epoch-scope + lifetime). R3-11 → NFR-004
  (concrete knobs + resumption PSK + disk-absence test). R3-12 → REQ-006 (drop-but-count).
  R3-13 → REQ-021 + REQ-024 (new agent surface). R3-14 → REQ-019 + OQ-001 (DS label + signer hygiene).
- R3-15 → REQ-020 executed in the live tree (index.html wording, 2026-06-10).

The gate **remains BLOCKED**: folding the dispositions is not the same as clearing them. A
**round-4 confirmation** (fresh context) + human crypto sign-off are still required, per
SPEC-013 §8. The "could NOT assess" items above (OpenMLS 0.8 retention/lifetime/Update
semantics; `cbcl_ristretto` point validation) are unchanged and must be confirmed by a human.
