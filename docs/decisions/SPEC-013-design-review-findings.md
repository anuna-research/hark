# SPEC-013 — Tier-1 Adversarial Review Findings (Round 1)

Cross-model adversarial review of [[SPEC-013-mls-private-channels]] (v0.1.0), against
the brief in `SPEC-013-review-brief`. **Verdict: Tier-1 stays BLOCKED.** Core defect:
**MLS membership is anchored to hub-mediated TOFU and unchecked KeyPackages/Welcomes,
not to authenticated wire identity.** 8 findings (Critical/High) + 1 non-finding. Each
resolves to a new/strengthened `REQ` (the spec mandates the secure behaviour) and a
`BUG` (the current experimental impl violates it). SPEC-013 advanced to **v0.2.0**;
re-review required before sign-off.

---

## BUG-001 (Critical) — KeyPackage substitution defeats E2E membership authenticity

The MLS leaf uses a **fresh** signing key bound only to the handle
(`cbcl-mls-wasm/src/lib.rs:55`); the browser accepts `keypkg` by `:for` only and calls
`add_member` without checking the target handle or a pinned wire key
(`mls.js:108`, `lib.rs:124`). **Attack:** an untrusted hub (esp. at TOFU first contact)
binds `@victim` to an attacker key, returns an attacker KeyPackage, and gets that member
added *as* the victim. **Disposition:** [[SPEC-013-mls-private-channels#REQ-007]] (binding)
+ strengthened [[SPEC-013-mls-private-channels#REQ-008]] (verify target handle **and**
leaf key == pinned wire key) + new [[SPEC-013-mls-private-channels#REQ-011]] (authenticated
pinning). Violated REQ: REQ-008.

## BUG-002 (Critical) — Unsolicited Welcome moves a victim into the wrong group

Server→client frames are hub-attested, not signed E2E (`cbcl-chat-session-ws.lfe:13`).
The browser joins on any `welcome` with `:for == myHandle` and overwrites the room group
(`mls.js:129`); `Group::join` validates MLS structure but not the app room, expected
committer, roster, or existing group (`lib.rs:147`). **Attack:** a malicious member or
hub creates a parallel group for the same room → future victim messages encrypt to
attacker-controlled membership. **Disposition:** new
[[SPEC-013-mls-private-channels#REQ-012]] (app-bound Welcome validation). Violated REQ: new.

## BUG-003 (Critical/High) — TOFU enrolment can be preempted globally

Any first signed frame carrying `:key` enrols a handle **globally**
(`cbcl-chat-session-ws.lfe:154`, `cbcl-chat-members.lfe:31`); `keypub` is accepted before
room-membership handling (`session-ws.lfe:162`). **Attack:** a first-contact attacker or
hub squats a handle, locks out the real user, and feeds BUG-001. **Disposition:**
[[SPEC-013-mls-private-channels#REQ-011]] (pin from the member's own signed frames, not
hub assertion) + the refined trust-root [[SPEC-013-mls-private-channels#OQ-002]]. Violated REQ: new.

## BUG-004 (High) — KeyPackage replay/reuse weakens forward secrecy

The directory is untrusted and consume-once is **advisory** (`cbcl-chat-keypkg.lfe:1`);
one-time packages are popped only locally, last-resort packages are returned repeatedly
(`keypkg.lfe:48`). **Attack:** the hub replays stale/last-resort packages; if the init
private key is later compromised, captured Welcomes encrypted to the reused package are
exposed. **Disposition:** new [[SPEC-013-mls-private-channels#REQ-013]] (enforced single-use;
bounded, documented last-resort reuse); resolves [[SPEC-013-mls-private-channels#OQ-004]].

## BUG-005 (High) — MLS removal not wired → leave is not confidentiality-preserving

Chat leave removes room fan-out only (`cbcl-chat-room.lfe:127`); the WASM `remove_member`
exists but the JS controller never calls it (`lib.rs:210`). **Attack:** with an untrusted
DS, removed/compromised members keep receiving MLS ciphertext while still in the group — a
**confidentiality** hole, not liveness. **Disposition:** new
[[SPEC-013-mls-private-channels#REQ-014]] (issue an MLS Commit removing the member on room
removal/leave); removal **moved into scope**.

## BUG-006 (High) — keypub/keyget validation bypassed

Validators exist (`cbcl-core-dialect.lfe:27`) but `keypub`/`keyget` are routed **before**
generic validation (`session-ws.lfe:162`). **Attack:** malformed, giant, non-base64, or
poisoning inputs mutate directory state. **Disposition:** new
[[SPEC-013-mls-private-channels#REQ-015]] (validate directory inputs before mutation).

## BUG-007 (Medium/High) — Owner election depends on unsigned hub presence

Owner is naive lexicographic over the roster (`mls.js:55`); presence is server-originated
with a zero signature (`cbcl-chat-room.lfe:162`). **Attack:** the hub serves divergent
rosters → split groups; a malicious admitted low-handle member becomes committer and
controls adds. Alone it is liveness/integrity; **with BUG-001/002 it is
confidentiality-impacting.** **Disposition:** new
[[SPEC-013-mls-private-channels#REQ-016]] (roster/committer authenticity; split-group
resistance); refines [[SPEC-013-mls-private-channels#OQ-003]] — *"match naive" is rejected.*

## Finding-8 (Medium) — Persisted-state claim underspecified

`SPEC-013:165` says secrets persist `0600` under `identity_dir`; that stops casual local
reads, but compromise of `identity_dir` yields wire identity **plus** MLS group state →
current/future impersonation + decryption; past-message exposure depends on retained
OpenMLS secret material. **Disposition:** strengthened
[[SPEC-013-mls-private-channels#NFR-004]] + refined [[SPEC-013-mls-private-channels#OQ-005]]
— state a **precise compromise window + retention policy**.

## Non-finding — OQ-001 (key reuse): no collision found

No concrete cross-protocol signature collision: the wire envelope starts `u32-be
len(DS_TAG) ‖ "cbcl-signed-member/v1"` (`hark/src/signed_frame.rs:18`); OpenMLS signs
TLS-serialised `SignContent` with `"MLS 1.0 " ‖ label`. The encodings don't collide under
current labels. **Disposition:** [[SPEC-013-mls-private-channels#OQ-001]] reuse is
*acceptable*, but a **regression/property test** asserting no collision is **required
before REQ-007 is approved** (added to the verification strategy).

---

## Required new/strengthened requirements (the review's bottom line)

1. **Authenticated handle→wire-key pinning** (REQ-011) — pin from the member's own signed
   frames, never hub-asserted; close the first-contact gap (OQ-002).
2. **KeyPackage target + key verification** (REQ-008) — check the target handle and that
   the leaf key == the pinned wire key.
3. **App-bound Welcome validation** (REQ-012) — bind to room + authorised committer; no
   silent group replacement.
4. **Single-use KeyPackage semantics** (REQ-013) — enforced, not advisory.
5. **MLS removal on room removal** (REQ-014) — Commit-out, not just fan-out drop.

Plus REQ-015 (directory input validation), REQ-016 (roster/committer authenticity), the
NFR-004 compromise model, and the OQ-001 regression test. **Tier-1 remains blocked
pending a re-review of v0.2.0.**

---

# Round 2 (re-review of v0.2.0)

Round-1's REQs protected the **adder's local `keyget → add_member` path**, but not
**inbound** membership changes, **sender** authenticity, or the **wire support** that
REQ-011 assumes. Folded into **v0.3.0**.

## BUG-008 (Critical) — Inbound Commits/proposals bypass adder verification

REQ-008 guards the local add path, but current processing **merges any valid MLS Commit**
and stores standalone proposals (`cbcl-mls-wasm/src/lib.rs:178`); any member can publish
`deliver` (`cbcl-chat-session-ws.lfe:280`); OpenMLS `add_members` consumes pending
proposal-store entries by default. **Attack:** a malicious member sends an Add proposal /
direct Add Commit for an attacker KeyPackage; other clients accept the MLS-valid membership
change **without** checking app-level target handle, pinned wire key, or authorised
committer. **Disposition:** new [[SPEC-013-mls-private-channels#REQ-017]] — inspect every
inbound Commit + pending proposal **before merge**; every Add leaf must satisfy
target+wire-key pinning; reject unauthorised proposals.

## BUG-009 (High) — MLS sender authentication discarded → `:from` forgery

WASM returns only plaintext bytes from MLS application messages (`lib.rs:178`); the browser
renders the decrypted inner CBCL `:from` as **verified** (`mls.js:141`, `app.js:524`).
**Attack:** Mallory (a real member) encrypts `(tell @room "…" :from @alice)`; MLS
authenticates *Mallory's* leaf, but the UI attributes it to Alice. **Disposition:** new
[[SPEC-013-mls-private-channels#REQ-018]] — expose the authenticated MLS sender leaf and
**reject decrypted CBCL whose `:from` ≠ that sender's pinned handle.**

## BUG-010 (Critical, spec gap) — REQ-011's pin source isn't peer-verifiable on the wire

REQ-011 says "pin from a member's own verified signed frames" — but server→client frames
are bare/hub-attested and **clients do not verify inbound signatures**
(`cbcl-chat-session-ws.lfe:13`, `app.js:255`, `hark/src/chat_frame.rs:10`); the hello
`:key` is consumed by the hub, **not fanned** as a peer-verifiable assertion. So REQ-011 is
**not implementable** on today's wire. **Disposition:** new
[[SPEC-013-mls-private-channels#REQ-019]] — a **peer-verifiable identity/key-assertion wire
contract** (fan enough signed-member envelope metadata for peers to verify, or an explicit
signed key-assertion frame). REQ-011 depends on it; refines the [[SPEC-013-mls-private-channels#OQ-002]] trust root.

## R2-4 (High) — OQ-004 "directory-enforced single-use" trusts the untrusted hub

v0.2.0 REQ-013 said one-time packages are "consumed atomically **at the directory**" — but
the directory **is** the untrusted hub, which can replay/drain/re-serve regardless.
**Disposition:** **OQ-004 reopened**; REQ-013 corrected to **client-side** replay detection
(transcript-visible `KeyPackageRef`s, reject duplicate refs; define last-resort compromise
cost).

## BUG-011 (High, operational) — the LIVE product still advertises unaudited E2EE

Implementation is gated (`SPEC-013:21`), but private rooms are configured **encrypted**
(`cbcl-chat-roomcfg.lfe:30`), the browser **boots MLS** (`app.js:29`), and the UI labels
private channels **"end-to-end encrypted"** (`index.html:503`). The disclosure hedges, but
the **security label** still makes a confidentiality/authenticity claim the implementation
does not back (and round-1/2 show it is broken). **Disposition:** new
[[SPEC-013-mls-private-channels#REQ-020]] — until the gate clears, the UI SHALL NOT claim
E2EE/confidentiality for private channels. **Immediate action recommended on the live
deployment** (downgrade wording or disable private-E2EE).

## Non-finding — still no signature collision (OQ-001)

Confirmed again. Keep the regression/property test before approving key reuse.

**Tier-1 remains BLOCKED.** v0.3.0 needs round-3 re-review; OQ-002/003/004 are OPEN.
