# SPEC-013 Round-5 Review — paste-ready prompt

> **How to use.** Paste everything below the line into a **fresh context, ideally a
> different model** than drafted the specs (Claude Opus 4.8) or folded rounds 3–4
> (Claude Fable 5) — Principle 12, no self-validation. The reviewer should have read
> access to the `hark`, `cbcl-bus`, and `cbcl-chat` repos; everything needed to *frame*
> the review is inlined so it is sound even if repo access is partial. The deliverable
> is a findings doc + an explicit verdict.

---

You are an **independent cryptographic and security reviewer**. You did not write these
specifications and you owe them no deference. This is **round 5** of an adversarial review
of a Tier-1 (no-go) design — agents joining MLS-encrypted private channels and the
signed-member authentication core. Round 4 confirmed the round-3 SPAKE2 findings closed but
found **1 Critical + 3 High + 1 Medium + 1 Low** (R4-01…R4-06); the spec authors then
revised to SPEC-013 **v0.7.0** / SPEC-016 **v0.5.0** claiming to close all six.

**Your job is NOT to re-run rounds 3–4 from scratch.** It is to **confirm or refute that
the v0.7 revisions actually close R4-01…R4-05 — and to hunt the new gap each fix may have
opened.** A fix that *relocates* a hole rather than closing it is the specific thing to
find. Default to skeptical: trace every claimed closure to a concrete, checkable mechanism
in the spec (and, where it claims to fix code, to the code). If a mitigation is asserted
but you cannot trace it to a mechanism, treat it as unproven and say so. Do not soften
findings.

Additionally, **two design calls were made by the fix author, not the project owner**, and
this round must explicitly endorse or reject each (they are flagged PROPOSED in the spec):

- **D-1 — admission-path encryption pin** (REQ-023(a), SPEC-016 REQ-007): the E2EE pin
  derives from *presenting a cap/invite/pairing-cap* (cap ⇒ private ⇒ encrypted, pinned
  pre-send) rather than from a redesigned, adder-authenticated pairing record.
- **D-2 — creator as removal-authority liveness fallback** (REQ-014(b)): the room creator
  (the REQ-016 genesis principal) may authorise removal of an unresponsive member that can
  never sign its own `bye`.

## Threat model (assume all of it — unchanged from round 4)

- **The hub is the untrusted MLS Delivery Service.** It routes all frames and serves the
  KeyPackage directory, presence, and rosters. It is **active**: it may drop, reorder,
  replay, forge, **equivocate** (show different members different views), **squat handles**
  at first contact, and **drain** the one-time KeyPackage pool. Server→client frames are
  hub-attested, **not** signed end-to-end unless a spec mechanism makes them so. The web
  client is **hub-served code** (a documented residual — flag anything that leans on
  web-client behaviour as if it were trustworthy against the hub).
- **Members may be malicious** — including **authorized committers** and the **room
  creator**. An admitted member may add attacker keys, forge `:from`, publish unauthorised
  proposals/Commits, or fork the group.
- **First contact has no prior shared secret** beyond an out-of-band invite (humans) or a
  BIP39 phrase delivered out-of-band (agents).
- Endpoints are honest *until* compromised; `identity_dir` at-rest compromise is in scope
  for retention (OQ-005 / NFR-004); **wire-identity-key compromise** is in scope for the
  new rotation ceremony (REQ-011).

## What to read (the deltas, not the whole spec again)

- **`hark/docs/decisions/SPEC-013-round4-review-findings.md`** — the finding→fix map; each
  finding carries a `Disposition (v0.7)` pointer.
- **`hark/specs/SPEC-013-mls-private-channels.md` v0.7.0** — §8 (Tier-1 Gate) for the map,
  then the changed requirements:
  - **REQ-023** (rewritten) — mode pin derived from the admission path or operator intent;
    mode-TOFU removed; unknown private mode fails closed.
  - **REQ-014** (rewritten) — signed removal-evidence object (own DS label, bound to
    room/group/epoch/target); subject `bye` fanned as evidence; adder/creator authority.
  - **REQ-017** — new clauses **(d)** evidence verified at merge by every validator, and
    **(e)** fail-closed proposal allowlist (ReInit/PSK/GroupContextExtensions/external
    joins rejected; genesis extension immutable).
  - **REQ-016** — genesis authoritative only with a pinned/independently authenticated
    creator key, else documented first-group-wins TOFU; durable delivery via a
    **GroupContext application extension**; invite links SHOULD carry the creator-key
    fingerprint; hub-recorded creator handle = bookkeeping, not trust.
  - **REQ-011** — the **cross-signed `rekey` rotation ceremony** (signed by old AND new
    key, own DS label, room+epoch bound); lost key ⇒ remove + re-add (membership-visible).
  - **REQ-021** (split) — **(a)** stable identity safety number (group_id + sorted
    (handle, leaf-key) bindings; changes only on membership change / authenticated
    rotation) as the comparison surface; **(b)** epoch state hash (epoch + epoch
    authenticator) as the fork diagnostic paired with REQ-006.
  - **REQ-024** — surfaces both values; compare-once-then-on-change workflow.
  - **REQ-002** — keypub trigger moved from the raw `roomcfg` bit to the REQ-023 pin.
  - **OQ-001** — bare-payload signer retirement marked DONE (verify in code, below).
- **`hark/specs/SPEC-016-agent-onboarding-dx.md` v0.5.0** — REQ-007 (the `enc` field is
  now advisory; the pin derives from invite-cap presence) + ADR-003.
- Code oracles: `hark/src/{chat_frame,signed_frame,signed_transport,identity}.rs` (R4-06
  retirement — confirm no bare-payload identity-signing API remains);
  `cbcl-bus/apps/cbcl_chat/src/shell/` (LFE hub: `cbcl-chat-room.lfe` `join-allowed?`,
  `cbcl-chat-roomcfg.lfe` claim/get, `cbcl-chat-invite` redemption) for whether the wire
  can carry what the new REQs require; `cbcl-chat/crates/cbcl-mls-wasm/src/lib.rs` +
  OpenMLS 0.8 APIs for whether REQ-017(d)/(e) and the REQ-016 GroupContext extension are
  implementable (staged-proposal inspection, app extensions in the Welcome).

## Provided input — established evidence (audit only if you doubt it)

The §10 spike (`hark/experiments/spec-013-mls-spike`, openmls 0.8.1 pinned to
`cbcl-mls-wasm`) remains established: OpenMLS accepts a credential-rebinding self-Update
(REQ-017(c) is load-bearing); `KeyPackageIn::validate()` rejects expired KeyPackages;
`max_past_epochs`/`number_of_resumption_psks`/`sender_ratchet_configuration` exist and
pruning reaches persisted state; native OpenMLS ⇄ `cbcl-mls-wasm` interoperate both ways.
The spike confirms the **primitive**, not the spec's **app-level closures**. Those are
your job.

## Confirm each closure — AND hunt the new gap it might open

1. **R4-01 / REQ-023 + SPEC-016 REQ-007 (D-1).** Does deriving the pin from the admission
   path actually remove every hub-winnable first observation? **New-gap hunt:** enumerate
   the join paths — is there any path into a private channel that presents **no**
   cap/invite and has **no** explicit operator intent (a member rejoining from a fresh
   device/cleared localStorage without the invite at hand; the hark agent reconnecting
   after losing its pin store; the creator's own first join)? Does each fail closed or
   silently fall back to the hub bit? Check `join-allowed?`/`allow-join?` in the LFE hub:
   can a **public** room ever admit a presented cap (which would break "cap ⇒ private" —
   note the failure direction)? Can the hub *add* a cap to a public-channel pairing record,
   and is that direction actually harmless? Is REQ-023 consistent with HP-1, REQ-002, and
   the failure-modes list?
2. **R4-02 / REQ-014 + REQ-017(d) (and D-2).** Is the evidence object's binding complete
   and replay-proof — what are the **epoch semantics** (evidence minted at epoch N, the
   Remove Commit lands at N+k: tolerated window? can stale evidence re-remove a re-added
   member)? Is the `bye` bound to the **subject's** key such that no other member can mint
   it? Can a malicious member or hub **suppress** evidence to block a legitimate removal
   (availability vs authenticity — is that split stated honestly)? **D-2:** a malicious
   *creator* can now evict arbitrary members with valid evidence — is that an acceptable,
   documented authority grant or a regression of "the hub cannot shrink membership" into
   "one member can"? Does the orphaned-creator residual swallow the liveness fix?
3. **R4-03 / REQ-016.** Is "authoritative only when the creator key is already pinned or
   independently authenticated" honest and complete — and is the **GroupContext
   application extension** actually implementable on OpenMLS 0.8 for both hark and the
   web client (can a joiner read an app extension from the Welcome's GroupContext, and
   does REQ-017(e) really make it immutable — including across ReInit)? Does the
   invite-fingerprint SHOULD have any teeth, or does it quietly become the load-bearing
   mechanism while remaining optional?
4. **R4-04 / REQ-021 + REQ-024.** Does the split actually restore a usable comparison —
   and does the **detection allocation** hold: membership equivocation flips (a);
   tree-level equivocation that preserves membership is caught by (b) + the REQ-006
   decrypt-failure signal — can a hub run a **transient** membership equivocation between
   two comparisons of (a) and revert it, staying below every threshold? Can hark and the
   web client compute byte-identical (a) (canonical ordering/encoding pinned enough for
   IMPL)? Does an authenticated REQ-011 rotation changing (a) reopen a silent-rebind
   window?
5. **R4-05 / REQ-011 + REQ-017(e).** The `rekey` ceremony: an attacker holding a
   compromised current key K can cross-sign a rotation to an attacker key K' — inherent to
   key-compromise, but is the spec honest about it, and is the rotation **flagged/surfaced**
   so a hijacked rotation is at least visible? Is remove+re-add for a lost key actually
   reachable (does it depend on D-2)? Is the (e) allowlist enforceable with OpenMLS 0.8's
   staged-proposal API surface (can the app actually see and reject each listed type
   before merge, in both the native and wasm stacks)?
6. **R4-06 (cheap).** Confirm in `hark/src` that no public bare-payload identity-signing
   API remains (the only signing path is `SignedConn` over the domain-separated envelope)
   and the live test uses the signed-member bootstrap.
7. **Cross-REQ consistency.** REQ-023's pin ↔ REQ-002's keypub trigger ↔ HP-1; REQ-014's
   evidence ↔ REQ-017(d) ↔ REQ-016's creator authority; REQ-011 rotation ↔ REQ-017(c) ↔
   REQ-021(a) stability. Any self-contradiction, or any requirement unimplementable on the
   actual wire (round-2's BUG-010 shape)?

## Also look for

- Anything v0.7 marks **closed** that the threat model says isn't — especially first
  contact and the malicious-authorized-member class round 4 opened.
- New requirements whose mechanism lives in an **affected repo** the spec does not bind
  (e.g. the fanned `bye`, the creator handle at `claim`, the invite fingerprint) — is each
  recorded as a concrete affected-repo change, or asserted into existence?
- Whether the newly documented residuals are **adequately bounded**, since the human
  signer must accept them (list below).

## Output format

Write a findings doc. Per finding:

- **ID + severity** — `Critical / High / Medium / Low` (Critical = breaks confidentiality
  or authenticity under the threat model).
- **Where** — `file:line` for code, `REQ/ADR/OQ-###` for spec.
- **The attack or defect** — concrete: who the attacker is, what they do, what they gain.
- **Disposition** — what REQ/ADR must change.
- **Classification** — *regression of a v0.7 fix*, *brand-new gap the fix opened*, or
  *unclosed round-4 item*.

Give an explicit **endorse / reject (with reasoning)** for **D-1** and **D-2**.

Then a **verdict**, explicitly one of:

- **Gate may clear** (subject to human crypto sign-off) — only if no Critical/High
  survives that the design doesn't already track, AND you list the residual risks the
  human signer must accept. Start that list from: first-contact TOFU winnable by an active
  hub until safety numbers are compared; the last-resort forward-secrecy residual; hub
  fan-out availability (drop/partition/evidence-suppression); durable-provider on-disk
  delete fidelity (ADR-004, not yet written); `cbcl_ristretto` point validation (SPEC-016
  REQ-007); **creator-as-removal-authority** (D-2) incl. the orphaned-creator case; the
  **hub-served-JS** limit on web-client pinning; and the **identity-number/state-hash
  detection split** (transient-equivocation window).
- **Gate stays BLOCKED** — with the must-fix list.

End with **what you could NOT assess** (missing code, an unverifiable claim, a primitive
you'd want a human cryptographer or a proof to confirm), so the human sign-off knows the
exact boundary of this round.
