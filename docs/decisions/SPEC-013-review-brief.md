# SPEC-013 — Round-3 Adversarial Review Brief (cross-model)

> Paste everything below the line into a **different model** than the one that drafted
> these specs (Principle 12 — no self-validation; cross-model preferred). The reviewer
> needs read access to the `hark`, `cbcl-bus`, and `cbcl-chat` repos. This brief is the
> third adversarial pass; rounds 1–2 are in [[SPEC-013-design-review-findings]].

---

## Your role

You are an **independent cryptographic and security reviewer**. You did not write these
specifications and you owe them no deference. Your job is to **break them** — to find
where the design fails to deliver the confidentiality and authenticity it claims, or
where a requirement is unimplementable, underspecified, or self-contradictory. A review
that finds nothing is only useful if you genuinely tried to break it and document how.

**Default to skeptical.** If a mitigation is asserted but you cannot trace it to a
concrete, checkable mechanism in the spec (and, where it claims to fix existing code, to
the code), treat it as **unproven** and say so. Do not soften findings to be agreeable.
Do not invent agreement. If the design is sound on a point, say *why* it is sound in
terms of the threat model — not that it "looks reasonable."

## What is being reviewed

This is a **Tier-1 / no-go** design (touches MLS end-to-end encryption + the
signed-member authentication core). Implementation cannot begin until a cross-model
review (this) plus a human cryptography sign-off clear the gate. Two specs carry Tier-1
weight:

1. **`hark/specs/SPEC-013-mls-private-channels.md` (v0.5.0)** — PRIMARY. Lets an
   authenticated `hark` agent join an MLS-encrypted private channel and interoperate
   with web members. Read the whole file.
2. **`hark/specs/SPEC-016-agent-onboarding-dx.md` — REQ-007 + ADR-003 only** — the
   **SPAKE2 pairing handshake** (BIP39 phrase → SPAKE2 → releases a `cbcl-chat-invite`
   cap + agent name + chosen dialects). This is the AS's agent-side first-contact anchor.

Context (NOT under Tier-1 review, but read for how membership/identity flow — and flag
if either *undermines* SPEC-013's guarantees):

- `cbcl-bus/specs/SPEC-015-channel-dialects.md` (Tier-2) — declared dialects, dumb hub.
- `hark/docs/decisions/SPEC-013-design-review-findings.md` — rounds 1–2 (BUG-001…011).
- `hark/docs/decisions/SPEC-016-open-question-decisions.md` — the SPAKE2 OQ rationale.

### The implementation is a test oracle, not the spec

The current `cbcl-mls-wasm` implementation is **known-defective** and is treated by the
spec as the thing to *correct*. Read it to verify whether a claimed fix is actually
expressible / whether a BUG is real, but **review the spec's design**, not the old code:

- `cbcl-chat/crates/cbcl-mls-wasm/src/lib.rs` (and `mls.js`) — leaf key, add/join/commit.
- `cbcl-chat`'s LFE hub: `cbcl-chat-session-ws.lfe`, `cbcl-chat-members.lfe`,
  `cbcl-chat-keypkg.lfe`, `cbcl-chat-room.lfe`, `cbcl-chat-roomcfg.lfe` — the hub paths.
- `hark/src/signed_frame.rs`, `chat_frame.rs`, `identity.rs` — the signed-member wire.

## Threat model (assume all of it)

- **The hub is the untrusted MLS Delivery Service.** It routes all frames and serves the
  KeyPackage directory, presence, and rosters. It is **active**: it may drop, reorder,
  replay, forge, equivocate (show different members different views), squat handles at
  first contact, and drain the one-time KeyPackage pool. Server→client frames are
  hub-attested, **not** signed end-to-end unless a spec mechanism makes them so.
- **Members may be malicious.** An admitted member may try to add attacker keys, forge
  `:from`, publish unauthorised proposals/Commits, or fork the group.
- **First contact has no prior shared secret** beyond an out-of-band invite (humans) or
  the BIP39 phrase delivered out-of-band (agents).
- Endpoints are honest *until* compromised; `identity_dir` at-rest compromise is in scope
  for the retention question (OQ-005 / NFR-004).

## What changed since round 2 — verify these specifically

The spec claims v0.4.0 + v0.5.0 close every round-1/2 finding. **Verify each claim against
the threat model. Do not accept the claim because the spec asserts it.**

1. **The Authentication Service (ADR-006, OQ-002).** The missing AS is now: **invite-anchored
   TOFU + safety numbers** (humans — REQ-019 self-signed key-assertion frame, REQ-021
   safety number) and **SPAKE2 pairing** (agents — SPEC-016 REQ-007). Pressure-test:
   - **REQ-019** — a member broadcasts `(idkey @handle :key K :room @room :nonce N)`
     signed by K, the hub fans it, peers verify the signature *themselves* and pin
     handle→K (TOFU). Is the signed context genuinely **independent of the per-connection
     envelope** (so a hub can't strip/replay/transplant it across rooms or connections)?
     Is the nonce/room binding sufficient against replay and cross-room transplant? Can a
     hub that controls fan-out still win the first-contact race (pin an attacker K before
     the honest assertion arrives) — and does **REQ-021** (safety number, out-of-band
     comparison) actually catch that, given humans may never compare?
   - **REQ-016** — committer/authority now derives from the **MLS ratchet tree**, not hub
     presence. Verify the bootstrap: the room creator is the root of trust for the tree.
     What stops a hub from presenting a *different* valid-looking tree (equivocation) to a
     joiner? Does REQ-021's safety number actually bind the *whole* membership, and is the
     "deterministic committer over MLS leaves" free of split-brain under concurrent
     commits / network partition?
   - Is **TOFU + safety numbers** an adequate AS for this threat model, or does the
     residual first-contact gap (deferred key transparency, OQ-002) leave a practical
     attack? Be concrete about the attacker and the cost.

2. **OQ-004 / REQ-013 + REQ-022 — KeyPackage replay, now client-side.** Enforcement moved
   off the untrusted hub: **delete-on-use** of the one-time init private key (memory +
   storage) on consuming a Welcome, a **consumed-`KeyPackageRef` ledger**, and
   **transcript-visible refs** so the group rejects an Add reusing a ref; one-time
   replenishment (REQ-022) with a **bounded last-resort** whose weaker-forward-secrecy
   residual is explicitly accepted. Pressure-test:
   - Is "transcript-visible `KeyPackageRef`" actually true of the MLS objects in play — can
     every member see and check the ref of an Add's KeyPackage at the point they need to
     reject a duplicate? Or is this assuming a visibility the protocol/encoding doesn't give?
   - Delete-on-use defends a *replayed Welcome to the same package*. Does it defend the
     **last-resort** case the spec admits (hub drains one-time → forces last-resort →
     later init-key compromise)? Is the "bounded, documented residual" actually bounded by
     a mechanism, or only by prose? Is there a worse consequence than the spec admits?
   - Race: between consuming and deleting the init key, or between two concurrent Welcomes
     to the same one-time package — any window?

3. **OQ-005 / NFR-004 — retention.** "Keep only current-epoch secrets (+ bounded
   out-of-order window), prune superseded, version bump = re-join." Does this match what
   OpenMLS actually retains and exposes as a knob? Does pruning superseded epoch secrets
   genuinely bound the past-message window after an `identity_dir` compromise, or does
   OpenMLS retain more than the spec assumes (message-secret trees, resumption PSKs)?

4. **REQ-008/011/012/017/018 — the membership-binding spine.** Confirm the chain actually
   anchors MLS membership to the **authenticated wire identity** end to end: pin source
   (REQ-011/019) → adder verification (REQ-008) → inbound Commit/proposal validation
   (REQ-017) → app-bound Welcome (REQ-012) → sender-authenticated `:from` (REQ-018). Find
   any path — inbound or outbound — where an MLS-valid but app-unauthorised membership
   change or message is accepted. Round 2 found the inbound path (BUG-008) and `:from`
   forgery (BUG-009); verify the new REQs close them *and* that no new gap opened between
   them.

5. **SPEC-016 REQ-007 — SPAKE2 pairing.** The BIP39 phrase is stored at the hub **only as
   an HMAC**; `hark pair` runs SPAKE2 against the hub, the hub releases the record on
   success. Pressure-test: is the hub a trusted party here in a way that contradicts the
   "untrusted hub" model? (The phrase authenticates the *operator to the hub* and releases
   a cap — does a malicious hub gain anything it didn't already have, given it issues the
   cap?) Single-use / TTL / online-guess-bounding — actually enforced, or assumed? Does
   reusing `cbcl-crypto-spake2` (built for router enrolment) carry any binding/transcript
   assumption that doesn't hold in this pairing context?

6. **OQ-001 — key reuse (ADR-002).** The wire Ed25519 key doubles as the MLS leaf signer.
   Rounds 1–2 found no cross-protocol signature collision (wire `DS_TAG` envelope vs
   OpenMLS `SignWithLabel`). Independently re-derive: under the **pinned labels and
   encodings**, is there any input that produces a valid signature in both contexts, or any
   cross-protocol confusion (e.g., an MLS-signed structure that parses as a wire envelope
   or vice versa)? This gates REQ-007's approval.

## Also look for

- **Requirements that are unimplementable on the actual wire** (round 2's BUG-010 was
  exactly this — REQ-011's pin source wasn't peer-verifiable until REQ-019 was added).
- **Self-contradictions** between REQs, ADRs, and the scope section.
- **Anything the spec marks resolved that the threat model says isn't.**
- **REQ-020** — the live deployment still labels private channels "end-to-end encrypted."
  Confirm whether the spec's own gating is consistent with that live claim (it should say
  the claim must come down until the gate clears).

## Output format

For each finding:

- **ID + severity** — `Critical / High / Medium / Low`. Critical = breaks confidentiality
  or authenticity under the stated threat model.
- **Where** — `file:line` for code, `REQ/ADR/OQ-###` for spec.
- **The attack or defect** — concrete: who the attacker is, what they do, what they gain.
- **Disposition** — what REQ/ADR must change, or what new requirement is needed.
- **Whether it is a regression of a round-1/2 fix or genuinely new.**

Then a **verdict**, explicitly one of:

- **Gate may clear** (subject to human crypto sign-off) — only if you found no Critical/High
  that the design doesn't already track, AND you state the residual risks a human signer
  must accept.
- **Gate stays BLOCKED** — with the must-fix list.

End with **what you could NOT assess** (missing code, an unverifiable claim, a primitive
you'd want a human cryptographer or a proof to confirm) — so the human sign-off knows
exactly what this review does and does not cover.
