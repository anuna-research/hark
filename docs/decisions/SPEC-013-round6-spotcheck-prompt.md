# SPEC-013 Round-6 Spot-Check — paste-ready prompt (condition K)

> **How to use.** Paste everything below the line into a fresh context on a model
> that is **neither Claude Fable nor Claude Opus** (e.g. a current GPT or Gemini
> model) — this check exists because round 5 was run by the same model family that
> authored the fixes it confirmed (Principle 12). Repo read access to `hark` is
> helpful but not required: every clause under test is quoted inline. The
> deliverable is small: three confirm/refute verdicts + two endorse/reject calls.

---

You are an independent cryptographic reviewer. You did not write this design and
owe it no deference. This is a **narrow spot-check**, not a full review: five
prior adversarial rounds exist, and a human sign-off has conditionally cleared the
gate. Your job is to verify that the final round of fixes — written and then
"confirmed" by the **same model** — actually says what it must, and to
independently endorse or reject two design calls. Be skeptical; if a mechanism is
asserted but not checkable from the text, say so.

## System context (1 paragraph)

`hark` agents join end-to-end-encrypted (MLS, RFC 9420, openmls 0.8.1) private
channels routed by an **untrusted hub** (the MLS Delivery Service — it may drop,
reorder, replay, forge, equivocate, and serve the web client's JS). Member
identity is an Ed25519 wire key; clients pin peer keys TOFU from self-signed
assertions and compare an out-of-band **identity safety number** (stable across
normal Commits) to catch hub MITM. Members may be malicious, including the room
creator. Every Remove Commit must carry signed, domain-separated
**removal evidence**; every validator verifies it at merge. The room's
**genesis assertion** (creator identity/key) rides in a custom GroupContext
application extension so every Welcome carries it.

## Check 1 — R5-01: removal-evidence epoch freshness (REQ-014 / REQ-017(d))

The hole being closed: removal evidence minted at epoch N (e.g. a member's own
signed `bye`) being **replayed** at epoch N+k to re-evict that member after they
were legitimately re-added. The fix text now reads:

> "The evidence epoch is the **current MLS group epoch before applying the Remove
> Commit**. Evidence is valid only in that exact epoch: validators SHALL reject
> stale or future evidence, with no tolerance window. A re-added member is a new
> leaf in a later epoch, so any prior `bye` or remover evidence for the old leaf
> is invalid and cannot remove the re-added member without fresh evidence."

and (validator side):

> "(d) Remove evidence at merge — … binding to this room, group, target handle +
> current leaf, and the validator's **current epoch before merge**; stale or
> future-epoch evidence SHALL be rejected, including any evidence from before the
> target was removed and later re-added."

**Questions:** (a) Does "exact epoch, no tolerance window" close the replay —
including the re-add case — or is there a residual race (e.g. two valid Removes
racing in one epoch; evidence minted at epoch N for a Commit the DS delays so the
validator's pre-merge epoch has moved)? (b) Is the zero-tolerance window
*operationally* sound on an asynchronous DS — i.e. does honest removal still work
when the hub reorders, or does the fix trade a replay hole for a liveness bug the
spec doesn't acknowledge? (c) Is the binding set (room, group, epoch, target
handle + **current leaf**) sufficient, or can evidence transplant across any
remaining dimension?

## Check 2 — R5-02: creator eviction authority documented honestly (REQ-014(b) / REQ-016)

The concern: adding the room creator as a removal-authority "liveness fallback"
actually grants unilateral eviction over ANY member. The fix text now reads:

> "The creator fallback is **not mechanically restricted to crashed or
> unresponsive members**: the creator can evict any member. This is an accepted
> single-party membership-shrink authority only because the evidence is signed by
> the creator's pinned key, attributable to that creator, and membership-visible
> via the identity safety number; it does not let the creator add attacker keys or
> break confidentiality by itself."

**Questions:** (a) Is that an honest and complete statement of the authority
grant, or does any other clause in the removal design still imply
liveness-only? (b) Are the two bounding claims true *given the rest of the
design* — i.e. is creator-signed evidence really attributable (the evidence object
is signed under its own DS label by the creator's pinned key) and is every
eviction really visible (it must change the membership set and hence the identity
safety number)? (c) Can a malicious creator + colluding hub turn eviction into
something worse than availability/integrity loss (e.g. force a victim's re-add
through an attacker-controlled path)?

## Check 3 — R5-03: the genesis-extension capabilities obligation (REQ-016 / REQ-017(e))

The genesis assertion rides in an `Unknown(0xF013)` GroupContext application
extension. openmls 0.8.1 requires every member's **leaf capabilities** to
advertise that extension type, or it rejects the operation. The spec now states:

> "the genesis extension SHALL have a pinned application extension type, and every
> hark and web-client (`cbcl-mls-wasm`) KeyPackage / leaf node SHALL advertise that
> type in its OpenMLS `Capabilities`; group-creation configuration SHALL include
> the extension. A stack that omits the capability must fail closed during
> Add/Welcome validation rather than silently joining…"

Executed probe evidence (openmls 0.8.1, native + wasm32): round-trip
create→add→welcome→read works with the capability on every leaf (readable
pre-finalize from the StagedWelcome); a default-capability KeyPackage is rejected
with `InsufficientCapabilities`; **nuance:** group *creation* with a
default-capability creator is ACCEPTED and the group bricks on its first
path-commit (`UnsupportedExtensions`) — so the create config must set the
capability.

**Questions:** (a) Given that evidence, is the durable-delivery mechanism sound —
the genesis reaches every joiner inside the MLS-authenticated Welcome and is
immutable once GroupContextExtensions proposals are rejected by the allowlist?
(b) Does the capabilities obligation create an unflagged interop/upgrade trap
(e.g. old clients with default capabilities permanently locked out — is
fail-closed the right call there)? (c) Is the delayed creator-side failure
(bricks on first commit, not at creation) adequately handled by requiring the
capability in the create config + a negative test, or does it need a stronger
guard?

## Endorse/reject — two design calls

- **D-1 — admission-path encryption pin:** a client pins a channel
  encrypted from *its own act* of presenting a cap/invite token (cap ⇒ private ⇒
  encrypted, pinned before the first send); the hub's `roomcfg :enc` bit is
  advisory; a private-channel join with no cap and no explicit operator intent
  **fails closed** (no plaintext send). The hub can strip a cap (join fails —
  availability) but cannot forge cap-presentation. Known cost: a returning member
  without their invite must be re-invited.
- **D-2 — creator as removal-authority fallback:** as in Check 2 — accepted
  because attributable + membership-visible, documented as unilateral.

Endorse or reject each, with reasoning. The failure-direction argument for D-1
(hub can only cause fail-closed, never cleartext) is the load-bearing claim —
attack it.

## Output format

For each of Check 1–3: **CONFIRMED CLOSED / NOT CLOSED (with the concrete gap) /
CLOSED WITH CAVEAT (state it)**. For D-1/D-2: **ENDORSE / REJECT** with reasoning.
Then one line: does anything you found rise to a level that should re-block
implementation? Finish with what you could not assess from the quoted material
alone.
