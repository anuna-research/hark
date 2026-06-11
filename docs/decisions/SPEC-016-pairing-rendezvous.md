# SPEC-016 — Pairing rendezvous: how the hub finds the record

**Date:** 2026-06-11
**Status:** DECIDED — implemented (`cbcl-bus feat/spec-016-pairing`).
**Context:** REQ-007 / HP-3. `hark pair "<code>"` runs SPAKE2 against the hub.
The hub is the responder, so it must locate the *specific* pending record (to
load that record's password-equivalent verifier) before it can run the
handshake. The phrase is the PAKE secret and must never travel the wire. So:
**how does the hub find the record from what the agent sends?**

This was non-obvious and went through a few wrong turns; recording it so it
isn't re-litigated.

## The constraint

You cannot have all three of: (a) the typed code is *only* the BIP39 phrase,
(b) the hub can disambiguate *concurrent* pending pairings, (c) no value
derived from the phrase crosses the wire. Specifically:

- **Hash-of-phrase as the lookup key** (`H(phrase)`) leaks the phrase: a
  ~44-bit phrase is offline-brute-forceable from its hash, which is exactly the
  offline attack SPAKE2 was chosen to prevent (ADR-003). *Rejected.*
  - (Caveat raised in review: under a strict TOFU + single-use + short-TTL
    reading this is *defensible* — a passive observer sees only TLS, and an
    active MITM would have to crack the phrase inside the TTL. But it couples the
    routing value to the secret, eroding SPAKE2's "secure on a broken channel"
    property, so we did not take it.)
- **Try every pending record** breaks the failed-MAC accounting: a failed MAC is
  *ambiguous* (wrong-record vs wrong-phrase), so the hub would burn the wrong
  record's budget and an attacker could DoS every pending pairing's budget at
  once. *Rejected.*
- **Single pending pairing per hub** (no locator) is phrase-only and secure but
  serialises pairing hub-wide — a real limit on a multi-tenant hub. *Rejected.*
- **OPRF blind lookup** is phrase-only, concurrent, and leak-free, but adds a
  round and a new Tier-1 crypto component. *Overkill here.*

## The decision: Magic-Wormhole nameplate + rate limiting

A wormhole code is `4-purple-sausages`: a short **nameplate** (a small integer
the rendezvous server allocates) plus the secret words. The nameplate is
public, sent in the clear to claim the rendezvous, and **independent of the
secret**, so it leaks nothing about the phrase. We adopt exactly this:

- **Nameplate = the smallest integer not currently pending**, allocated at mint
  and bundled into the handed-off code (`1-rocket-anchor-velvet-quantum`). It only has
  to be unique across the pairings outstanding *right now* (normally one).
  Freed on consume/expiry/delete and reused. Public + predictable + independent
  of the phrase → zero leakage. (`cbcl-chat-pairing-store:alloc-nameplate`.)
- **Both halves are required.** A small *enumerable* nameplate means an
  unobserved attacker could connect to `/pair/v1`, hammer `1,2,3…` with junk
  phrases, and blindly delete every pending pairing via the failed-MAC burn. Wormhole
  pairs the small nameplate with **server-side rate limiting**; so do we:
  `cbcl-chat-pair-ratelimit` (per-source sliding window) gates `/pair/v1` before
  any pairing work and burns budget on each failed attempt. The per-record
  burn-on-first-failure (N=1) stops guessing one record; the limiter
  **throttles** enumeration across many — it does not stop it. At the defaults
  (10 failures/min per source, then a 5-min cooldown) one source can burn up
  to ~10 pending records a minute before lockout (every failed attempt now
  burns its record), and distributed sources scale that linearly. The residual
  risk is bounded and is **availability, never secrecy**: a burned pairing
  deletes a pending record (single-use, 10-min TTL, normally one outstanding)
  and the adder re-mints; no failure budget leaks anything about the phrase.

The 32-hex id originally shipped was *also* secure (unguessable ⇒
un-enumerable) — it was just unmemorable, and it had been quietly doing the
rate-limiter's job. Shrinking the nameplate is what made the limiter load-bearing.

## What the agent sends

`pair_init` carries the **nameplate** (public locator) + `msg_a`. The two words
never leave the agent — they derive the PAKE password `w`. `idA` in the
transcript is the nameplate, binding the handshake to the specific record.

## Properties

- Pure-phrase secret, memorable code (`1-rocket-anchor`), unlimited
  concurrency, no phrase-derived value on the wire, no single-pending limit.
- Online-guess budget mechanized two ways: per-record burn-on-first-failure
  (N=1) + per-source rate limit. Single-use + short TTL bound the exposure
  window.
- Verified live under the original 4-word/N=3 parameters, and **re-verified
  live 2026-06-11 under 2-word/N=1** (web `addagent` → `1-ice-boat` →
  `hark pair` against a local hub): pairs end-to-end with adder-attributed
  roster; the consumed code is single-use (`unknown_pairing_id` on re-use);
  ONE wrong guess burns the record (`budget_exhausted`, then the legitimate
  phrase finds it gone); a freed nameplate is reused by the next mint.

## Revision (2026-06-11): two words, burn on first failure

Owner decision, matching Magic-Wormhole's posture exactly: the phrase drops
from four BIP39 words (44 bits) to **two** (22 bits), and the failed-MAC
budget drops from N=3 to **N=1** — one wrong guess burns the record and frees
the nameplate. SPAKE2 still makes offline attack impossible, so the only
attack is the single online guess: success odds 2^-22 per minted record
(wormhole ships 16 bits under the same rule). A typo now costs a re-mint —
the failure is loud, the adder is one click from a fresh code. Entropy above
this buys nothing real: the binding exposure is the password-equivalent
verifier in the hub DB, which no phrase length defends.
