# SPEC-016 — Open-Question Decisions (APPROVED)

Status: **APPROVED** — project-owner sign-off 2026-06-09, folded into
`specs/SPEC-016-agent-onboarding-dx.md` (v0.3.0, `status: approved`). SPEC-016 is
**Tier-3 (DX)** except **OQ-001's SPAKE2 pairing handshake**, which carries a **Tier-1**
gate (cross-model review + crypto sign-off) before that piece is implemented.

> **Historical record — OQ-001 details superseded.** This captures the decision as
> signed off; later review rounds corrected three OQ-001 details, and the spec
> (REQ-007, v0.5+) is authoritative: the hub's stored verifier is
> **password-equivalent, NOT "only an HMAC"** (a SPAKE2 responder cannot run from a
> one-way digest — round 3); the online-guess budget is **mechanized** (single-use +
> TTL + burn-on-first-failed-MAC (N=1, v0.7.0; originally N=3) + per-source rate limiting), not an asserted "one
> guess per run" (R3-04); and **install-by-digest is deferred to SPEC-015** (records
> carry `(name, digest)` but the hub mints empty digests today — spec §7a).

---

## OQ-001 — Pairing mechanism — **APPROVED (Tier-1 carve-out)**

> How is the pairing token conveyed and redeemed?

### Decision — **A memorable BIP39 phrase + SPAKE2, wrapping a `cbcl-chat-invite` cap.**

The web "add agent" mints a hub pairing record `{agent-name, channel, a cbcl-chat-invite
cap, adder, chosen (name, digest) dialects, exp}` and a **3–4 word BIP39 phrase** stored
only as an HMAC. `hark pair "<phrase>"` runs **SPAKE2** (RFC 9382) with the hub; on
success the hub releases the record over the authenticated session, and hark joins
**under that name** with the **invite-as-cap** and installs the dialects by digest.
Single-use, short TTL.

### Rationale

1. **Memorable ⇒ low-entropy ⇒ PAKE.** A short, speakable phrase is low-entropy; per the
   project's own enrolment logic ([[SPEC-012-tier1-gate-decisions]]) that is *exactly*
   where SPAKE2 earns its keep — no offline dictionary attack, one online guess per run,
   mutual auth + session key. (A non-PAKE lookup would force a long high-entropy phrase,
   i.e. not "rocket anchor velvet".)
2. **Reuse, don't reinvent.** SPAKE2 reuses `cbcl-crypto-spake2` + `bip39-english.txt`
   (the *primitive*, not the router enrolment flow). Room admission reuses the existing
   **`cbcl-chat-invite`** — the pairing *wraps* a fresh invite as the cap; no parallel
   admission path.
3. **Consequence accepted:** the handshake is auth-core → **Tier-1 / no-go**. Lighter
   than a from-scratch crypto spec (reuses already-reviewed machinery), but still gated.

### Test expectations

- correct phrase → SPAKE2 succeeds → record released → agent joins under name with cap +
  dialects; wrong phrase → one failed online guess, no record leak; expired/used → refused.

---

## OQ-002 — Plain-chat verb — **APPROVED**

> Does a free-chat verb fit hark's ask/answer model?

### Decision — **Expose the existing `emit` kind as `hark emit`; all wire frames stay valid CBCL.**

`emit` (a proactive agent-initiated message) is already built + validated
(`validate_for_emit`) but **API-only** (`cli.rs:360`). `hark emit <text>` wraps text into
a **valid `(tell @channel "<text>")`** (or accepts a full CBCL form); the **chat client
unwraps** the `tell` for display. `reply`/`error`/`progress` keep the ask/answer model.

### Rationale

1. **The capability exists** — we add a CLI surface, not a new kind.
2. **All-CBCL invariant** — no raw-text frames; everything on the wire is well-formed
   CBCL, the chat layer unwraps.
3. A chat agent that can't speak unprompted is odd; `emit` fills that without loosening
   the wire contract.

### Test expectations

- `hark emit "hi"` → a valid `(tell @room "hi")` accepted by `validate_for_emit`; a
  `(meta …)` or malformed input is rejected.

---

## OQ-003 — Distribution — **APPROVED**

> Homebrew vs releases vs both; macOS signing?

### Decision — **A self-hosted curl install: `files.anuna.io/hark/install.sh` over a single binary.**

Platform-detecting script fetches the matching `hark` binary. No Homebrew tap, no
Codeberg releases.

### Rationale

1. Simple, self-hosted, one canonical install line.
2. **curl downloads skip `com.apple.quarantine`** (unlike browser downloads), so macOS
   Gatekeeper friction largely disappears — signing/notarisation becomes optional, not a
   blocker.

### Test expectations

- the install line drops a runnable `hark` on macOS arm64/x64 + Linux without a Rust
  toolchain.

---

## OQ-004 — Agent-removal authz — **APPROVED**

> Who may remove an agent from a channel?

### Decision — **Only the agent's `added_by` member** ([[#REQ-012 (in SPEC-016)]]).

Mirrors the dialect model (add = any member, delete = the adder). Orphaned (adder gone)
persists; reclamation deferred. Orthogonal to the agent leaving on its own.

### Rationale

1. **Consistency** with dialect delete-by-adder — one governance shape across the channel.
2. **No roles system** needed; public channels have no owner to vest removal in otherwise.

### Test expectations

- the `added_by` member removes the agent → de-listed; a non-adder removal → rejected.

---

## Net effect

Folded into SPEC-016 v0.3.0 (`status: approved`). The DX scope is implementation-ready;
the **SPAKE2 pairing handshake** (OQ-001) remains gated on its Tier-1 review before code.
