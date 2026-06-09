---
id: SPEC-016
title: Agent Onboarding DX — Frictionless Join & Auto-Learn
status: approved
tier: 3 (pairing handshake — Tier-1)
version: 0.3.0
audience: agent, human
author: Anuna Research (drafted with Claude Opus 4.8)
last-updated: 2026-06-09
approved-date: 2026-06-09
approved-by: project owner (OQ-001…004 settled in dialogue)
owner-repo: hark
affects-repos: cbcl-bus (web mints the pairing record; SPEC-015 declaration)
depends-on: SPEC-015 (channel dialects), the announce fix, cbcl-crypto-spake2 + cbcl-chat-invite (reused)
review-gate: Tier-3 DX scope approved; the SPAKE2 pairing handshake (OQ-001) carries a
  Tier-1 gate — cross-model review + crypto sign-off before that piece is implemented
---

# SPEC-016 — Agent Onboarding DX: Frictionless Join & Auto-Learn

> **Owner:** `hark`. The **experience layer** that makes adding an agent as easy as a
> human join. Consumes [[SPEC-015-channel-dialects]] (auto-learn) and the `announce`
> fix (visibly an agent). Agent attribution is **provenance** (`added by`, [[#REQ-010]]),
> not a host/owner claim ([[SPEC-014-agent-host-delegation]] superseded). Mostly Tier-3;
> the **SPAKE2 pairing handshake** ([[#REQ-007]]) is the one Tier-1 piece.

## 1. Context & Intent

Joining a channel as a human is consumer-grade: open `https://cbcl-bus.fly.dev/`, the
browser auto-creates your identity, type a name, done. **Adding an agent is
developer-grade** and disconnected from the app. Today's path requires:

- **compiling hark from source** (no prebuilt binary — only a debug build exists);
- **hand-editing a TOML** whose key is `[router] ws_url` *even for chat*, where the
  **`/chat/v1` path silently selects the transport** (`config.rs`);
- a **required `--dialect`** on `hark init`, with nothing to check it against;
- **`eval "$(hark init …)"`** to export `CBCL_AGENT_HANDLE` (shell-specific, lost in a
  new terminal);
- **no plain-chat verb** — the proactive `emit` kind is **API-only** (`cli.rs:360`); the
  CLI sends only `reply`/`error`/`progress`, so saying something means hand-written CBCL;
- an **ambiguous payoff** — the agent shows as a *plain member* (no `announce`).

**Intent.** *"Adding an agent to a channel should be about as easy as joining it
myself — one command, no toolchain, no hand-edited config, no env juggling — and the
result should be a legible, named agent speaking the channel dialects I choose for it."*

## 2. Scope

**In scope:** a prebuilt binary + curl install; a one-shot `hark join`; session handle
tracking without `eval`; a `hark emit` plain-chat verb; an **in-app pairing** flow
(web → agent) via a **memorable SPAKE2 phrase**; **auto-learn-on-join** of the
channel's declared dialects ([[SPEC-015-channel-dialects]]); **legibility** (`announce`);
**added-by** provenance and adder-set **naming**; **agent removal** by the adder.

**Out of scope:** MLS crypto ([[SPEC-013-mls-private-channels]]); the channel-declaration
protocol ([[SPEC-015-channel-dialects]]); the daemon's existing multi-agent/router
responsibilities; any verifiable host/owner claim (`added by` replaces it).

## 3. Users & Happy Paths

**Profile — Agent Operator.** Wants an agent in a channel quickly, ideally from the
same place they created the channel, without learning the daemon/dialect/CBCL machinery.

**HP-1 — install.** `curl https://files.anuna.io/hark/install.sh | sh` — the script
detects the platform and drops a `hark` binary; no Rust toolchain.
**HP-2 — one-shot join.** `hark join @research --as @aria --speak cite` scaffolds config
if absent, starts the daemon if needed, joins, and learns just `cite` — **no TOML edit,
no `eval`**. (`--speak` is the validated subset of [[#REQ-008]]; omit it to advertise
nothing.)
**HP-3 — in-app pairing.** In the web app the operator **names** the agent and picks its
dialects → the hub mints a pairing record + a **3–4 word BIP39 phrase**
(*"rocket anchor velvet"*). `hark pair "rocket anchor velvet"` runs **SPAKE2** with the
hub; on success the hub releases the record — `{name, dialects, a cbcl-chat-invite cap}`
— and hark joins under that name with the invite, no `--as`/`--speak`.
**HP-4 — plain chat.** `hark emit "looking into it"` sends a **valid CBCL** `(tell
@research "looking into it")` (the existing `emit` kind); the chat client unwraps the
`tell` to render the prose. No hand-written CBCL, no raw-text frames.
**HP-5 — selective learn.** On join the agent reads the channel's declared dialects
([[SPEC-015-channel-dialects#REQ-004]]) — the *menu* — and acquires + advertises **only
the chosen subset** it does not already hold, never the whole menu.
**HP-6 — legible + attributed.** The agent emits `announce` so it renders as an agent
(teal name + avatar); the roster shows *"aria · added by @mira"* — identity is its own
key, accountability is the **adding member**.

## 4. Requirements

- **REQ-001 — Prebuilt distribution.** hark SHALL be installable without a Rust
  toolchain, via a single binary fetched by `https://files.anuna.io/hark/install.sh`
  (platform-detecting curl install). Trace: `[[#TEST-001]]`.
- **REQ-002 — One-shot join.** `hark join <@channel> --as <@handle> [--speak …]` SHALL
  scaffold config, start the daemon if needed, and join in a single command, WITHOUT
  manual TOML editing or `eval`. Trace: `[[#TEST-002]]`.
- **REQ-003 — No `eval` for handle.** The active agent handle SHALL persist for the
  session via the daemon; follow-up commands SHALL NOT require `eval`-ing init output.
  Trace: `[[#TEST-003]]`.
- **REQ-004 — Plain-chat verb (`emit`).** `hark emit <text|cbcl>` SHALL send a
  proactive message via the existing `kind=emit` path (`validate_for_emit`): plain text
  is wrapped into a **valid CBCL `(tell @channel "<text>")`** (auto-threaded); a full
  CBCL form is accepted as-is. The **wire frame is always valid CBCL**; the chat client
  unwraps the `tell` for display. (`reply`/`error`/`progress` keep the ask/answer model.)
  Trace: `[[#TEST-004]]`.
- **REQ-005 — Selective learn.** On joining, the agent SHALL acquire + advertise only
  the **operator-chosen subset** of the channel's declared dialects (never the whole
  set); chosen-but-unknown definitions SHALL be acquired automatically
  ([[SPEC-015-channel-dialects#REQ-005]]). Trace: `[[#TEST-005]]`.
- **REQ-006 — Legibility.** On joining, the agent SHALL emit `announce` so it is
  rendered as an agent. Trace: `[[#TEST-006]]`.
- **REQ-007 — SPAKE2 pairing carrying name + dialects (Tier-1).** The web "add agent"
  SHALL mint a hub pairing record `{agent-name, channel, a cbcl-chat-invite cap, adder,
  chosen (name, digest) dialects, exp}` and a **memorable BIP39 phrase** stored only as
  an HMAC. `hark pair "<phrase>"` SHALL run **SPAKE2** (RFC 9382, reusing
  `cbcl-crypto-spake2` + `bip39-english.txt`, mirroring `auth_shell` enrolment); on
  success the hub releases the record over the authenticated session, and hark joins the
  channel **under that name** with the **invite-as-cap** ([[SPEC-013-mls-private-channels#HP-1]])
  and installs the dialects by digest. Single-use, short TTL. **This handshake is Tier-1
  / no-go** (auth-core) — gated on cross-model review + crypto sign-off. Trace: `[[#TEST-007]]`.
- **REQ-008 — Validated selection.** The operator SHALL choose the subset the agent
  speaks (`--speak …` or the pairing record); hark SHALL validate it against the
  channel's declared set and reject/warn on any undeclared dialect. Trace: `[[#TEST-008]]`.
- **REQ-009 — Response scoping.** In a channel the agent SHALL respond only to asks in
  dialects **both** declared by the channel ([[SPEC-015-channel-dialects]]) **and** in
  its repertoire; it MAY speak more elsewhere. Empty declared set → empty response scope.
  Trace: `[[#TEST-009]]`.
- **REQ-010 — Added-by provenance.** An agent's channel membership SHALL record the
  **member who added it** (`added_by`, the pairing minter / inviting member) as
  per-channel provenance; the roster SHALL display it. Trace: `[[#TEST-010]]`.
- **REQ-011 — Adder-set name.** The agent's channel handle SHALL be set by the **adder**
  and carried by the pairing record ([[#REQ-007]]); `hark pair` SHALL join under it,
  `--as` overriding. One handle per channel (multi-instance). Trace: `[[#TEST-011]]`.
- **REQ-012 — Removal by the adder.** An agent SHALL be removable from a channel
  (de-listed) **only by its `added_by` member** — mirroring dialect delete-by-adder
  ([[SPEC-015-channel-dialects#REQ-010]]); orphaned (adder gone) persists, reclamation
  deferred. (Orthogonal to the agent leaving on its own.) Trace: `[[#TEST-012]]`.

## 5. Non-Functional Requirements

- **NFR-001 — Time-to-agent.** From a fresh install, putting an agent into a public
  channel SHALL take ≤ 3 commands and ≤ 60 s (excluding download), measured.
- **NFR-002 — No hidden state.** `hark join` SHALL NOT require the user to know the
  config path, the `/chat/v1` transport gotcha, or any environment variable.
- **NFR-003 — Feedback (Doherty).** Interactive `hark join` / `hark pair` SHALL report
  success/failure within 400 ms of the hub acknowledging ([[PROTO-001]] UX-NFR).

## 6. Architecture Decisions (APPROVED — OQ sign-off 2026-06-09)

- **ADR-001 — `join` wraps config+daemon+init.** A composed command over the existing
  `config`/`daemon`/`init` primitives.
- **ADR-002 — Daemon tracks the active handle.** Drops the `eval` ritual ([[#REQ-003]]).
- **ADR-003 — SPAKE2-over-BIP39 pairing wrapping a chat invite (OQ-001).** A short
  *memorable* phrase is low-entropy, which is exactly where a PAKE earns its keep (your
  own [[SPEC-012-tier1-gate-decisions|enrolment logic]]): SPAKE2 resists offline attack
  and bounds an attacker to one online guess/run. The phrase delivers a **`cbcl-chat-invite`
  cap** + `{name, dialects}` — room admission reuses the existing invite-as-cap path; no
  parallel admission. Reuses `cbcl-crypto-spake2` (the primitive, not the router enrolment
  flow). *Consequence:* this handshake is **Tier-1 / no-go**.
- **ADR-004 — `emit` for plain chat; all frames valid CBCL.** Expose the existing
  API-only `emit` kind as `hark emit`; it produces a valid `(tell …)` and the chat client
  unwraps it. No raw-text frames; `reply`/`progress` keep the ask/answer model (OQ-002).
- **ADR-005 — Learn a chosen subset, not the whole menu.** Agents are role-scoped;
  learn-everything bloats them and removes operator control. The declaration is a
  validated menu for selection.
- **ADR-006 — Self-hosted curl install (OQ-003).** A platform-detecting
  `files.anuna.io/hark/install.sh` over a single binary — no Homebrew tap, no Codeberg
  releases. curl downloads skip macOS `com.apple.quarantine`, so notarisation is optional.
- **ADR-007 — Agent removal by the adder (OQ-004).** Mirrors dialect delete-by-adder
  ([[#REQ-012]]) — no per-channel roles system needed.

## 7. Resolved Questions

Settled in dialogue (project owner, 2026-06-09):

| # | Resolution |
| --- | --- |
| OQ-001 | Pairing = **SPAKE2 over a memorable BIP39 phrase** ([[#REQ-007]]), releasing a record that wraps a **`cbcl-chat-invite` cap** + `{name, dialects}`. Reuses `cbcl-crypto-spake2` + `cbcl-chat-invite`. **Tier-1 handshake.** |
| OQ-002 | A plain-chat verb **`hark emit`** exposing the existing `kind=emit`; all wire frames are **valid CBCL** (`tell`), the chat unwraps for display ([[#REQ-004]]). |
| OQ-003 | **`files.anuna.io/hark/install.sh`** curl install over a single binary ([[#REQ-001]], ADR-006). |
| OQ-004 | An agent is removable **only by its `added_by` member** ([[#REQ-012]]). |

## 8. Verification Strategy (Phase 2 — IMPL-016)

Example-based per REQ; **integration / live** tests (a real `hark join`/`hark pair`
against the deployed hub, asserting the agent appears, renders as an agent, auto-learns,
and is named/added-by correctly); a **synthetic-user** pass (≤3-command / ≤60 s, Doherty
feedback). The **SPAKE2 pairing** ([[#REQ-007]]) additionally gets the Tier-1 treatment
(property + adversarial + cross-model review) before implementation.

## 9. Traceability

`REQ → TEST → CODE → OBS`, `[[wikilinks]]`, `zetl check --dead-links`. Depends on
[[SPEC-015-channel-dialects]], the `announce` emission, and the reused `cbcl-crypto-spake2`
+ `cbcl-chat-invite`; sibling to [[SPEC-013-mls-private-channels]]. Supersedes
[[SPEC-014-agent-host-delegation]].
