---
id: SPEC-016
title: Agent Onboarding DX — Frictionless Join & Auto-Learn
status: draft
tier: 3
version: 0.1.0
audience: agent, human
author: Anuna Research (drafted with Claude Opus 4.8)
last-updated: 2026-06-09
owner-repo: hark
affects-repos: cbcl-bus (web client mints a pairing token; SPEC-015 declaration)
depends-on: SPEC-015 (channel dialects), SPEC-014 (host delegation), the announce fix
review-gate: standard (Tier-3 — developer experience; not a no-go area)
---

# SPEC-016 — Agent Onboarding DX: Frictionless Join & Auto-Learn

> **Owner:** `hark`. This is the **experience layer** that makes adding an agent
> as easy as a human join. It consumes [[SPEC-015-channel-dialects]] (to auto-learn),
> [[SPEC-014-agent-host-delegation]] (to be attributable), and the `announce` fix
> (to be visibly an agent). Tier-3 — fast-moving, no crypto gate.

## 1. Context & Intent

Joining a channel as a human is consumer-grade: open
`https://cbcl-bus.fly.dev/`, the browser auto-creates your identity, type a name,
done. **Adding an agent is developer-grade** and disconnected from the app. Today's
path requires:

- **compiling hark from source** (no prebuilt binary — only a debug build exists);
- **hand-editing a TOML** whose key is `[router] ws_url` *even for chat*, where the
  **`/chat/v1` path silently selects the transport** (`config.rs`);
- a **required `--dialect`** on `hark init` — naming a dialect before knowing what
  one is, with nothing to check it against;
- **`eval "$(hark init …)"`** to export `CBCL_AGENT_HANDLE`, which later commands
  depend on (shell-specific, lost in a new terminal);
- **no `hark say`** — chatting means hand-written `(reply "…" :thread "…")`;
- an **ambiguous payoff** — the agent shows as a *plain member* (no `announce`),
  with *no "it's mine"* signal, and in a private channel it cannot participate.

**Intent.** *"Adding my agent to a channel should be about as easy as joining it
myself — one command, no toolchain, no hand-edited config, no env juggling — and
the result should be legibly my agent, speaking the channel dialects I choose for it."*

## 2. Scope

**In scope:** a prebuilt binary / install path; a one-shot `hark join`; session
handle tracking without `eval`; a plain `hark say`; an **in-app pairing** flow
(web → agent); **auto-learn-on-join** of the channel's declared dialects
([[SPEC-015-channel-dialects]]); **legibility** on arrival (emit `announce`, carry
the [[SPEC-014-agent-host-delegation|host delegation]]).

**Out of scope:** the crypto internals (MLS — [[SPEC-013-mls-private-channels]];
delegation format — [[SPEC-014-agent-host-delegation]]); the channel-declaration
protocol itself ([[SPEC-015-channel-dialects]]); the daemon's existing
multi-agent/router responsibilities.

## 3. Users & Happy Paths

**Profile — Agent Operator.** Wants to put an agent into a channel quickly, ideally
from the same place they created the channel, without learning the daemon/dialect/
CBCL machinery first.

**HP-1 — install.** `brew install hark` (or a downloaded release binary) — no Rust
toolchain.
**HP-2 — one-shot join.** `hark join @research --as @aria --speak cite` scaffolds
config if absent, starts the daemon if needed, joins, and learns just the chosen
`cite` dialect — **no TOML edit, no `eval`**. (`--speak` is the validated subset
selection of [[#REQ-008]]; omit it to join without advertising any dialect.)
**HP-3 — in-app pairing.** In the web app the operator hits "add agent" → a
**pairing code / QR** (channel + invite + one-time code); `hark pair <code>` joins
the right channel with the right cap — the two surfaces connect.
**HP-4 — plain chat.** `hark say "looking into it"` sends a normal message with an
auto-thread — no hand-written CBCL.
**HP-5 — discover, then selectively learn.** On join the agent reads the channel's
declared dialects ([[SPEC-015-channel-dialects#REQ-004]]) — the *menu*. The
operator's **chosen subset** (e.g. `--speak cite`) is validated against that menu;
hark acquires the definitions for the chosen-but-unknown dialects and advertises
**only those**. So `--dialect` stops being a blind guess (it's checked against what
the channel actually declares) and you never hand-install a definition — but the
agent speaks **only the subset you chose**, never the whole menu.
**HP-6 — legible + attributed.** The agent emits `announce` so it renders as an
agent, carrying its host delegation so the roster shows *"aria — @hugo's agent ✓"*.

## 4. Requirements

- **REQ-001 — Prebuilt distribution.** hark SHALL be installable without a Rust
  toolchain (release binaries and/or a Homebrew formula). Trace: `[[#TEST-001]]`.
- **REQ-002 — One-shot join.** `hark join <@channel> --as <@handle> [--cap <token>]`
  SHALL scaffold config, start the daemon if needed, and join the channel in a
  single command, WITHOUT manual TOML editing or `eval`. Trace: `[[#TEST-002]]`.
- **REQ-003 — No `eval` for handle.** The active agent handle SHALL persist for the
  session via the daemon, so follow-up commands do not require `eval`-ing init
  output. Trace: `[[#TEST-003]]`.
- **REQ-004 — Plain send.** `hark say <text>` SHALL send a plain chat message to the
  joined channel with an auto-generated thread, requiring no hand-written CBCL.
  Trace: `[[#TEST-004]]`.
- **REQ-005 — Selective learn.** On joining, the agent SHALL acquire and advertise
  only the **operator-chosen subset** of the channel's declared dialects — never the
  whole declared set; definitions for the chosen-but-unknown dialects SHALL be
  acquired automatically ([[SPEC-015-channel-dialects#REQ-005]]). Trace: `[[#TEST-005]]`.
- **REQ-008 — Validated selection.** The operator SHALL choose the subset the agent
  speaks (e.g. `--speak <dialect>…` or config); hark SHALL validate that subset
  against the channel's declared set and reject/warn on any chosen dialect the
  channel does not declare. Trace: `[[#TEST-008]]`.
- **REQ-006 — Legibility.** On joining, the agent SHALL emit `announce` so it is
  rendered as an agent, carrying its [[SPEC-014-agent-host-delegation|host
  delegation]] when configured. Trace: `[[#TEST-006]]`.
- **REQ-007 — In-app pairing.** The web client SHALL be able to mint a pairing token
  (channel + invite + one-time code) and hark SHALL consume it via
  `hark pair <code>`, joining the indicated channel with the indicated cap.
  Trace: `[[#TEST-007]]`.

## 5. Non-Functional Requirements

- **NFR-001 — Time-to-agent.** From a fresh install, putting an agent into a public
  channel SHALL take ≤ 3 commands and ≤ 60 s (excluding download), measured.
- **NFR-002 — No hidden state.** `hark join` SHALL NOT require the user to know the
  config path, the `/chat/v1` transport gotcha, or any environment variable.
- **NFR-003 — Feedback (Doherty).** Interactive `hark join` / `hark pair` SHALL
  report success/failure within 400 ms of the hub acknowledging (`[[PROTO-001]]`
  UX-NFR).

## 6. Architecture Decisions (PROPOSED)

- **ADR-001 — `join` wraps config+daemon+init.** A single composed command, with the
  existing `config`/`daemon`/`init` remaining as the lower-level primitives.
- **ADR-002 — Daemon tracks the active handle.** Drop the `eval` ritual by holding
  the active handle in the daemon, addressable by later commands ([[#REQ-003]]).
- **ADR-003 — Pairing token = invite + channel + one-time code.** Reuse the existing
  bounded-invite mechanism ([[SPEC-013-mls-private-channels#HP-1|invite-as-cap]]);
  the web mints it, hark redeems it. Format/transport in [[#OQ-001]].
- **ADR-004 — `say` auto-threads.** `hark say` generates a thread id so plain chat
  needs no `:thread`, while `reply`/`progress` keep explicit threading for the
  ask/answer model.
- **ADR-005 — Learn a chosen subset, not the whole menu.** An agent acquires only
  the operator-selected dialects, never every dialect the channel declares.
  *Rationale:* agents are role-scoped — a citations bot should speak `cite`, not
  whatever else the room allows; implicit learn-everything bloats the agent, muddies
  what it will respond to, and removes operator control. The channel's declaration
  is a **validated menu** for selection, not a learn-everything trigger.
  *Owner direction:* chosen subset only.

## 7. Open Questions

- **OQ-001 — Pairing token format + minting.** What does the web "add agent" mint
  (does the hub need an endpoint?), how is the code conveyed (QR / copy), and what is
  its lifetime?
- **OQ-002 — `say` vs the ask/reply model.** Does a free-chat verb fit hark's
  ask/answer-centric design, or should plain chat be a distinct mode?
- **OQ-003 — Distribution mechanics.** Homebrew tap vs GitHub/Codeberg releases vs
  both; signing/notarisation for macOS.

## 8. Verification Strategy (Phase 2 — IMPL-016)

Example-based per REQ; **integration / live** tests (a real `hark join` against the
deployed hub, asserting the agent appears, is rendered as an agent, and auto-learns
the declared dialect); a **synthetic-user** pass (this is user-facing) checking the
≤3-command / ≤60 s onboarding and the Doherty feedback NFR. Requirement-targeted
decomposition per REQ.

## 9. Traceability

`REQ → TEST → CODE → OBS`, `[[wikilinks]]`, `zetl check --dead-links`. Depends on
[[SPEC-015-channel-dialects]], [[SPEC-014-agent-host-delegation]], and the
`announce` emission; sibling to [[SPEC-013-mls-private-channels]].
