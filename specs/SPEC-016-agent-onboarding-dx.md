---
id: SPEC-016
title: Agent Onboarding DX — Frictionless Join & Auto-Learn
status: approved (DX scope); pairing handshake CONDITIONALLY CLEARED 2026-06-10 with SPEC-013 (see review-gate)
tier: 3 (pairing handshake — Tier-1)
version: 0.6.0
audience: agent, human
author: Anuna Research (drafted with Claude Opus 4.8; v0.4 folds SPEC-013 round-3 findings; v0.5 folds round-4 R4-01, Claude Fable 5; v0.5.1 folds round-5 D-1/R5-07 clarification; v0.6.0 records the Tier-1 sign-off)
last-updated: 2026-06-10
approved-date: 2026-06-09
approved-by: project owner (OQ-001…004 settled in dialogue; REQ-007 re-opened by round-3 — see below)
owner-repo: hark
affects-repos: cbcl-bus (web mints the pairing record; SPEC-015 declaration)
depends-on: SPEC-015 (channel dialects), the announce fix, cbcl-crypto-spake2 + cbcl-chat-invite (reused)
review-gate: Tier-3 DX scope approved; the SPAKE2 pairing handshake (REQ-007/OQ-001) carries a
  Tier-1 gate — cross-model review + crypto sign-off before that piece is implemented. The
  SPEC-013 **round-3 review (R3-01..R3-05)** corrected REQ-007 + ADR-003 (v0.4.0): SPAKE2
  anchors capability + name, NOT peer identity; the hub holds a password-equivalent verifier;
  pairing-specific transcript constants + failed-attempt bound + an `enc`-mode field are now
  required. The **round-4 review (R4-01)** corrected the `enc` field's role (v0.5.0): the
  record is hub-released and not authenticatable against the hub, so `enc` is **advisory** —
  the encryption pin derives from the record's **invite-cap presence**
  (SPEC-013 REQ-023(a)). Round 5 endorsed that call and documented the no-cap returning-member
  availability cost. **The Tier-1 human sign-off was given 2026-06-10**
  (hark/docs/decisions/SPEC-013-tier1-signoff.md): D-1 ratified; the pairing handshake is
  CONDITIONALLY CLEARED with SPEC-013 — implementation merge waits on the round-6
  independent-model spot-check (condition K), and the **`cbcl_ristretto` point-validation
  audit (condition J) blocks IMPL-016's handshake implementation** specifically.
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
hub; on success the hub releases the record (bound to the PAKE key) —
`{name, dialects, enc-mode, a cbcl-chat-invite cap}` — and hark joins under that name with
the invite, pinning the channel's encryption mode, no `--as`/`--speak`.
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
- **REQ-007 — SPAKE2 pairing carrying name + dialects + enc-mode (Tier-1).** The web "add
  agent" SHALL mint a hub pairing record `{agent-name, channel, **enc** (the channel's pinned
  encryption mode — [[SPEC-013-mls-private-channels#REQ-023]]), a cbcl-chat-invite cap, adder,
  chosen (name, digest) dialects, exp}` and a **memorable BIP39 phrase**. `hark pair
  "<phrase>"` SHALL run **SPAKE2** (RFC 9382, reusing the `cbcl-crypto-spake2` **primitive**);
  on success the hub releases the record **bound to the PAKE-derived session key K** (encrypted
  and/or MAC'd under K, not merely "sent after success"), and hark joins the channel **under
  that name** with the **invite-as-cap** ([[SPEC-013-mls-private-channels#HP-1]]) and installs
  the dialects by digest.
  - **The `enc` field is advisory, NOT the encryption-pin source (R4-01).** The record is
    hub-stored and hub-released, and (per the scope note below) its contents cannot be
    authenticated *against* the hub — so a hub-alterable `enc` bit must not decide whether the
    agent sends plaintext. The pin SHALL derive from the record's **`cbcl-chat-invite` cap
    presence**: a cap admits to a **private** channel, and private ⇒ encrypted, so hark SHALL
    pin `enc=true` **before its first frame** whenever the record carries a cap
    ([[SPEC-013-mls-private-channels#REQ-023]](a)). A hub that strips the cap merely breaks
    the join (availability); it cannot induce a cleartext send into a private channel. A
    record whose `enc` claim conflicts with its cap presence SHALL be surfaced, and the
    cap-derived pin wins. A record with no cap SHALL NOT use `enc=true` by itself as an
    encryption pin; if the channel is believed private and no cap/operator-intent signal is
    present, `hark pair` SHALL fail closed and require a fresh pairing/invite rather than
    send plaintext.
  - **Storage is password-equivalent (NOT a one-way HMAC).** A SPAKE2 *responder* cannot run
    from a one-way digest — it needs the password to derive `w` (`cbcl-crypto-spake2.lfe`
    `init-responder`). Whatever the hub stores to execute the handshake (the phrase, `w`, or
    an HMAC-as-password-input) is **password-equivalent**; SPAKE2 is not an augmented PAKE, so
    a hub-DB reader can complete the pairing as either side. The spec SHALL state this plainly
    (do not claim "stored only as an HMAC"). The exposure is bounded by **single-use + short
    TTL + a failed-attempt bound** (delete the record after **N=3 failed MAC verifications**)
    + hub-side rate limiting — a 3–4-word BIP39 phrase is only ~33–44 bits, so the online-guess
    budget must be mechanized, not asserted "one guess per run" (R3-04).
  - **Pairing-specific transcript binding.** The reused module hard-codes router-enrolment
    identities/labels (`idB = "cbcl-router:" ++ deployment_id`, salt `"CBCL-enrollment-v1"`,
    MAC labels `cbcl-agent-confirm`/`cbcl-router-confirm`, a 3-word/5-byte password encoding).
    Pairing SHALL pin **its own** identity strings (e.g. `idB = "cbcl-chat-pair:" ++ hub_id`,
    a defined `idA`), its own HKDF salt/info, and an encoding covering **4 words** — so a
    pairing transcript is domain-distinct from an enrolment transcript and the promised
    "rocket anchor velvet" 4-word phrase actually fits (R3-03).
  - **Scope.** This handshake authenticates **capability + name delivery to the intended
    agent** against third parties; it is **NOT** the agent Authentication Service and carries
    **no peer-identity material** — agent first-contact identity is hub-mediated TOFU + the
    [[SPEC-013-mls-private-channels#REQ-024]] safety number ([[SPEC-013-mls-private-channels#ADR-006]]).
  **This handshake is Tier-1 / no-go** (auth-core) — gated on cross-model review + crypto
  sign-off. Trace: `[[#TEST-007]]`. *(Corrected per SPEC-013 round-3 R3-01..R3-05.)*
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
- **ADR-003 — SPAKE2-over-BIP39 pairing wrapping a chat invite (OQ-001; re-scoped per R3-01/R3-02).**
  A short *memorable* phrase is low-entropy, which is exactly where a PAKE earns its keep (your
  own [[SPEC-012-tier1-gate-decisions|enrolment logic]]): SPAKE2 resists **offline** attack and
  bounds an attacker to online guesses (bounded by [[#REQ-007]]'s failed-attempt limit). The
  phrase delivers a **`cbcl-chat-invite` cap** + `{name, dialects, enc}` — room admission reuses
  the existing invite-as-cap path; no parallel admission. Reuses the `cbcl-crypto-spake2`
  **primitive** (with pairing-specific transcript constants — [[#REQ-007]]), not the router
  enrolment flow. **What this is NOT:** it is **not** the agent Authentication Service. The
  pairing authenticates the *operator/agent to the hub* and releases a cap the hub itself
  issues, so a **malicious hub gains nothing it did not already have** — but it also means the
  hub holds password-equivalent material and the record contents cannot be authenticated
  *against* the hub by phrase-derived keys — which is why the `enc` field is **advisory** and
  the encryption pin derives from the **invite-cap presence**, a signal the hub can withhold
  but not invert ([[#REQ-007]], [[SPEC-013-mls-private-channels#REQ-023]]; R4-01). Agent
  peer-identity first-contact therefore rests on hub-mediated TOFU + the
  [[SPEC-013-mls-private-channels#REQ-024]] safety number, **not** on this phrase.
  *Consequence:* this handshake is **Tier-1 / no-go**, and the design SHALL NOT claim it
  anchors agent first-contact *identity*.
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
| OQ-001 | Pairing = **SPAKE2 over a memorable BIP39 phrase** ([[#REQ-007]]), releasing a record (bound to the PAKE key K) that wraps a **`cbcl-chat-invite` cap** + `{name, dialects, enc}`. Reuses the `cbcl-crypto-spake2` **primitive** (pairing-specific transcript constants) + `cbcl-chat-invite`. **Tier-1 handshake.** **Round-3 correction (R3-01/R3-02):** anchors *capability + name*, NOT agent peer-identity; hub stores a **password-equivalent** verifier (not a one-way HMAC), bounded by single-use + TTL + a failed-attempt limit. |
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
