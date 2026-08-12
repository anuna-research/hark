---
id: SPEC-016
title: Agent Onboarding DX — Frictionless Join & Auto-Learn
status: IMPLEMENTED 2026-06-11 (IMPL-016 — all REQs EXCEPT the digest-install leg of REQ-005/REQ-007, deferred to SPEC-015 — see §7a; pairing handshake cross-stack-verified; J-a/J-b done)
tier: 3 (pairing handshake — Tier-1)
version: 0.8.0
audience: agent, human
author: Anuna Research (drafted with Claude Opus 4.8; v0.4 folds SPEC-013 round-3 findings; v0.5 folds round-4 R4-01, Claude Fable 5; v0.5.1 folds round-5 D-1/R5-07 clarification; v0.6.0 records the Tier-1 sign-off; v0.6.1 folds the round-6 clearance; v0.6.2 records the condition-J satisfaction, J-a/J-b riding; v0.6.3 records full IMPL-016 implementation; v0.6.4 folds the rendezvous design + REQ-012 live eviction; v0.6.5 folds the round-7 review — digest-leg deferral made explicit, NFR claims scoped to what is measured, release pin; v0.7.0 owner decision: 2-word phrase + N=1 burn-on-first-failure, wormhole-style; v0.8.0 folds the CLI verb set / CBCL convention merge — ADR-008/009/010, REQ-013…020, OQ-005…008; `progress` retired, `emit` split into `tell`/`send`, LOCAL_API_VERSION 4)
last-updated: 2026-08-11
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
  availability cost. **The Tier-1 gate is CLEARED 2026-06-10**: human sign-off
  (hark/docs/decisions/SPEC-013-tier1-signoff.md, D-1 ratified) + the round-6 independent
  spot-check (GPT-5.x, D-1 independently endorsed —
  hark/docs/decisions/SPEC-013-round6-spotcheck-findings.md). The **`cbcl_ristretto`
  point-validation audit (condition J) is SATISFIED 2026-06-11**
  (hark/docs/decisions/SPEC-013-condition-J-ristretto-audit.md: no blocking finding;
  owner-ratified after a live probe re-run). Two conditions ride into the handshake
  implementation: **J-a** (fix the `ct-equal?` strict-`and` MAC-length crash so the
  failed-attempt counter cannot be evaded) and **J-b** (the audit's §6 negative
  tests: K-=-identity abort, wrong-length MAC, M/N known-answer) — both bind
  **before `hark pair` ships**.
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
tracking without `eval`; a `hark tell` plain-chat verb; an **in-app pairing** flow
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
dialects → the hub mints a pairing record + a **2-word BIP39 phrase**
(*"rocket anchor"*). `hark pair 1-rocket-anchor` runs **SPAKE2** with the
hub; on success the hub releases the record (bound to the PAKE key) —
`{name, dialects, enc-mode, a cbcl-chat-invite cap}` — and hark joins under that name with
the invite, pinning the channel's encryption mode, no `--as`/`--speak`.
**HP-4 — plain chat.** `hark tell "looking into it"` sends a **valid CBCL** `(tell
@research "looking into it" :from @aria)`; the chat client unwraps the `tell` to render
the prose. No hand-written CBCL, no raw-text frames. A frame the operator wrote goes to
`hark send` instead ([[#REQ-016]]).
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
- **REQ-004 — Plain-chat verb (`emit`). SUPERSEDED** by [[#REQ-014]]/[[#REQ-015]]
  (v0.8.0, ADR-009). The verb is now `tell`, the argument is always literal text, and
  a caller-supplied form goes to `send`. Two clauses of the original text were also
  wrong about the implementation and are corrected rather than carried: the wrapped
  frame is `(tell @channel "<text>" :from @handle)` and is **not** auto-threaded,
  and `progress` no longer exists ([[#REQ-019]]). Retained here because
  [[#TEST-004]] and the IMPL-016 record reference it.
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
  the dialects by digest *(the digest-install leg is deferred to SPEC-015 — implementation
  status in §7a; today the record carries names with empty digests)*.
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
    TTL + a failed-attempt bound** (delete the record on the **FIRST failed MAC
    verification** — N=1, Magic-Wormhole's burn-the-code rule) + hub-side rate limiting —
    a 2-word BIP39 phrase is only ~22 bits, so the online-guess budget must be mechanized,
    not asserted "one guess per run" (R3-04). With the N=1 burn it IS one guess per mint,
    enforced: success odds 2^-22 per record, a mistyped code burns the pairing (loudly —
    the adder re-mints), and entropy adds nothing against a hub-DB reader anyway (the
    verifier is password-equivalent), so the shorter, more memorable phrase costs nothing
    the burn doesn't already cover.
  - **Pairing-specific transcript binding.** The reused module hard-codes router-enrolment
    identities/labels (`idB = "cbcl-router:" ++ deployment_id`, salt `"CBCL-enrollment-v1"`,
    MAC labels `cbcl-agent-confirm`/`cbcl-router-confirm`, a 3-word/5-byte password encoding).
    Pairing SHALL pin **its own** identity strings (e.g. `idB = "cbcl-chat-pair:" ++ hub_id`,
    a defined `idA`), its own HKDF salt/info, and an encoding covering the pairing
    phrase's **2 words** (`<<i1:11, i2:11, 0:2>>`) — so a pairing transcript is
    domain-distinct from an enrolment transcript and the promised "rocket anchor"
    phrase actually fits (R3-03).
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

### 4a. CLI verb set / CBCL convention merge (v0.8.0 — ADR-008…010)

Folded from [[SPEC-016-cli-verb-set-cbcl-merge]]. One obligation per requirement,
so a failing test attributes to a single clause.

- **REQ-013 — Performative-named minting verbs.** The hark CLI's message-minting
  surface SHALL consist of exactly `tell`, `reply`, `error`, and `send`. A verb on that
  surface that constrains its frame to one [[CBCL-performative|performative]] SHALL bear
  that performative's name; a verb accepting any performative SHALL bear the transport
  name `send`. Trace: `[[#TEST-013]]`.
- **REQ-014 — `tell` wraps literal text.** `hark tell <text>` SHALL wrap its argument
  into `(tell @<channel> "<text>" :from @<handle>)`. Trace: `[[#TEST-014]]`.
- **REQ-015 — `tell` does not parse its argument.** `hark tell` SHALL NOT parse its
  argument as CBCL, regardless of the argument's leading character. An argument
  beginning with `(` SHALL be transmitted as the quoted body of a `tell`.
  Trace: `[[#TEST-015]]` (prohibited-action).
- **REQ-016 — `send` transmits unmodified.** `hark send <frame>` SHALL transmit a
  caller-supplied CBCL frame unmodified, accepting any core or custom performative, bare
  or carried in a `(lang …)`, `(envelope …)`, `(signed …)`, or `(with-limits …)`
  envelope. Trace: `[[#TEST-016]]`.
- **REQ-017 — `send` adds nothing.** `hark send` SHALL NOT wrap, rewrite, reorder, or
  inject any parameter into the caller's frame — including `:thread`, `:from`, and a
  `(lang …)` envelope. Trace: `[[#TEST-017]]` (prohibited-action, scope-invariant).
- **REQ-018 — `send` refuses dialect teaching.** `hark send` SHALL refuse a frame whose
  parsed form is `(meta …)`. Trace: `[[#TEST-018]]` (negative-input).
- **REQ-019 — `progress` is retired.** hark SHALL NOT provide a `progress` CLI verb, a
  `kind=progress` [[local-api]] variant, or progress-specific frame validation. No
  replacement verb SHALL be added. Trace: `[[#TEST-019]]` (prohibited-action).
- **REQ-020 — Deprecation is loud and bounded.** `hark emit` and `hark progress` SHALL
  remain accepted as hidden aliases for exactly one minor release, SHALL write a
  single-line deprecation notice naming the replacement to **stderr**, and SHALL
  preserve their current exit codes so scripts break visibly rather than silently.
  Trace: `[[#TEST-020]]`.

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
- **ADR-004 — `emit` for plain chat; all frames valid CBCL. SUPERSEDED by ADR-009**
  (v0.8.0). Exposed the existing API-only `emit` kind as `hark emit`. The
  "all frames are valid CBCL" half survives verbatim in ADR-009; the single overloaded
  verb does not.
- **ADR-005 — Learn a chosen subset, not the whole menu.** Agents are role-scoped;
  learn-everything bloats them and removes operator control. The declaration is a
  validated menu for selection.
- **ADR-006 — Self-hosted curl install (OQ-003).** A platform-detecting
  `files.anuna.io/hark/install.sh` over a single binary — no Homebrew tap, no Codeberg
  releases. curl downloads skip macOS `com.apple.quarantine`, so notarisation is optional.
- **ADR-007 — Agent removal by the adder (OQ-004).** Mirrors dialect delete-by-adder
  ([[#REQ-012]]) — no per-channel roles system needed.
- **ADR-008 — A message-minting verb is named for what it produces.** On the CLI's
  message-minting surface, a verb constraining its frame to one performative bears that
  performative's name; a verb transmitting a caller-supplied frame of any performative
  bears the transport name. `reply` and `error` already satisfied it; `emit` and
  `progress` did not. Rejected: renaming `emit` to `send` while keeping one verb —
  `send` is already the transport word one layer down, and overloading it reproduces
  the defect. Full rationale: [[SPEC-016-cli-verb-set-cbcl-merge]].
- **ADR-009 — `emit` splits into `tell` and `send` ([[#REQ-014]]…[[#REQ-018]]).** One
  verb per contract, which removes the leading-`(` sniff that let a single verb carry
  two. `send` preserves `validate_for_emit`'s full width, including `Wrapped`
  envelopes. Because ADR-010 retires `progress` rather than folding it in, `send` is
  `emit` renamed and the per-handle causal store is untouched — no runtime behaviour
  changes.
- **ADR-010 — `progress` is retired without replacement ([[#REQ-019]]).** `progress`
  was never a performative, only the content string `"progress"` on a `tell`, so every
  way of getting it wrong failed silently. CBCL's sanctioned extension mechanism is a
  dialect-scoped custom performative, so hark carried a second, hand-rolled one beside
  it. It buys no delivery confirmation, does not complete the in-flight ask, has no
  read path in `src/`, and was never exercised in [[playtest-findings-2026-08-06]] —
  Simplicity Ladder rung 1. **Consequence:** hark stops discharging the client
  obligation in [[router-protocol]]; a hand-built progress frame missing `:thread`
  orphans under receipt id `"unknown"`, and that risk moves to the frame's author.
  Rejected for now: a `cbcl-router` dialect performative — the right shape, but it
  breaks the wire and needs a `(define …)` that does not exist. See OQ-005.

## 7. Resolved Questions

Settled in dialogue (project owner, 2026-06-09):

| # | Resolution |
| --- | --- |
| OQ-001 | Pairing = **SPAKE2 over a memorable BIP39 phrase** ([[#REQ-007]]), releasing a record (bound to the PAKE key K) that wraps a **`cbcl-chat-invite` cap** + `{name, dialects, enc}`. Reuses the `cbcl-crypto-spake2` **primitive** (pairing-specific transcript constants) + `cbcl-chat-invite`. **Tier-1 handshake.** **Round-3 correction (R3-01/R3-02):** anchors *capability + name*, NOT agent peer-identity; hub stores a **password-equivalent** verifier (not a one-way HMAC), bounded by single-use + TTL + a failed-attempt limit. |
| OQ-002 | A plain-chat verb exposing the proactive send path; all wire frames are **valid CBCL** (`tell`), the chat unwraps for display. **Revised v0.8.0:** the verb is `hark tell` and the form path is `hark send` ([[#REQ-014]]…[[#REQ-018]], ADR-009). |
| OQ-003 | **`files.anuna.io/hark/install.sh`** curl install over a single binary ([[#REQ-001]], ADR-006). |
| OQ-004 | An agent is removable **only by its `added_by` member** ([[#REQ-012]]). |

### Open (v0.8.0 — CLI verb set merge)

| # | Question | Disposition |
| --- | --- | --- |
| OQ-005 | Does progress return as a `cbcl-router` dialect performative, `(lang cbcl-router (progress @router :thread …))`? | **Defer, and pursue.** The CBCL-native shape; it converts a silent drop into a grammar violation. Breaks the wire and needs a `(define cbcl-router …)` that does not exist — cross-stack with cbcl-bus. Owner: project owner. |
| OQ-006 | Does hark keep any client-side guard for hand-built progress frames sent through `send`? | **No.** A transport that inspects payload semantics is a minting verb again (ADR-008). The [[router-protocol]] obligation moves to the frame's author. Revisit if OQ-005 lands. |
| OQ-007 | `hark ask` — does hark surface bare asks, or does the web wrap in the channel dialect? | **Defer.** Cross-stack with cbcl-bus; owns [[playtest-findings-2026-08-06]] FINDING-5. |
| OQ-008 | Does the [[local-api]] `kind` change ship with the CLI change? | **Same release.** The `LOCAL_API_VERSION` 3 → 4 bump is what makes a stale daemon fail loudly (exit 12); staging them creates a window where it does not. |

## 7a. Implementation status (IMPL-016, 2026-06-11)

All twelve requirements implemented across `hark` (Rust) + `cbcl-bus`
(LFE/Erlang) — EXCEPT the **digest-install leg of REQ-005/REQ-007, which is
deferred to SPEC-015**, not claimed (see the follow-ons below); plan of record
`plans/IMPL-016-agent-onboarding-dx.spl`.

- **Tier-3 DX (hark):** REQ-001 install.sh + `make dist` + release CI
  (`.github/workflows/release.yml` builds all four `hark-<os>-<arch>` binaries
  + `.sha256` on native runners, names matching install.sh; it targets
  GitHub-hosted runners, so it runs on a **GitHub mirror** — Codeberg-hosted
  runners are Linux-only — and builds against a cbcl-rs commit **pinned in the
  workflow** (`--locked` cannot pin path-dependency contents; bump the pin per
  release)); REQ-002 `hark join`;
  REQ-003 daemon-tracked active handle (no `eval`); REQ-004 `hark emit`;
  REQ-005/008 declared-menu `--speak` validation; REQ-006 `announce`; REQ-009
  response scoping.
- **Pairing (Tier-1, REQ-007/011):** the SPAKE2 handshake is implemented on
  both sides and **cross-stack byte-verified** by a shared known-answer fixture
  (`tests/fixtures/pairing-vectors.json`): the LFE hub responder
  (`cbcl-chat-pairing`, over the relocated shared `cbcl_bus` crypto) and the
  Rust initiator (`hark pair`, curve25519-dalek) reproduce identical
  msg_a/msg_b/K/MACs/AEAD-record. Store enforces single-use + TTL + the N=1
  burn-on-first-failed-MAC bound (wormhole-style); the record is released bound to K; the encryption pin
  derives from invite-cap presence (R4-01). `/pair/v1` WS endpoint + the web
  "add agent" mint flow (`addagent` → `paircode` code). The code is a
  Magic-Wormhole nameplate (smallest free integer) + the 2-word phrase
  (`1-rocket-anchor`); the phrase never crosses the wire, and the small
  nameplate is paired with a per-source `/pair/v1` rate limiter that *throttles*
  blind enumeration (it bounds the burn rate per source; it cannot stop a
  distributed attacker — the residual risk is availability, never secrecy) —
  see [[SPEC-016-pairing-rendezvous]].
- **Provenance/removal (REQ-010/012):** `cbcl-chat-provenance` records the
  adder; the agent's `announce` carries `:added-by` so every roster shows it;
  `removeagent` is authorized only against the recorded adder and **evicts the
  agent from the live roster** (`cbcl-chat-room:evict`).
- **Control dialect learned from the hub (no baked copy):** the hub's control
  performatives (`announce`/`addagent`/`paircode`/… + the folded-in room/MLS
  verbs) are a real CBCL dialect. Rather than ship a copy that drifts, the hub
  **teaches** it: every join leads with a `(meta (define hub …))` advertisement
  (CBCL's native dialect-distribution path), built from the hub's canonical
  `priv/dialects/hub.cbcl` (`cbcl-chat-dialects:hub-meta-frame`). hark learns it
  via the Meta → `InstallDialect` mechanism (`hub_dialect::learn_hub_dialect`)
  and validates its own `announce` against the grammar the hub actually
  declared. **Ordering contract:** the meta precedes the join verdict
  (`roomcfg`/`presence`) — pinned hub-side by
  `join-leads-with-the-hub-dialect-meta`; a hub that taught only after its
  verdict would degrade to the taught-nothing path. Only the dialect actually
  *named* `hub` (and defining `announce`, the frame the agent self-validates)
  counts as control-grammar teaching — other dialects distributed over the
  same meta path (e.g. `cite`) are ignored for this purpose, and a hub
  dialect once learned is never clobbered by a later bad frame (R7-001). A
  legacy hub that teaches nothing — and a hub whose advertisement cannot be
  learned (warning carries the learn error) — degrades to a surfaced warning
  (announce still emitted).
  hark's test fixture of the grammar is drift-guarded byte-for-byte against
  the canonical hub file when a sibling `cbcl-bus` checkout is present
  (`hub_dialect_fixture_matches_the_canonical_cbcl_bus_grammar`). Verified
  end-to-end against the live hub.
- **Condition J:** signed off; J-a (`ct-equal?` fix) and J-b (negative tests)
  implemented.
- **NFRs measured (scope: `hark join`, local mock hub):** the one-shot
  `hark join` against a local in-process **mock** WS hub (a real WebSocket
  server speaking the join protocol; full config-scaffold → daemon-spawn →
  signed hello → ack) is a **single command** completing in **~1.0 s**
  (NFR-001: ≤ 3 commands, ≤ 60 s), with the hub-ack → success-report feedback
  at **~3 ms** (NFR-003: ≤ 400 ms Doherty) — asserted as a budget regression
  guard by `nfr_time_to_agent_and_feedback_within_budget` in
  `tests/join_cli.rs`. This is loopback CLI-overhead measurement, NOT a field
  measurement: real-network latency and the `hark pair` feedback path are not
  measured. The SPAKE2 handshake algebra + the no-false-accept
  security property are property-tested over arbitrary verifiers/ephemerals
  (`src/pairing/spake2.rs::proptests`), beyond the single cross-stack KAT.

- **Live playtest (2026-06-11, browser-automated web + real hub):** the happy
  paths verified end-to-end against a local cbcl-bus hub — HP-1 (install.sh
  artifact resolution), HP-2 (one-shot join, 0.07 s, hub-taught dialect
  learned, no warnings beyond the expected menu-absent soft-pass), HP-3 (web
  `addagent` → `1-ice-boat` → `hark pair`, 0.03 s), HP-4 (`hark emit` rendered
  for the web member as a verified signer), HP-6 (roster: agent treatment +
  *"aria · added by @mira"* + adder-only remove control); plus single-use and
  the N=1 burn live. The playtest caught one real defect, fixed: `hark emit`
  wrapped tells WITHOUT `:from`, which the hub's per-frame sender resolution
  rejects (`missing-from`) — the same omission the announce had (mock hubs
  don't enforce `:from`; only a live hub could catch it).

**Documented follow-ons (dependent on other work, surfaced not faked):** the
**digest leg of REQ-005 and REQ-007** waits on the hub's SPEC-015 `roomcfg`
dialect menu + fetch-by-digest endpoint. Concretely, today: the web `addagent`
prompt sends dialect **names only** (`priv/web/app.js`), the hub mints pairing
records with **empty digests** (`cbcl-chat-session-ws:dialect-entry` — `{name,
<<>>}`), and `hark pair` passes the names through to the join, where
acquisition degrades to the surfaced "cannot be acquired by digest yet"
warning. The `{name, digest}` record **schema** is in place end-to-end (and
KAT-verified with a non-empty digest); the install-by-digest / fail-closed
behaviour is NOT claimed implemented and lands with SPEC-015. (REQ-012 live
roster eviction is now implemented — `cbcl-chat-room:evict`; only rejoin
prevention for a still-cap-holding agent is deferred, a cap-revocation concern
orthogonal to de-listing.)

## 8. Verification Strategy (Phase 2 — IMPL-016)

Example-based per REQ; **integration / live** tests (a real `hark join`/`hark pair`
against the deployed hub, asserting the agent appears, renders as an agent, auto-learns,
and is named/added-by correctly); a **synthetic-user** pass (≤3-command / ≤60 s, Doherty
feedback). The **SPAKE2 pairing** ([[#REQ-007]]) additionally gets the Tier-1 treatment
(property + adversarial + cross-model review) before implementation.

### 8a. TEST-013…020 (CLI verb set merge)

Split into a **core** an implementer writes in one sitting with no new rig, and
**depth** that needs infrastructure. All eight core tests are implemented and green.

| TEST | type | case | tier | where |
| --- | --- | --- | --- | --- |
| TEST-013 | positive | the visible subcommand set is exactly `tell`, `reply`, `error`, `send`; `emit`/`progress` are hidden | core | `src/cli.rs` `minting_surface_is_tell_reply_error_send` |
| TEST-014 | positive | `tell "hi"` builds `(tell @chan "hi" :from @me)`, escaping the text | core | `src/cli.rs` `tell_wraps_plain_text` |
| TEST-015 | prohibited-action | `tell '(tell @x "y")'` yields a frame whose parsed recipient is the channel and whose content is a **string atom** — never a form addressed to `@x` | core | `src/cli.rs` `tell_never_parses_its_argument_as_cbcl` |
| TEST-016 | positive | `send` accepts bare, `(lang …)`, and `(signed …)` frames, any performative, with or without `:thread` | core | `src/cbcl_validation.rs` `send_accepts_any_performative_bare_or_wrapped` |
| TEST-017 | scope-invariant | the bytes reaching the router equal the caller's frame | core | `tests/agent_workflow_cli.rs` |
| TEST-018 | negative-input | a **parseable** `(meta …)` form is refused by the emit guard, asserted on the guard's own message | core | `src/cbcl_validation.rs` `send_refuses_meta_forms` |
| TEST-019 | prohibited-action | no `cbcl_progress_*` error code survives; frames the retired rules rejected now pass or fail for other reasons | core | `src/cbcl_validation.rs` `no_progress_specific_validation_remains` |
| TEST-020 | positive | the deprecated aliases still run and still reach the wire | core | `tests/e2e_mvp.rs`, `tests/agent_workflow_cli.rs` |
| TEST-020b | negative-input | the aliases are gone one minor release later | **depth — deferred**, release-gated. Owner: project owner |

**Mutation evidence (Red Gate substitute, Constitutional Principle 3).** Strict
test-first ordering was impractical for a deletion-heavy refactor, so the suite was
verified by deliberate mutation instead. Three mutations, each run against the test
that claims to catch it:

| mutation | result |
| --- | --- |
| un-hide the deprecated `emit` alias | TEST-013 **fails** ✅ |
| `build_tell_message` stops escaping its text | TEST-015 **fails** ✅ |
| `validate_for_emit` stops refusing `Message::Meta` | TEST-018 **survived** ❌ → repaired |

The third mutation survived on the first attempt: the `(meta …)` input chosen for
TEST-018 did not parse, so the pipeline rejected it as malformed and the guard was
never reached — a test that passed whether or not the guard existed. Repaired by
choosing a parseable `(meta (teach …))` form and asserting the guard's own message
rather than its error code, which a parse failure shares. The mutation is killed
after the repair. The pre-existing `emit_rejects_meta_and_malformed` test has the
same weakness and is **not** repaired here — out of this change's scope, recorded
so it is not mistaken for coverage.

## 9. Traceability

`REQ → TEST → CODE → OBS`, `[[wikilinks]]`, `zetl check --dead-links`. Depends on
[[SPEC-015-channel-dialects]], the `announce` emission, and the reused `cbcl-crypto-spake2`
+ `cbcl-chat-invite`; sibling to [[SPEC-013-mls-private-channels]]. Supersedes
[[SPEC-014-agent-host-delegation]].
