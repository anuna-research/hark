# IMPL-016 — SPAKE2 Pairing Flow: Scoping Plan

> **Status:** scoping / planning only — no production code. Implements the
> **SPAKE2 pairing handshake** of [[SPEC-016-agent-onboarding-dx]] REQ-007 / ADR-003
> (the one Tier-1 piece of an otherwise Tier-3 DX spec). Honours the
> [[SPEC-013-mls-private-channels]] round-3 re-scope (ADR-006, R3-01/R3-02): pairing
> anchors **capability + name**, not peer identity.
>
> **Owner repo:** `hark`. **Affects:** `cbcl-bus` (web mints the record; hub runs the
> responder). **Date:** 2026-06-10.

---

## 1. Goal & Non-Goals

**Goal.** Let an operator add a named, dialect-scoped agent to a channel from the web app
without a TOML edit, `--as`, or `--speak`: the web mints a pairing record + a memorable
3–4-word BIP39 phrase, the operator runs `hark pair "rocket anchor velvet"`, hark runs
SPAKE2 with the hub, and on success retrieves `{name, dialects, enc-mode, a
cbcl-chat-invite cap}` and joins the channel under that name with the cap.

**Non-goal — this is capability/name onboarding, NOT MLS identity.** Per
[[SPEC-013-mls-private-channels#ADR-006]] (re-scoped by R3-01/R3-02), the SPAKE2 pairing
is **not** the agent Authentication Service. It carries **no peer-identity material** (no
member keys, no group fingerprint, no adder pin), and because plain SPAKE2 is **not an
augmented PAKE** (R3-02) the hub holds a **password-equivalent verifier** — it cannot
authenticate record contents *against* the hub. The handshake authenticates **capability +
name delivery to the intended agent against third parties**, nothing more.

**Accepted residual (already ratified — [[SPEC-013-tier1-signoff]] item B).** For agents
the first-contact identity root is **hub-mediated TOFU**, winnable by an active hub by
construction until verified. The compensating control is the **REQ-024 safety number**
(`hark safety-number <@channel>`, already shipped — `cli.rs:63`) compared **out-of-band**:
the operator compares once at pairing time and again on any membership change or rotation
([[SPEC-013-mls-private-channels#REQ-024]]). IMPL-016 SHALL NOT claim the phrase anchors
identity.

---

## 2. The Pairing Handshake, End to End

The phrase flow maps onto the existing SPAKE2 state machine in
`cbcl-bus/apps/cbcl_router/src/crypto_core/cbcl-crypto-spake2.lfe` (initiator = agent,
responder = hub; three `step/2` calls each side). hark is the **initiator**
(`init-initiator/1`); the hub is the **responder** (`init-responder/1`).

1. **Web mints (cbcl-bus).** Operator names the agent and picks dialects in the web "add
   agent" UI. The web/hub mints:
   - a **pairing record** `{agent-name, channel, enc (advisory — the channel's pinned
     mode), cbcl-chat-invite cap, adder, chosen (name, digest) dialects, exp}` (REQ-007),
     stored hub-side bound to the phrase;
   - a **3–4-word BIP39 phrase** (e.g. *"rocket anchor velvet"*), single-use, short TTL.

2. **Operator runs `hark pair "rocket anchor velvet"`.** hark decodes the phrase to a word
   -index byte encoding (the 4-word pairing encoding — see §3 / R3-03), derives the
   password scalar `w`, and starts the SPAKE2 initiator.

3. **SPAKE2 exchange (RFC 9382, Ristretto255).** Mirrors the `.lfe` step order over a hub
   pairing endpoint:
   - hark → hub: **`msg_A`** (`X*B + w*M`).
   - hub → hark: **`msg_B`** (`Y*B + w*N`).
   - hark → hub: **`mac_A`** = `HMAC(K, "<pair-confirm-A-label>" ‖ transcript)`.
   - hub → hark: **`mac_B`** = `HMAC(K, "<pair-confirm-B-label>" ‖ transcript)`; hark
     verifies it in constant time (`ct-equal?`).
   Both sides derive the session key **`K`** = `HKDF(transcript, salt, "<pair-info>", 32)`.
   On `N=3` failed MAC verifications the hub deletes the record (R3-04).

4. **Record release bound to K.** On a verified handshake the hub releases the pairing
   record **encrypted and/or MAC'd under K** (REQ-007: "bound to the PAKE-derived session
   key K", not merely "sent after success"). hark decrypts/verifies under K and obtains
   `{name, dialects, enc-mode, cbcl-chat-invite cap}`.

5. **Join under the delivered name with the cap.** hark joins the channel under
   `name` (REQ-011, `--as` overriding) presenting the `cbcl-chat-invite` cap on the
   `(hello … :cap "<token>")` line — the existing admission path (`chat.rs:118` /
   `cap_part`, `chat.rs:78`), reusing [[SPEC-013-mls-private-channels#HP-1]] invite-as-cap.
   It installs the chosen dialects by digest (REQ-005) and emits `announce` (REQ-006).

6. **Derive the REQ-023 enc-mode pin from cap presence, not from `enc`.** The delivered
   `enc-mode` is **advisory only** (R4-01): the record is hub-released and not
   authenticatable against the hub, so a hub-alterable bit must never decide plaintext-vs-
   encrypted. The pin derives from the **cap's presence** — a cap admits to a private
   channel, private ⇒ encrypted — so hark pins `enc=true` before its first frame whenever
   the record carries a cap ([[SPEC-013-mls-private-channels#REQ-023]](a)). A conflict
   between the advisory `enc` and cap presence is surfaced; the cap-derived pin wins. A
   record with **no cap** SHALL NOT use `enc=true` alone as a pin — if the channel is
   believed private, `hark pair` fails closed (no plaintext send).

**Wire verbs touched:** `msg_A` / `msg_B` / `mac_A` / `mac_B` (the SPAKE2 frames, new
pairing endpoint); then the existing chat-join verbs — `hello` (with `:cap`), the hub
`roomcfg` ack judged by `MlsSession::on_roomcfg` (`chat.rs:144`), `presence`, `announce`.

---

## 3. What It Depends On

| Dependency | State today | What IMPL-016 needs |
| --- | --- | --- |
| **SPAKE2 primitive** | Exists **only in LFE** — `cbcl-bus/.../cbcl-crypto-spake2.lfe` (RFC 9382 framing on Ristretto255, depends on the `cbcl_ristretto` NIF). **No Rust SPAKE2 exists** in `cbcl-rs` (grep for "spake" returns nothing) or in hark (`Cargo.toml` has only `cbcl-core`, `cbcl-parser`, `openmls*`). | **Must be built/added on the hark side.** Two options: (a) add an interoperable Rust SPAKE2 crate to hark `Cargo.toml` (e.g. a curve25519-dalek/Ristretto255 implementation) re-implementing the exact transcript/HKDF/MAC framing of the `.lfe` module so the two sides interop bit-for-bit; or (b) a shared NIF/FFI. **Recommendation: (a) a Rust impl pinned to identical constants + cross-language test vectors** — the wire/transcript bytes are the contract, mirroring the [[SPEC-013-mls-private-channels#NFR-001]] shared-test-vector discipline. (b) couples hark to the Erlang VM and is rejected. |
| **BIP39 phrase handling** | None in hark. | A BIP39 wordlist + decode (phrase → word indices → password bytes). Encoding must cover **4 words**, not the LFE module's 3-word/5-byte enrolment encoding (R3-03). |
| **Pairing-record format** | Defined in spec (REQ-007); not implemented either side. | A serde struct in hark for the K-bound record `{name, channel, enc, cap, adder, dialects:[(name,digest)], exp}`; the hub minting side in cbcl-bus. |
| **cbcl-chat-invite cap** | **Reused as-is** — the admission path already exists (`chat.rs:78` `cap_part`, `local_api.rs:179` `cap` field). | No new admission protocol; the record's cap flows into the existing `:cap` hello clause and the `cap_present` pin derivation (`local_api.rs:810`). |
| **SPEC-015 dialects** | Channel-declaration / auto-learn ([[SPEC-015-channel-dialects]]). | The record's `(name, digest)` dialect list is installed by digest on join (REQ-005). |

---

## 4. hark Changes (real files / functions)

1. **New CLI command — `hark pair <phrase>`** (`src/cli.rs`). Add a `Pair(PairArgs)`
   variant to `pub enum Command` (`cli.rs:37`), alongside `Init`/`SafetyNumber`, with a
   `pair_command(args)` dispatch arm in `run()` (`cli.rs:205`). `PairArgs`: the phrase
   (positional), optional `--as` override (REQ-011), optional `--channel`, `--json`.
   It mirrors `init_command` (`cli.rs:327`): discover the live daemon client, then issue a
   daemon request — but the request now carries the **phrase**, and the daemon performs the
   handshake (the phrase must not be logged; the daemon holds it transiently).

2. **Config additions** (`src/config.rs`). The pairing/SPAKE2 endpoint. The hub URL is
   already derivable from `[router] ws_url` / `[chat]` (`config.rs:21`); add (if the
   handshake is not on the same `/chat/v1` socket) a pairing endpoint setting and the BIP39
   wordlist resource. Pairing produces a chat-transport join, so it slots beside
   `ValidatedChatConfig` (`config.rs:111`).

3. **Local-API / daemon wiring** (`src/local_api.rs`). Add a `PairRequest { phrase,
   handle_override, channel }` and a handler that: (a) runs the SPAKE2 initiator against
   the hub; (b) on success decrypts the K-bound record; (c) then funnels into the **existing
   create-agent path** by constructing a `CreateAgentRequest` (`local_api.rs:159`) with
   `dialects` = record dialects, `handle` = record name (or override), `channel` = record
   channel, and **`cap` = the record's `cbcl-chat-invite` cap**. This deliberately reuses
   the create path so the pin derivation is unchanged.

4. **enc-mode / cap → `open_if_relevant`'s `pinned_encrypted` (REQ-023).** The crucial
   integration point already exists and need not be re-invented. In `local_api.rs:810`,
   `cap_present` is computed from `request.cap` and passed as the `pinned_encrypted`
   argument to `MlsSession::open_if_relevant` (`session.rs:170`), which sets
   `enc_pinned` (`session.rs:134`). **Pairing feeds this chain by putting the record's cap
   into `CreateAgentRequest.cap`** — so a paired join into a private channel pins
   `enc=true` from cap presence, exactly as REQ-023(a) requires, with **zero new pin
   logic**. The advisory `enc-mode` from the record is used only to **surface a conflict**
   if it disagrees with cap presence; the cap-derived pin wins. A capless record believed
   private fails closed (no `CreateAgentRequest` issued).

5. **REQ-024 surface — already shipped.** `hark safety-number <@channel>`
   (`cli.rs:63`, `safety_number_command`) is the out-of-band compensating control;
   IMPL-016 documents that the operator runs it at pairing time. No code change.

---

## 5. Affected-Repo (cbcl-bus) Changes

These live in **cbcl-bus** (cbcl-chat is deprecated; the bus is the hub).

1. **Web "add agent" mints the pairing record + BIP39 phrase.** The web UI (operator names
   the agent, picks dialects) calls a hub endpoint that creates the record `{name, channel,
   enc, cbcl-chat-invite cap, adder, dialects, exp}`, stores it bound to the phrase
   (single-use, short TTL, failed-attempt counter), and returns the 4-word BIP39 phrase to
   display.

2. **Hub SPAKE2 responder endpoint.** A pairing handshake endpoint running
   `cbcl-crypto-spake2:init-responder/1` + `step/2` with **pairing-specific transcript
   constants** distinct from router enrolment (R3-03): pin `idB = "cbcl-chat-pair:" ++
   hub_id` (not `"cbcl-router:" ++ deployment_id`), a defined `idA`, its **own HKDF
   salt/info** (the module currently hard-codes `"CBCL-enrollment-v1"` /
   `"cbcl-spake2-password-v1"` / `"cbcl-session-key-v1"` and MAC labels
   `"cbcl-agent-confirm"`/`"cbcl-router-confirm"`), and a **4-word** password encoding (the
   module's `init-responder` documents a 3-word/5-byte encoding). On a verified handshake,
   release the record **bound to K**. Enforce **N=3 failed-MAC deletion** + hub-side rate
   limiting (R3-04) — a 4-word phrase is only ~44 bits, so the online-guess budget is
   mechanized, not asserted.

3. **Storage is password-equivalent.** The hub stores phrase/`w`/HMAC-as-password-input —
   **not** a one-way digest (an `init-responder` cannot run from a one-way digest). cbcl-bus
   docs/spec SHALL say so plainly; do not claim "stored only as an HMAC".

---

## 6. Security Review Obligation (Tier-1)

The SPAKE2 handshake is **Tier-1 / no-go** (auth-core). Per [[PROTO-001]] it requires
**cross-model adversarial review + human crypto sign-off before implementation**, exactly
as [[SPEC-013-mls-private-channels]] received (rounds 1–6, [[SPEC-013-tier1-signoff]]).

**Gate status (good news, with one rider).** The SPEC-016 Tier-1 gate was **CLEARED
2026-06-10** as part of the SPEC-013 sign-off (human sign-off + the round-6 GPT-5.x
independent spot-check — D-1 endorsed). **However, one condition rides into IMPL-016 and
blocks the handshake code specifically:**

> **Condition J — `cbcl_ristretto` point-validation audit** ([[SPEC-013-tier1-signoff]],
> "IMPL-016, before the pairing handshake is implemented"). SPAKE2 must **reject
> non-canonical / low-order / identity-element `msg_A`/`msg_B`**; `from_hash` /
> `scalar_reduce` soundness was *assumed*, not verified, by the round-3 reviewers. A human
> cryptographer or test vectors must close it.

**IMPL-016 SHALL NOT begin handshake code until condition J clears.** The Rust SPAKE2 side
inherits the same obligation: its point-validation must match the audited `cbcl_ristretto`
behaviour, with shared test vectors.

**Residuals a reviewer must explicitly accept** (carried from R3-01/R3-02, all already
ratified for SPEC-013 but re-affirmed for the IMPL):
- **Password-equivalent verifier at the hub** — a hub-DB reader can complete the pairing as
  either side and redeem the cap; bounded only by single-use + short TTL + N=3 failed-MAC
  deletion + rate limiting (R3-02, R3-04).
- **No peer-identity material** — the handshake binds capability + name only, never member
  keys / group fingerprint (R3-01).
- **TOFU first-contact for agents** — first-contact identity is hub-mediated TOFU, winnable
  by an active hub until the REQ-024 safety number is compared out-of-band (ADR-006).

---

## 7. Phased Task Breakdown

### Phase A — Safe to build now (non-crypto DX scaffolding, gate-independent)

No SPAKE2 / no `cbcl_ristretto` dependency; cannot send plaintext into a private channel.

- **A1. `hark pair <phrase>` CLI shape** — `Pair(PairArgs)` variant + `pair_command`
  dispatch (`cli.rs:37`, `cli.rs:205`), help text, `--as`/`--channel`/`--json` flags.
  Wire it to a **stub** daemon handler that errors `pairing_handshake_gated` until Phase B.
- **A2. BIP39 phrase parsing** — wordlist + 4-word phrase → word-index byte encoding
  (pure, testable, no crypto-handshake). Validate against the 4-word encoding (R3-03).
- **A3. Pairing-record serde + cap/enc-mode plumbing** — the record struct; the mapping
  `record → CreateAgentRequest { dialects, handle, channel, cap }` (`local_api.rs:159`);
  the conflict-surface logic between advisory `enc` and cap presence; the capless-private
  **fail-closed** path. Crucially this exercises the **existing** REQ-023 pin chain
  (`cap_present` → `open_if_relevant` → `enc_pinned`, `local_api.rs:810` /
  `session.rs:170`) with no new pin code.
- **A4. cbcl-bus record-minting endpoint + web UI** (record + phrase generation, TTL,
  single-use, failed-attempt counter) — the **release-bound-to-K** step is gated, but the
  record format, storage table, and BIP39 generation are safe.
- **A5. Operator workflow doc** — `hark safety-number` at pairing time (REQ-024).

### Phase B — Gated on the Tier-1 condition J (the SPAKE2 handshake itself)

Blocked until the `cbcl_ristretto` point-validation audit clears.

- **B1. Rust SPAKE2 primitive** — interoperable with the `.lfe` module (identical
  transcript/HKDF/MAC framing), with point validation matching the audited `cbcl_ristretto`
  and **cross-language test vectors**.
- **B2. Pairing-specific transcript constants** — `idB = "cbcl-chat-pair:…"`, defined
  `idA`, own salt/info/MAC labels, 4-word encoding (R3-03) — pinned identically on both
  sides.
- **B3. The handshake exchange** — `msg_A`/`msg_B`/`mac_A`/`mac_B`, constant-time MAC
  verify, **K-bound record release/decrypt**; hub responder endpoint + N=3 deletion +
  rate limiting (R3-04).
- **B4. End-to-end live test** — real `hark pair` against the deployed hub: agent appears,
  renders as agent, auto-learns dialects, named/added-by correct; plus property +
  adversarial tests per [[SPEC-016-agent-onboarding-dx#8-verification-strategy-phase-2--impl-016]].

---

## 8. Open Questions

**SPEC-016 OQ-001..004 status** (all APPROVED 2026-06-09 —
[[SPEC-016-open-question-decisions]]):

| # | Status carried forward |
| --- | --- |
| OQ-001 | **APPROVED (Tier-1 carve-out).** Pairing = SPAKE2 over a BIP39 phrase releasing a K-bound record wrapping a `cbcl-chat-invite` cap + `{name, dialects, enc}`. Tier-1 gate **CLEARED 2026-06-10**, but **condition J blocks the handshake code** of IMPL-016. |
| OQ-002 | **APPROVED.** `hark emit` plain-chat verb; all frames valid CBCL. (Separate REQ-004 DX work; not part of this pairing scope.) |
| OQ-003 | **APPROVED.** `files.anuna.io/hark/install.sh` curl install. (REQ-001 DX; out of scope here.) |
| OQ-004 | **APPROVED.** Agent removable only by its `added_by` member. (REQ-012; orthogonal to pairing.) |

**Surfaced by this scoping:**

- **OQ-A (build vs NIF).** Confirm the Rust SPAKE2 path: a hark-side Rust crate mirroring
  the `.lfe` transcript byte-for-byte (recommended) vs a shared NIF. Affects Phase B1 and
  the cross-language test-vector burden.
- **OQ-B (transport for the handshake).** Is the SPAKE2 exchange a new hub endpoint or
  multiplexed over the existing `/chat/v1` socket? Affects §4.2 config and the cbcl-bus
  endpoint shape.
- **OQ-C (capless-private fail-closed UX).** REQ-007 says a capless record believed private
  must fail closed; confirm the exact operator-facing message and recovery (re-pair / fresh
  invite) so it is not mistaken for a transport error.
- **OQ-D (condition-J timing).** Who runs the `cbcl_ristretto` point-validation audit and
  when, since it is the single hard blocker on Phase B. Track it like a SPEC-013 review
  round.

---

## Traceability

`REQ → TEST → CODE → OBS`, `[[wikilinks]]`, `zetl check --dead-links`. Implements
[[SPEC-016-agent-onboarding-dx#REQ-007]] / ADR-003; honours
[[SPEC-013-mls-private-channels#ADR-006]], [[SPEC-013-mls-private-channels#REQ-023]],
[[SPEC-013-mls-private-channels#REQ-024]]; depends on [[SPEC-015-channel-dialects]],
`cbcl-crypto-spake2` (LFE today), and the reused `cbcl-chat-invite`. Gated by
[[SPEC-013-tier1-signoff]] condition J.
