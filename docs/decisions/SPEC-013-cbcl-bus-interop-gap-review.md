# SPEC-013 ⇄ cbcl-bus — Encrypted-Channel Interop Gap Review

- **Date:** 2026-07-10
- **Reviewer:** Claude Fable 5 (workflow session, [[PROTO-001]] Phase-4 review; hark-side
  evidence re-verified in-repo, cbcl-bus evidence from a fresh-context survey with
  spot-verification of every load-bearing claim)
- **Scope:** does today's `cbcl-bus` (hub + web client + in-repo `cbcl-mls-wasm` crate +
  vendored artifact, HEAD `43f37a4`) let a `hark` agent participate in an encrypted private
  channel per [[SPEC-013-mls-private-channels]]? What breaks, what is merely
  non-conformant, and what must land where.
- **Inputs:** [[SPEC-013-mls-private-channels]] v0.8.1 (gate CLEARED 2026-06-10),
  [[SPEC-013-tier1-signoff]], [[IMPL-013-trace]], hark `src/mls/*` (9 modules, all
  IMPL-013 tasks completed in `plans/impl-013-mls.spl`), cbcl-bus
  `crates/cbcl-mls-wasm/src/lib.rs` (single commit `e6fd708`, 2026-06-10),
  `apps/cbcl_chat/priv/web/{app.js,mls.js,mls-wire.js}`,
  `apps/cbcl_chat/src/{cbcl-chat-session-ws.lfe,cbcl-chat-room.lfe,cbcl-chat-roomcfg.lfe,cbcl-chat-keypkg.lfe}`.

## Orientation

**Intent:** hark's MLS side is done and live-verified agent↔agent; this review locates the
exact seam that still prevents agent↔web interop and ranks the remaining cbcl-bus work.

**Verdict in one line:** the wire/crypto substrate is compatible (openmls 0.8.1 both
sides, pinned ciphersuite, [[SPEC-013-mls-private-channels#REQ-007]] binding and the
`0xF013` genesis capability landed in `cbcl-mls-wasm`), but **four gaps in the cbcl-bus
web glue break the happy paths outright** — the web client creates genesis-less groups
hark fail-closed rejects (IG-1), never emits the `idkey` assertion hark needs to pin
web members (IG-2), never mints removal evidence (IG-3), and has no safety-number
surface (IG-4) — and the entire [[SPEC-013-mls-private-channels#REQ-017]] validation
layer is still absent web-side, so the [[SPEC-013-mls-private-channels#ADR-001]]
lockstep obligation remains open. One shared-substrate risk sits underneath all of it:
the hub parses CBCL via a cbcl-rs pin now 74 commits behind the revision hark builds
against (DR-1, §4). **No hark-side change is required for compatibility; hark SHALL NOT
relax its fail-closed checks to tolerate the gaps.**

## 1. Confirmed-compatible surface

Verified present and interoperable on both stacks:

| Surface | hark | cbcl-bus | Evidence |
|---|---|---|---|
| MLS stack + version | openmls **0.8.1** (`Cargo.lock`) | openmls **0.8.1** (`Cargo.lock`; manifest is caret `"0.8"` — see BK-3) | both resolve identically today |
| Ciphersuite | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (`src/mls/mod.rs:42`) | same (crate) | [[SPEC-013-mls-private-channels#NFR-001]]; §10 spike round-trip PASS both directions |
| [[SPEC-013-mls-private-channels#REQ-007]] leaf = wire [[Ed25519]] key | `MlsIdentity::from_wire_identity` (`src/mls/mod.rs:110`) | `Identity::from_wire_key` (`lib.rs:99`), wired from IndexedDB seed (`app.js:64-172`, `mls.js:29-42`) | binding landed both sides |
| [[SPEC-013-mls-private-channels#REQ-016]] genesis ext type + capability | `GENESIS_EXT_TYPE = 0xF013` (`src/mls/mod.rs:47`) | `0xF013` (`lib.rs:23`), advertised on every KeyPackage/leaf (`lib.rs:29-37,130`), K-2 create guard (`lib.rs:177-209`) | type IDs match; K-2 present both sides |
| [[SPEC-013-mls-private-channels#REQ-014]](a) hub `bye` evidence fan | consumes evidence | hub forwards verified payload+sig room-wide pre-leave (`session-ws.lfe:596-601`, `room.lfe:61-68`) | the affected-repo wire change **landed** |
| [[SPEC-013-mls-private-channels#REQ-016]] creator bookkeeping | n/a | `cbcl-room.creator` recorded at claim + schema migration (`roomcfg.lfe:35,100-106`) | landed (bookkeeping, not trust — correct) |
| Condition A-t / K-2 / K-1 (hark side) | `no_cross_protocol_signature_collision` (`src/mls/pins.rs:498`); K-2 guard (`src/mls/group.rs:281-304`); K-1 retry per [[IMPL-013-trace]] | — | sign-off conditions discharged in IMPL-013 |

hark↔hark encrypted exchange is live-verified ([[IMPL-013-trace]] playtest, identical
[[SPEC-013-mls-private-channels#REQ-024]] safety numbers + round-trip decrypt); native ⇄
wasm wire compatibility is spike-verified (`experiments/spec-013-mls-spike/cross-stack/`).

## 2. Interop-breaking gaps (block the happy paths hark↔web)

### IG-1 — Web group creation omits the genesis: hark can never join a web-created group. **Critical.**

The wasm API accepts a genesis (`Group::create(provider, identity, genesis?)`,
`lib.rs:177`), but the web controller calls it **without one**:
`B.Group.create(provider, identity)` (`mls.js:56`). hark's Welcome validation
hard-rejects a group whose GroupContext carries no genesis extension —
`"welcome's group carries no genesis extension (REQ-016)"` (`src/mls/group.rs:483-494`),
by design ([[SPEC-013-mls-private-channels#REQ-016]] durable-delivery obligation).

**Consequence:** [[SPEC-013-mls-private-channels#3. Users & Happy Paths|HP-1]] fails
whenever the group creator is a web member — i.e. the *primary* onboarding flow (human
invites agent into an existing private channel) is dead on arrival. The reverse works:
a hark-created group (`hark init --mls-create`) admits web members, because the web side
validates nothing (see LG table).

**Fix (cbcl-bus, web glue):** on `createGroup`, build the creator-signed genesis
assertion (`cbcl-mls-genesis/v1` context: `(genesis @room :creator @h :group <id> :key K)`
signed by the wire key — hark's `genesis_signing_bytes`, `src/mls/group.rs:84`, is the
normative byte layout) and pass it to `Group.create`. The crate needs a small signing
seam (it holds the `SignatureKeyPair`; expose a `sign_genesis` or accept
handle→signed-bytes from JS). Byte-compat MUST be vectored against hark's
`create_add_join_roundtrip_with_genesis` (`src/mls/group.rs:722`).

### IG-2 — Web members never emit `idkey` assertions: hark cannot pin them, so a hark owner cannot add a web member. **Critical.**

hark pins handle→wire-key only from self-signed evidence — in practice the
[[SPEC-013-mls-private-channels#REQ-019]] `cbcl-idkey-assert/v1` assertion
(`src/mls/pins.rs:148-178`); the live playtest needed idkey re-broadcast wiring even
agent↔agent ([[IMPL-013-trace]]). The web client has no idkey emission at all (label
absent from `apps/` — grep clean). Without a pin, hark's
[[SPEC-013-mls-private-channels#REQ-008]] adder check fail-closes any Add of a web
member.

**Consequence:** HP-1 also fails in the direction that *does* have a valid genesis —
hark as creator/owner cannot admit the humans. Together with IG-1, **no mixed
hark+web group can currently form in either direction.** (Joining an all-first-contact
tree via Welcome still works — [[SPEC-013-mls-private-channels#REQ-012]] TOFU path —
which is why hark↔hark passed.)

**Fix (cbcl-bus, web glue):** emit `(idkey @handle :key K :room @room :nonce N)` signed
under `cbcl-idkey-assert/v1` on join and on new-peer presence (mirror hark's
re-broadcast behaviour); verify + pin inbound ones. hark's `pins.rs` signing-bytes
layout is normative.

### IG-3 — Web clients neither mint nor validate removal evidence. **High.**

The hub relays `bye` evidence correctly now (landed — §1), but the web client sends no
`cbcl-mls-remove/v1` payload on leave and `remove_member` (`lib.rs:320-339`) produces
evidence-free Removes. hark rejects any Remove without exact-epoch evidence at merge
([[SPEC-013-mls-private-channels#REQ-017]](d), `src/mls/removal.rs`).

**Consequence:** HP-1/HP-2 survive, but membership diverges on any leave/eviction —
hark keeps the member in the MLS group (fail-closed, correct per spec) while the web
side's group drops them; subsequent web Commits from a diverged tree will then fail to
apply cleanly for hark members. Epoch churn + drained KeyPackages follow.

**Fix (cbcl-bus):** web leave mints the self-signed `bye` evidence (leaning on the
already-landed hub fan); web Removes carry remover-signed evidence; web validates
inbound Remove evidence (arrives with the REQ-017 layer, LG-1).

### IG-4 — No web safety-number surface: the ADR-006 compensating control is one-sided. **High.**

hark ships the [[SPEC-013-mls-private-channels#REQ-021]] identity safety number with a
pinned canonical encoding and a byte-exact vector (`src/mls/safety.rs:37-72,134-176`)
plus the `hark safety-number` CLI ([[SPEC-013-mls-private-channels#REQ-024]]). The label
`cbcl-mls-identity-safety/v1` appears **nowhere** in cbcl-bus. The entire
[[SPEC-013-mls-private-channels#ADR-006]] trust design (TOFU + out-of-band comparison)
assumes the web UI displays the same number; today the operator has nothing to compare
against, so first-contact TOFU is **uncompensated** — the exact residual the sign-off
accepted only *conditional on the comparison surface existing*.

**Fix (cbcl-bus):** implement the canonical frame (spec §REQ-021 pins the exact bytes;
hark's `identity_safety_number_vector` test is the shared vector NFR-001 requires) in
the wasm crate or JS, and render it in the web UI. This is also the **remaining §9
round-5 interop item** (shared test vector) — half-done until cbcl-bus reproduces it.

## 3. Lockstep security gaps (don't block interop; violate ADR-001 until closed)

hark tolerates these because its own checks are client-side, but each leaves the *web
members* of a mixed channel exposed, and [[SPEC-013-mls-private-channels#ADR-001]]
(“fix now, across all three codebases”) plus the Tier-1 gate's premises assume they
close. Severity per [[SPEC-013-mls-private-channels]]'s own review taxonomy:

| # | Requirement | cbcl-bus state | Severity |
|---|---|---|---|
| LG-1 | [[SPEC-013-mls-private-channels#REQ-017]] inbound validation | `Group::process` merges any Commit / stores any proposal, zero app checks (`lib.rs:288-316`); no allowlist, no credential-immutability — the R3-07 `:from`-forgery reopener is live web-side | Critical (web-side) |
| LG-2 | [[SPEC-013-mls-private-channels#REQ-008]]/[[SPEC-013-mls-private-channels#REQ-011]] pins | no pin store anywhere; `add_member` trusts hub-served KeyPackages (`lib.rs:234-254`) | Critical (web-side) |
| LG-3 | [[SPEC-013-mls-private-channels#REQ-018]] sender-auth `:from` | authenticated sender discarded (`lib.rs:296`); UI attributes from wire `:from` yet renders “custody-verified” (`mls.js:168-180`, `app.js:642-646`) — an unbacked claim | High |
| LG-4 | [[SPEC-013-mls-private-channels#REQ-012]] Welcome validation | `onWelcome` checks only `for == me` (`mls.js:156-166`) | High |
| LG-5 | [[SPEC-013-mls-private-channels#REQ-023]] mode pin | mode read straight from unsigned `roomcfg :enc`; `:enc false` silently un-pins — downgrade accepted (`app.js:631-632`); caps are stored (`app.js:1101-1119`) but never pin the mode | Critical (web-side; R4-01 unfixed in product) |
| LG-6 | [[SPEC-013-mls-private-channels#REQ-013]] single-use ledger | crate provider in-memory, no consumed-ref ledger, no delete-after-join (`lib.rs:43-44,257-268`); hub consume-once advisory (`keypkg.lfe:6,51-68`) | High |
| LG-7 | [[SPEC-013-mls-private-channels#REQ-015]] directory input validation | `keypub` writes raw binaries unbounded, no size/structure checks (`session-ws.lfe:449-474`, `keypkg.lfe:33-41`) | Medium ([[PROTO-001]] LangSec: trust-boundary input) |
| LG-8 | [[SPEC-013-mls-private-channels#REQ-020]] UI claim | private channels rendered “private, end-to-end encrypted (experimental, unaudited…)” (`app.js:638`) while LG-1..6 are open — the claim outruns the implementation again (R3-15's pattern) | High (operational) |
| LG-9 | [[SPEC-013-mls-private-channels#REQ-011]] rotation | `cbcl-idkey-rotate/v1` absent web-side | Medium (blocks rotation, not bootstrap) |

## 4. Shared-language layer: cbcl-rs parser drift (DR-1). **High (risk).**

Every SPEC-013 wire object — `keypub`/`keyget`, the fanned [[Welcome]]/[[Commit]]
frames, `idkey`/`rekey` assertions, `bye` removal evidence, `genesis` — travels as
CBCL, so the *language* compatibility surface is **cbcl-rs**, consumed differently by
the two sides:

- **hark** builds against cbcl-rs **HEAD** via path deps
  (`Cargo.toml:17-18` → `../cbcl-rs/crates/{cbcl-core,cbcl-parser}`);
- **the hub** builds its `cbcl-erl` NIF from cbcl-rs at the **pinned SHA**
  `693e3c15` (`cbcl-bus/cbcl-rs.sha` ↔ Dockerfile `ARG CBCL_RS_SHA`, enforced by
  `scripts/check-cbcl-rs-pin.sh`, SPEC-008 REQ-004).

As of 2026-07-10 the pin is **74 commits behind** hark's HEAD (`1e43e472`), and the
interval is not cosmetic: it includes grammar/semantic changes — typed-Merkle-root
content addresses + v3 attestation (cbcl-rs SPEC-017 stages 1–3), R4 v2 attestation
signing, redacted envelopes, `(repeat k …)`, the wrapper-dialect pin, and acceptance
*tightenings* ("reject address groups as content", CON-600 grammar fix). Two
recognisers for one wire language at different revisions is precisely the
**parser-differential** shape [[PROTO-001]] LangSec principle 5 prohibits ("one parser
per language"), and the [[SPEC-013-mls-private-channels]] threat model gives the hub
active-adversary status — divergence in what the two sides accept is exploitable
surface, not just an availability nuisance.

No concrete break is demonstrated (the 2026-06-10 live playtest predates part of the
drift), but the exposure grows with every cbcl-rs commit. **Fix:** bump
`cbcl-bus/cbcl-rs.sha` + Dockerfile in lockstep with the revision hark builds against
(or pin hark to the same SHA the hub ships), and add a **chat-frame conformance
corpus** — the SPEC-013 wire verbs round-tripped through both `cbcl-parser` (Rust) and
`cbcl-erl` (NIF) at CI time — so future skew fails a test instead of a channel.

*Owner disposition (2026-07-10):* acknowledged as a release-hygiene issue, not an
architectural one — an imminent cbcl-rs release will be **fixed and versioned**, which
supersedes ad-hoc SHA pinning on both sides. The design rationale: CBCL is deliberately
a **small core language whose growth happens through in-language self-extension**
(runtime-declared dialects under the R1–R5 invariants), so new capability lands as
dialect content the stable core parser already recognises, not as core-grammar change —
the drift window that matters is the small core, and versioned releases close it. The
conformance-corpus recommendation stands as the cheap regression guard for exactly that
core subset; severity accordingly read as **Medium (accepted, mitigation scheduled)**
rather than open High.

## 5. Bookkeeping corrections (spec/vault hygiene)

- **BK-1 — `affects-repos` is stale.** [[SPEC-013-mls-private-channels]] names
  `cbcl-chat (cbcl-mls-wasm crate)`, but the crate moved **into cbcl-bus** at `e6fd708`
  (2026-06-10, “move the crate in-repo with SPEC-013 changes; re-vendor the artifact”).
  All affected-repo work now lands in `cbcl-bus` alone. *Applied with this review:*
  spec header corrected, doc-only, v0.8.2.
- **BK-2 — dangling review gate.** `cbcl-mls-wasm`/web code comments gate MLS wiring on
  `cbcl-chat.spl` task `mls-review` — a plan file that no longer exists in cbcl-bus
  (legacy of the repo move). The gate needs a live home (a cbcl-bus IMPL plan — §6).
- **BK-3 — ADR-003 pin discipline.** cbcl-bus `Cargo.toml:24` uses caret `openmls = "0.8"`;
  hark likewise relies on `Cargo.lock` for 0.8.1. Both currently resolve 0.8.1, but
  [[SPEC-013-mls-private-channels#ADR-003]] says *version-pinned to the crate* — an
  unlocked `cargo update` on either side can silently diverge wire behaviour. Recommend
  `=0.8.1` in both manifests.
- **BK-4 — working-tree damage (hark).** `docs/decisions/SPEC-013-round6-spotcheck-prompt.md`
  has two accidentally indented blockquote markers (`>` → `    >`) as an uncommitted
  modification — looks like editor damage, not intent; recommend reverting the hunk.

## 6. Recommended sequencing (all in cbcl-bus; hark changes: none)

Ordered so each step unlocks an observable capability; the first three make HP-1/HP-2
work hark↔web:

1. **IG-1** genesis on web `createGroup` (+ crate signing seam) — unblocks web-created
   groups admitting agents.
2. **IG-2** idkey emission + pin store in web glue — unblocks hark-owned groups
   admitting humans; the pin store is also the substrate LG-1..4 need.
3. **IG-4** safety-number surface + shared NFR-001 vector — completes the ADR-006
   control and the last §9 round-5 interop item.
4. **IG-3 + LG-1** removal evidence + the REQ-017 validation layer in the crate
   (one body of work: both need pins + evidence verification at merge).
5. **LG-5** mode pin from admission path (R4-01 is folded in the spec but unfixed in
   the shipped web client), **LG-6** durable ledger, **LG-7** keypub validation,
   **LG-8** soften the UI claim until the above land.
6. **DR-1** (parallel, cheap, do first if a release is near): bump the cbcl-bus
   `cbcl-rs.sha` pin to the revision hark builds against; conformance guard per D-3
   below (in-language), with the CI corpus as interim fallback until the dialect lands.

**D-3 — Owner direction (ratified 2026-07-10): the SPEC-013 wire verbs ship as a
declared CBCL dialect.** The MLS wire verb set (`keypub`/`keyget`, the Welcome/Commit
fan frames, `idkey`, `rekey`, `bye` removal evidence, `genesis`) SHALL be specified as
a **pinned, content-hashed dialect declaration** under cbcl-bus SPEC-015 (per-channel
declared dialects), rather than as ad-hoc verbs each client recognises independently.
Rationale: this is CBCL's design point — a small stable core with in-language
self-extension under the R1–R5 invariants — applied to SPEC-013's own traffic. The
dialect content hash then *is* the cross-stack version agreement: hark, the web client,
and the hub all validate the verbs against one declared grammar (LangSec "one parser
per language" discharged by construction), and the two-recogniser conformance corpus
(DR-1) reduces to asserting both stacks accept the pinned dialect. Sequencing: after
the fixed-and-versioned cbcl-rs release (DR-1 disposition); the dialect declaration
becomes an early deliverable of the cbcl-bus IMPL plan, and IMPL-013's wire-contract
`CON-###` entries should reference it as the normative grammar source.

These belong in a **cbcl-bus IMPL plan** (hence `.spl`, per [[PROTO-001]] Phase 2) — the
successor to the vanished `cbcl-chat.spl` `mls-review` gate (BK-2) — with the
[[SPEC-013-mls-private-channels#9. Verification Strategy|§9 techniques]] applied
web-side (the shared safety-number vector, the K-1 remove-race retry test, and the
live hark↔web round-trip as the [[SPEC-013-mls-private-channels#REQ-010]] acceptance).

## 7. Traceability

Findings IG-1..4 / LG-1..9 / DR-1 / BK-1..4 trace to
[[SPEC-013-mls-private-channels]] REQ-007/008/011/012/013/014/015/016/017/018/019/020/021/023/024,
NFR-001, ADR-001/003/006, and [[SPEC-013-tier1-signoff]] conditions A-t/I/J/K-1/K-2
(hark-side: discharged; web-side: K-2 present in the crate, K-1 untested there).
Related: [[IMPL-013-trace]], [[SPEC-016-agent-onboarding-dx]] (pairing/`added_by`
remover authority), [[SPEC-013-round6-spotcheck-findings]].
