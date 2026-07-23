# SPEC-024 / IMPL-025 §2 — canonical-vector proof-of-fit spike

**Status:** complete.
**Gate-permitted:** this is the *one* work item [[IMPL-025-hark-mls-ds-client#2. Entry gates]]
permits while [[SPEC-024-mls-delivery-service|SPEC-024]] is `draft` and the production
cbcl-rs role layer is unpinned. Isolated crate (own empty `[workspace]`), detached from
hark's build, touches **no** production code. Mirrors `experiments/spec-013-mls-spike`'s
isolation discipline.

**Scope guard (read first):** this proves the [[SPEC-024-mls-delivery-service#CON-002]]
byte foundation **only**. It **MUST NOT** be reported as role-runtime binding
([[IMPL-025-hark-mls-ds-client#ADR-031]] / H1): the role verifier, the closed-world
recogniser, and the reducers are out of scope until the integration gate opens. See
[[IMPL-025-hark-mls-ds-client#H1 — Bind the shared PRODUCTION role runtime]].

## Purpose

Confirm that hark, linking the production `cbcl-core` encoder through its **own** path
dependency (`../cbcl-rs/crates/cbcl-core`), computes **byte-identical** canonical bytes to
the SPEC-024 web/NIF reference — the [[SPEC-024-mls-delivery-service#CON-002]] premise that
[[IMPL-025-hark-mls-ds-client#NFR-006]] cross-runtime parity rests on. A one-byte
disagreement here forks the log; this is the floor every later work package stands on.

## Run

```
cargo test --manifest-path experiments/spec-024-mls-ds-canonical-spike/Cargo.toml -- --nocapture
```

Every check prints a `[CON-002 …]` line — the stdout **is** the evidence. `2 passed`.

## Provenance (what was tested, exactly)

| Input | Value |
|---|---|
| cbcl-rs commit linked | `1c6fa8f581a69a7bcb88fb787fa37c81f5de4221` (`main`) — **note:** not the repo `cbcl-rs.sha` pin `693e3c15`, and *not* the production role layer (see finding 2) |
| `cbcl-core` / `cbcl-parser` | `0.1.0` (path dep) · `sha2` `0.10.9` (matches hark + `cbcl-mls-wasm`) |
| `fixtures/mls_ds_canonical_vectors.txt` | sha256 `3dc436eafd479c884395cce91aeeda0a9fe790274562cf2f0a1a579ac2f00dd2` (verbatim from cbcl-bus `apps/cbcl_chat/priv/web/`) |
| `fixtures/mls-ds-v1.cbcl` | sha256 `f668451b75215e2bf5b100219cb73aeaf674f975a5238f1da7751778c0b18bf2` (verbatim from cbcl-bus `apps/cbcl_chat/priv/dialects-v1/`) |

The expected bytes are **read from the authority file**, never hand-transcribed; only each
vector's *input* `SExpr` is reconstructed in the test. A wrong reconstruction fails the
byte-identity assertion loudly (it cannot silently pass).

## Findings

| # | Check | Observed | Consequence |
|---|---|---|---|
| 1 | `canonical_encode` over the 21 byte-authority vectors ([[SPEC-024-mls-delivery-service#CON-002]]) | **21/21 byte-identical.** All atom kinds (Symbol/Str/Keyword/Num incl. `i64::MIN`/`MAX`, Bool), UTF-8 (`café-日本`), empty string, nested lists, the record-signature / 9-tuple add-authorization / successor-offer shapes — every one MATCH. | hark's linked encoder reproduces the SPEC-024 canonical bytes **exactly**. The CON-002 foundation holds under hark's real dependency graph. This is the NFR-006 floor — confirmed. |
| 2 | `mls-ds/v1` `Dialect::hash` == `sha256:922ba8…261858` ([[SPEC-024-mls-delivery-service#CON-002]]) | **BLOCKED on cbcl-rs `main`:** `parse_dialect` rejects the dialect with `unknown keyword clause: :roles`. The DS dialect's `(:roles (client ds))` clause is not in main's grammar. | **Direct, independent evidence the integration gate is CLOSED** ([[IMPL-025-hark-mls-ds-client#2. Entry gates]]): cbcl-rs main cannot even *parse* the SPEC-024 dialect, let alone expose the role verifier / 40-performative typed decoder. The `922ba8` assertion is wired and activates automatically once the **production** cbcl-rs is pinned (H1 / [[IMPL-024-mls-delivery-service#ADR-021]]). |

Two independent lines therefore agree that H1–H10 are not yet startable: the role verifier
functions are absent from `main` (`grep` → 0), **and** the dialect grammar itself is absent
(finding 2). Only this spike was startable, and it is done.

## What this spike establishes / does NOT establish

**Establishes:** the CON-002 canonical-encoding parity floor for hark (finding 1), and a
concrete gate-state datum (finding 2) for the [[IMPL-025-hark-mls-ds-client#12. AI trust record and synthesis trajectory|validation record]].

**Does NOT establish (carry forward — all gated):**
- Role-runtime binding — the verifier, recogniser, typed tuple constructors ([[IMPL-025-hark-mls-ds-client#ADR-031]], H1).
- The corrected `DomainTuple` preimages ([[IMPL-025-hark-mls-ds-client#ADR-032]]) — the JS
  proofs' preimages are non-canonical; signing/hashing parity is unproven until the upstream
  reconciliation lands and its vectors regenerate.
- Any client reducer / genesis / closure / attestation verdict (H4/H8/H9/H10).
- The `mls-ds/v1` dialect hash itself (finding 2), pending the production pin.

## Next step

Feed finding 2 into [[IMPL-025-hark-mls-ds-client#2. Entry gates]] as observed
confirmation that the integration gate is closed, and hold all H1+ work until the production
cbcl-rs role artifact is pinned per [[IMPL-024-mls-delivery-service#ADR-021]]. When it is,
re-run this spike unchanged: finding 1 must stay 21/21, and finding 2's `922ba8` assertion
must go green — that pairing is the H1 acceptance signal ([[SPEC-024-mls-delivery-service#TEST-018]]).
