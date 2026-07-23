# SPEC-024 / IMPL-025 — pre-pin validation suite (canonical · H1 role · H3 crypto)

**Status:** complete — **10/10 green** against the mls-ds substrate (`epp` + 5).
**Gate-permitted:** grew from the [[IMPL-025-hark-mls-ds-client#2. Entry gates]] proof-gate
spike. Isolated crate (own empty `[workspace]`), detached from hark's build, touches **no**
production code. Mirrors `experiments/spec-013-mls-spike`'s discipline.

**Scope guard:** this validates the CON-002 byte + dialect foundation, the H1 role
projection, and the H3 crypto-admission (domain separation) — all by **consuming** the
cbcl-rs primitives ([[IMPL-025-hark-mls-ds-client#ADR-031]]), never porting. It does **not**
consume the mls-ds *recogniser* (still a subset — see below), and it is **pre-pin**: the
substrate is a proof artifact, not the ADR-021 production pin.

## cbcl-rs branch topology (the load-bearing correction)

The role layer is **not on `main`** — building there is why an earlier run saw `:roles`
rejected and no verifier.

| Branch | Carries | Used here |
|---|---|---|
| `main` (`1c6fa8f`) | base runtime, **no** role layer | ✗ (dialect hash blocks, `:roles` rejected) |
| `epp-correspondence-proof` (`febc669`) | SPEC-014 generic role layer (`role.rs`, `:roles`, R6 verifier, canonical `922ba8`) | canonical + H1 come from here |
| **`fix/mls-ds-quoted-hash-depth` (`fd8f034`, `epp`+5)** | `mls_ds.rs`: the **corrected `DomainTuple`** (all 15 CON-002 tuples), strict Ed25519 (REQ-141), proven native↔NIF↔wasm32 (`df90533`) — behind the `mls-ds-proof` feature | **the substrate this crate links** (superset of `epp`) |

The `DomainTuple` inventory carries the *corrected* tags [[IMPL-025-hark-mls-ds-client#ADR-032]]
demanded — `AddAuth → "mls-add-authorization-v1"` **with `room`** (not the JS proof's
`mls-ds-add-auth-v1`), `Record → "mls-ds-record-signature-v1"` wrapper, `Source`, the three
genesis sigs, and the full successor-closure family. **The one remaining non-production piece
is the recogniser** (a subset with `Other` shells) — H1's `verify_mls_ds_request` / closed-world
ingress binding awaits the ADR-021 production pin.

## Run

```
cargo test --manifest-path experiments/spec-024-mls-ds-canonical-spike/Cargo.toml -- --nocapture
```

Every check prints a `[CON-002 …]` / `[H1 role]` / `[H3 crypto]` line — the stdout **is** the
evidence. `10 passed`.

## Provenance

| Input | Value |
|---|---|
| cbcl-rs commit linked | **`fd8f034`** (`fix/mls-ds-quoted-hash-depth` = `epp febc669` + 5), feature `mls-ds-proof` |
| `sha2` | `0.10` (matches hark + `cbcl-mls-wasm`) · Ed25519 via `ed25519-dalek` v2 (the pinned strict profile) |
| `fixtures/mls_ds_canonical_vectors.txt` | sha256 `3dc436eafd479c884395cce91aeeda0a9fe790274562cf2f0a1a579ac2f00dd2` (verbatim, cbcl-bus `priv/web/`) |
| `fixtures/mls-ds-v1.cbcl` | sha256 `f668451b75215e2bf5b100219cb73aeaf674f975a5238f1da7751778c0b18bf2` (verbatim, cbcl-bus `priv/dialects-v1/`) |

Expected bytes are **read from the authority file**, never hand-transcribed; only inputs are
reconstructed, so a wrong reconstruction fails loudly.

## Findings

| Layer | Check | Observed | Realises |
|---|---|---|---|
| CON-002 byte | `canonical_encode` over the 21 authority vectors | **21/21 byte-identical** | [[SPEC-024-mls-delivery-service#CON-002]] / NFR-006 floor |
| CON-002 dialect | `mls-ds/v1` `Dialect::hash` | **`sha256:922ba8…261858` = expected** (parse accepts `(:roles (client ds))`) | [[SPEC-024-mls-delivery-service#TEST-018]] |
| H1 role | `r6_violations(mls-ds/v1)`; role/performative projection | **`[]`** (R6 verifier accepts); roles `{client:Singleton, ds:Singleton}`; **40 performatives = 15 client→ds + 25 ds→client**; envelope routes total+deterministic | [[SPEC-024-mls-delivery-service#CON-003]] (role verifier, consumed) |
| H3 crypto | `DomainTuple` sign/verify; domain separation; Ed25519 strict | valid sig verifies under `mls-add-authorization-v1`; **domain-transplant to 4 foreign tags all rejected**; field mutation rejected; foreign-key rejected; non-canonical scalar rejected | [[SPEC-024-mls-delivery-service#TEST-024]] oracle 2 core · [[IMPL-025-hark-mls-ds-client#ADR-032]] domain separation · REQ-141 |

## What this establishes / does NOT establish

**Establishes (verified, pre-pin):** CON-002 byte + dialect parity; the H1 role projection
under the SPEC-014 R6 verifier; and the H3 crypto-admission **domain-separation** property
over the corrected `DomainTuple` — the ADR-032 risk that a divergent preimage silently forks.

**Does NOT establish (next):**
- The mls-ds **recogniser** binding (`verify_mls_ds_request` / closed-world ingress) — the
  DS-branch recogniser is still a subset (`Other` shells); this is the ADR-021 production-pin
  gap, the one genuinely non-production piece.
- H2 read-frame (CON-012), H4 reducer / genesis / closure / attestation (H4/H8/H9/H10),
  H5 durable store (CON-013), H6 pull loop, and the TEST-025 two-machine interop.
- The full TEST-024 crypto-admission corpus (every one of the 15 tuples + all mutants) — this
  proves the pattern on `AddAuth`; the exhaustive per-tuple sweep is the `task-parity-harness` job.

## Next step

Bind the production recogniser once pinned ([[IMPL-024-mls-delivery-service#ADR-021]]), then
proceed H2→H10. Re-run this suite unchanged as the canonical + role + crypto regression signal.
