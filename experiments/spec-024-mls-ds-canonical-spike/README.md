# SPEC-024 / IMPL-025 §2 — canonical-vector proof-of-fit spike

**Status:** complete — **2/2 green against the epp role-layer cbcl-rs.**
**Gate-permitted:** the *one* work item [[IMPL-025-hark-mls-ds-client#2. Entry gates]]
permits while [[SPEC-024-mls-delivery-service|SPEC-024]] is `draft`. Isolated crate (own
empty `[workspace]`), detached from hark's build, touches **no** production code. Mirrors
`experiments/spec-013-mls-spike`'s isolation discipline.

**Scope guard (read first):** this proves the [[SPEC-024-mls-delivery-service#CON-002]]
byte + dialect foundation **only**. It is **not** the full role-runtime binding
([[IMPL-025-hark-mls-ds-client#ADR-031]] / H1): the mls-ds *verifier* and closed-world
*recogniser* are a further layer (see topology below).

## Purpose

Confirm hark, linking the production `cbcl-core` encoder through a path dependency, computes
**byte-identical** canonical bytes and the **canonical `mls-ds/v1` dialect hash** to the
SPEC-024 reference — the [[SPEC-024-mls-delivery-service#CON-002]] premise
[[IMPL-025-hark-mls-ds-client#NFR-006]] parity rests on. A one-byte disagreement forks the log.

## cbcl-rs branch topology (the load-bearing correction)

The role layer is **not on `main`** — it is on `epp-correspondence-proof`. Building against
`main` is why an earlier run saw `:roles` rejected and no verifier.

| Branch | Carries | This spike |
|---|---|---|
| `main` (`1c6fa8f`) | base runtime, **no** role layer | ✗ dialect hash blocked (`parse_dialect` rejects `:roles`) |
| **`epp-correspondence-proof` (`febc669`)** | SPEC-014 generic role layer (`role.rs`, `:roles` dialect parse REQ-600/621, canonical `922ba8`) | **✓ 2/2 green** — the substrate this spike now links |
| `fix/mls-ds-quoted-hash-depth` (`epp`+5) | the mls-ds-specific `mls_ds.rs` (verifier / recogniser / vector generator / NIF vectors) | not linked — IMPL-025 §2 flags it non-production |

`febc669` is the base IMPL-024 W1 built on. This crate links `epp` via a sibling
`../../../cbcl-rs-epp` worktree; when `epp` is pinned per
[[IMPL-024-mls-delivery-service#ADR-021]] (or checked out as `../cbcl-rs`), the dep normalises.

## Run

```
cargo test --manifest-path experiments/spec-024-mls-ds-canonical-spike/Cargo.toml -- --nocapture
```

Every check prints a `[CON-002 …]` line — the stdout **is** the evidence. `2 passed`.

## Provenance (what was tested, exactly)

| Input | Value |
|---|---|
| cbcl-rs commit linked | **`febc669`** (`epp-correspondence-proof`) — the SPEC-014 role layer |
| `cbcl-core` / `cbcl-parser` | path dep into the `epp` worktree · `sha2` `0.10` (matches hark + `cbcl-mls-wasm`) |
| `fixtures/mls_ds_canonical_vectors.txt` | sha256 `3dc436eafd479c884395cce91aeeda0a9fe790274562cf2f0a1a579ac2f00dd2` (verbatim from cbcl-bus `apps/cbcl_chat/priv/web/`) |
| `fixtures/mls-ds-v1.cbcl` | sha256 `f668451b75215e2bf5b100219cb73aeaf674f975a5238f1da7751778c0b18bf2` (verbatim from cbcl-bus `apps/cbcl_chat/priv/dialects-v1/`) |

Expected bytes are **read from the authority file**, never hand-transcribed; only each
vector's *input* `SExpr` is reconstructed in the test. A wrong reconstruction fails loudly.

## Findings

| # | Check | Observed | Consequence |
|---|---|---|---|
| 1 | `canonical_encode` over the 21 byte-authority vectors ([[SPEC-024-mls-delivery-service#CON-002]]) | **21/21 byte-identical** (all atom kinds incl. `i64::MIN`/`MAX`, UTF-8 `café-日本`, empty string, nested record-sig / 9-tuple add-auth / successor-offer shapes). | hark's linked encoder reproduces the SPEC-024 canonical bytes exactly. The NFR-006 floor holds. |
| 2 | `mls-ds/v1` `Dialect::hash` == `sha256:922ba8…261858` ([[SPEC-024-mls-delivery-service#CON-002]]) | **GREEN against `epp`:** `parse_dialect` accepts the full dialect (incl. `(:roles (client ds))`), and `dialect_canonical_bytes` + SHA-256 reproduce `922ba8…261858` exactly. | The dialect-hash half is proven against the role-layer substrate. (Against `main` this is blocked — that was a wrong-branch artifact, not a real divergence.) |

## What this spike establishes / does NOT establish

**Establishes:** the CON-002 canonical-encoding **and** dialect-hash parity floor for hark,
against the `epp` role-layer cbcl-rs.

**Does NOT establish (next, H1+):**
- The full role-runtime binding — the mls-ds *verifier* (`verify_mls_ds_request/response`),
  the closed-world ingress + attestation *recognisers*, and native/WASM/NIF parity live in
  `mls_ds.rs` on `fix/mls-ds-quoted-hash-depth` (`epp`+5), which IMPL-025 §2 flags as a
  non-production proof module. Binding those is H1 and needs the production-pin decision
  ([[IMPL-024-mls-delivery-service#ADR-021]]).
- The corrected `DomainTuple` preimages ([[IMPL-025-hark-mls-ds-client#ADR-032]]) for signing.
- Any client reducer / genesis / closure / attestation verdict (H4/H8/H9/H10).

## Next step

Bind H1 against `epp`'s role layer (`role.rs` primitives + `:roles` projection + the `922ba8`
dialect) and resolve which artifact supplies the production mls-ds verifier/recogniser
([[IMPL-024-mls-delivery-service#ADR-021]]). Re-run this spike unchanged as the H1 canonical
+ dialect regression signal ([[SPEC-024-mls-delivery-service#TEST-018]]).
