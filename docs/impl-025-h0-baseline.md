# IMPL-025 H0 — freeze & baseline

Records the hark baseline IMPL-025 departs from, and enumerates the SPEC-013 wire surface to
retire. Dated 2026-07-23. This is the H0 work package; it captures the frozen starting point
and does **not** add the production cbcl-rs role dep (that is gated on the ADR-021 pin — see
the note below).

## Baseline revision

| | |
|---|---|
| Branch | `feat/auto-reconnect` |
| Commit | `b70dee5f55bfbca85d9509e3ec8fbe6440ded3c9` |
| Toolchain | `rustc 1.95.0` · `cargo 1.95.0` · `openmls =0.8.1` (pinned, wire-parity with `cbcl-mls-wasm`) |

## Test inventory (frozen)

- **14 integration test targets** under `tests/`: `agent_workflow_cli`, `chat_live`,
  `chat_responder_live`, `daemon_lifecycle`, `discovery`, `e2e_mvp`, `join_cli`, `local_api`,
  `mls_private_channel`, `pairing_client`, `pairing_vectors`, `r5_runtime`,
  `router_integration`, `signed_handshake_live`.
- **336** `#[test]` / `#[tokio::test]` functions across `src/` + `tests/`.

Note: several targets (`*_live`, `daemon_lifecycle`, `e2e_mvp`) drive a real daemon/socket, so
a clean-room full green count is an integration-harness run, not a unit pass. The last recorded
green interop figure for this line is 324 (SPEC-013 v0.10.0 interop work). The inventory + the
pinned `openmls 0.8.1` build are the baseline anchor; the exact green count is re-measured under
the H0 harness when the successor work begins.

## SPEC-013 wire surface to retire (IMPL-025 §3 "Discard")

| Surface | Where | Retires to |
|---|---|---|
| Push `deliver` / `welcome` as the **primary** ingestion path | `src/mls/session.rs` (36 `deliver`/`welcome` sites) | the ADR-035 reducer-driven **pull loop** (one outstanding `next-record`) |
| Inbound decoder that **discards the 64-byte outer signature** | `src/chat_frame.rs` (`SIG_LEN = 64`; the agent does not verify inbound sigs) | the CON-012 typed **receive-frame** that retains + verifies the outer sig under the pinned DS key |
| The unverified-inbound-trust `/chat/v1` read path | receive sites in `src/chat.rs` | every DS response **verified** under the pinned DS key (CON-003) |
| Any bespoke / would-be MLS-control parser | — | the shared closed-world **recogniser** (CON-011, one parser per language) |
| The SPEC-013 v0.10.0 owner-departure carve-out | `src/mls/group.rs`, `src/validation.rs` | successor-room CON-010 turnover — but **only** at the post-H10 retirement gate (ADR-034), never in-place |

## Gate note — production cbcl-rs dep deferred

H0 explicitly does **not** point hark at the role-layer cbcl-rs yet. The substrate exists — the
SPEC-014 role layer on `epp-correspondence-proof` (`febc669`) and the corrected `DomainTuple`
crypto on `fix/mls-ds-quoted-hash-depth` (`fd8f034`, `epp`+5, feature `mls-ds-proof`) — and the
pre-pin proof suite in `experiments/spec-024-mls-ds-canonical-spike/` already validates canonical
bytes (21/21), the H1 role projection (R6-clean), and the H3 crypto-admission (domain separation)
against it. But it is a **proof artifact**: the mls-ds recogniser is still a subset (`Other`
shells). Per ADR-031, hark must consume a single **production** role artifact — full
40-performative typed decode, no `Other` shell — pinned per IMPL-024 ADR-021, before the
production `[dependencies]` change lands. Until then the binding lives only in the isolated,
feature-gated experiment.
