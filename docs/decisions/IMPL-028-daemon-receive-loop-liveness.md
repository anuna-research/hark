---
id: IMPL-028
title: Daemon Receive-Loop Liveness Implementation
status: implementing
spec: SPEC-028
last-updated: 2026-08-16
---

# IMPL-028 — Daemon Receive-Loop Liveness Implementation

## Orientation

Intent: Convert a permanently ready closed channel into a disabled receive-loop branch without losing buffered delivery-service applies.

Structure:

```text
Receiver<DsApply> ──closed──▶ Option<Receiver<DsApply>> ──None──▶ pending branch
       │                              │                              │
       └──── buffered apply ──────────┴────TEST-003────────────────────┘
```

Decisions: [[SPEC-028-daemon-receive-loop-liveness#ADR-001]] uses `Option` after closure, not `is_closed()` before receive.

Load-bearing: [[SPEC-028-daemon-receive-loop-liveness#REQ-001]] · [[SPEC-028-daemon-receive-loop-liveness#REQ-002]] · [[SPEC-028-daemon-receive-loop-liveness#REQ-003]].

Controls: [[SPEC-028-daemon-receive-loop-liveness#REQ-002]] forbids repeat polling after closure.

Open: Cross-model and human maintainer Tier-2 reviews remain outstanding.

Detail: [[SPEC-028-daemon-receive-loop-liveness]] · [[SPEC-028-daemon-receive-loop-liveness#CON-001]] · [[SPEC-028-daemon-receive-loop-liveness#TEST-001]].

## Planning ledger

| Task | Governing source | Acceptance evidence | Dependency | Placement |
|---|---|---|---|---|
| `closed-ds-input` | [[SPEC-028-daemon-receive-loop-liveness#REQ-001]] | [[SPEC-028-daemon-receive-loop-liveness#TEST-001]] and [[SPEC-028-daemon-receive-loop-liveness#TEST-002]] pass | specification accepted | `src/chat.rs`; the receive loop owns the receiver |
| `buffered-ds-input` | [[SPEC-028-daemon-receive-loop-liveness#REQ-003]] | [[SPEC-028-daemon-receive-loop-liveness#TEST-003]] passes | `closed-ds-input` | `src/chat.rs`; the helper owns receiver lifecycle |
| `verify-receive-loop` | [[SPEC-028-daemon-receive-loop-liveness#TEST-001]] | targeted and workspace tests pass; closure mutation fails targeted test | `buffered-ds-input` | test runner only |

## Implementation sequence

1. Add a failing asynchronous test for a closed optional receiver.
2. Add the smallest helper that changes a closed receiver to `None`.
3. Route the receive-loop branch through that helper.
4. Add the buffered-apply test before treating channel closure as disabled.
5. Run the targeted test, the chat tests, formatting, and traceability checks.

## Purity Boundary Map

### Pure Core

- None. The helper awaits an asynchronous channel, so it is not deterministic computation.

### Effectful Shell

- `next_optional_apply`: awaits the in-process channel and disables it after closure.
- `spawn_receive_loop`: records the debug observation and applies delivery-service records through the existing session path.

### Boundary Contracts

- `Option<Receiver<DsApply>>`: channel lifecycle enters the helper.
- `Option<DsApply>`: one accepted apply or one closure event returns to the receive loop.

### Dependency Rule

The helper imports no session or transport code. The receive loop owns all application side effects.

## Simplicity record

The work stops at Simplicity Ladder rung 5. `Option` uses the standard library and the existing receiver.

The rejected `is_closed()` guard loses buffered applies after the sender drops.

## Verification strategy

The core suite contains [[SPEC-028-daemon-receive-loop-liveness#TEST-001]], [[SPEC-028-daemon-receive-loop-liveness#TEST-002]], and [[SPEC-028-daemon-receive-loop-liveness#TEST-003]].

Mutation changes the disabled branch to immediate `None`. [[SPEC-028-daemon-receive-loop-liveness#TEST-002]] must fail under that mutation.

No external-input grammar applies. The contract accepts a typed internal receiver.
