---
id: SPEC-028
title: Daemon Receive-Loop Liveness
status: implementing
tier: 2
version: 0.1.0
audience: agent, human
last-updated: 2026-08-16
owner-repo: hark
depends-on: SPEC-026 transport resilience; SPEC-024 MLS delivery service
intent-source: anuna-research/hark#43
---

# SPEC-028 — Daemon Receive-Loop Liveness

## Orientation

Intent: The daemon must sleep while an optional input is absent. A closed optional input must not turn idle time into a host-wide CPU spin.

Metaphor: An unplugged doorbell is removed from the attendant's desk. The attendant waits for the remaining bells instead of checking the empty socket forever.

Structure:

```text
optional DS sender ──close──▶ CON-001 receive helper ──disabled──▶ chat receive loop
                                      │                              │
                                      └────TEST-001 / TEST-002────────┘
```

Decisions: [[SPEC-028-daemon-receive-loop-liveness#ADR-001]] retains buffered applies after a sender closes.

Load-bearing: [[SPEC-028-daemon-receive-loop-liveness#REQ-001]] disables the closed branch · [[SPEC-028-daemon-receive-loop-liveness#REQ-002]] forbids repeat polling · [[SPEC-028-daemon-receive-loop-liveness#REQ-003]] preserves active delivery.

Controls: [[SPEC-028-daemon-receive-loop-liveness#REQ-002]] The receive loop SHALL NOT poll a closed optional input after it observes closure.

Open: No open product decision. Tier-2 review remains required before the specification reaches `implemented`.

Detail: [[SPEC-028-daemon-receive-loop-liveness#BUG-001]] · [[SPEC-028-daemon-receive-loop-liveness#CON-001]] · [[SPEC-028-daemon-receive-loop-liveness#TEST-001]] · [[IMPL-028-daemon-receive-loop-liveness]].

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

## Amendment Channels

Amendable by: Hark maintainers.

Through: A merged revision of this specification that cites the acceptance evidence.

Not amendable by: Issue comments, chat messages, prompts, or source code.

Hard stops: [[SPEC-028-daemon-receive-loop-liveness#REQ-002]] cannot be waived in flight.

## 1. Failure mode

An ordinary room has no [[SPEC-024-mls-ds-v1|MLS delivery-service]] pull task. The sender for its optional apply channel drops during setup.

The runtime's `select!` branch polls that closed channel. Each poll returns `None` immediately.

The branch continues the receive loop. It remains ready and prevents the worker from parking.

Issue #43 observed one spinning worker for each host core. The daemon emitted no log records after startup.

## 2. Defect record

### BUG-001 — A closed optional DS channel spins the daemon

**Severity:** S2 · **Priority:** P1 · **Status:** confirmed · **Reported by:** hugo in `anuna-research/hark#43` · **Assigned to:** this specification.

**Specification reference.** [[SPEC-026-transport-resilience#REQ-001]] governs transport ends. It does not govern an optional local input that closes before the receive loop begins.

**Root cause.** *Category:* `spec-gap` with an `implementation-error` surface. The `ds_rx.recv()` branch in `src/chat.rs` remains selectable after its only sender drops.

**Expected behaviour.** The receive loop removes a closed optional input. It then waits for a socket frame, outbound frame, close signal, timer, or active delivery-service apply.

**Actual behaviour.** The closed branch returns `None` indefinitely. The task re-enters `select!` without an await point.

**Resolution.** [[SPEC-028-daemon-receive-loop-liveness#REQ-001]] through [[SPEC-028-daemon-receive-loop-liveness#REQ-003]], verified by [[SPEC-028-daemon-receive-loop-liveness#TEST-001]] through [[SPEC-028-daemon-receive-loop-liveness#TEST-003]].

## 3. Requirements

### REQ-001 — Disable a closed optional input

When an optional delivery-service apply channel returns closure, the receive loop SHALL remove that channel before its next `select!` iteration.

Trace:

- [[SPEC-028-daemon-receive-loop-liveness#CON-001]]
- [[SPEC-028-daemon-receive-loop-liveness#TEST-001]]
- [[SPEC-028-daemon-receive-loop-liveness#OBS-001]]

### REQ-002 — Do not re-poll a closed optional input

The receive loop SHALL NOT poll an optional delivery-service apply channel after it observes that channel closed.

Trace:

- [[SPEC-028-daemon-receive-loop-liveness#CON-001]]
- [[SPEC-028-daemon-receive-loop-liveness#TEST-002]]
- [[SPEC-028-daemon-receive-loop-liveness#OBS-001]]

### REQ-003 — Preserve active delivery-service applies

When an optional delivery-service apply channel remains open, the receive loop SHALL process each received apply through its existing delivery-service path.

Trace:

- [[SPEC-028-daemon-receive-loop-liveness#CON-001]]
- [[SPEC-028-daemon-receive-loop-liveness#TEST-003]]
- [[SPEC-028-daemon-receive-loop-liveness#OBS-001]]

## 4. Contract

### CON-001 — Optional apply receiver

**Interface:** `next_optional_apply<T>(&mut Option<Receiver<T>>) -> Future<Option<T>>`.

**Pre-conditions:** The receiver is owned only by the chat receive loop. A `Some` receiver follows the existing delivery-service apply contract.

**Post-conditions:** An open receiver yields its next apply. A closed receiver yields `None` once and becomes absent. An absent receiver returns no value until cancellation.

**Error model:** Channel closure is a normal lifecycle transition. It emits one debug observation and does not fail the agent.

**Input grammar:** Not applicable. This contract accepts an internal typed value, not external input.

Implements:

- [[SPEC-028-daemon-receive-loop-liveness#REQ-001]]
- [[SPEC-028-daemon-receive-loop-liveness#REQ-002]]
- [[SPEC-028-daemon-receive-loop-liveness#REQ-003]]

Verified by:

- [[SPEC-028-daemon-receive-loop-liveness#TEST-001]]
- [[SPEC-028-daemon-receive-loop-liveness#TEST-002]]
- [[SPEC-028-daemon-receive-loop-liveness#TEST-003]]

## 5. Decision

### ADR-001 — Represent lifecycle with `Option<Receiver>`

**Status:** accepted.

**Context.** A boolean guard based on `Receiver::is_closed()` suppresses a closed receiver immediately. It can discard applies buffered before sender closure.

**Decision.** The receive loop owns `Option<Receiver>`. It consumes buffered applies. It changes `Some` to `None` only after `recv()` returns closure.

**Consequences.** The code adds one small helper. The helper makes the disabled branch pending, while retaining valid buffered work.

**Simplicity Ladder.** Rung 5. Existing channel semantics require a state transition. A new abstraction is unnecessary.

Trace: [[SPEC-028-daemon-receive-loop-liveness#CON-001]] · [[SPEC-028-daemon-receive-loop-liveness#TEST-003]].

## 6. Test specification

### TEST-001 — Closed receiver becomes absent

**Validates:** [[SPEC-028-daemon-receive-loop-liveness#REQ-001]].

**Type:** Positive lifecycle test.

**Scenario:** Create an apply channel, drop its sender, and await the helper. The helper returns closure and changes the receiver state to absent.

### TEST-002 — Disabled receiver remains pending

**Validates:** [[SPEC-028-daemon-receive-loop-liveness#REQ-002]].

**Type:** Prohibited-action test.

**Scenario:** After [[SPEC-028-daemon-receive-loop-liveness#TEST-001]], await the helper under a bounded test timeout. The timeout expires because the helper does not poll a closed channel again.

### TEST-003 — Buffered applies survive sender closure

**Validates:** [[SPEC-028-daemon-receive-loop-liveness#REQ-003]].

**Type:** Positive and negative-output test.

**Scenario:** Send one valid apply, then drop the sender. The helper yields that apply before it reports closure. The receiver becomes absent only after the buffered apply drains.

## 7. Observability

### OBS-001 — Optional apply channel closure

The daemon emits one `debug` record when it disables a closed optional delivery-service apply channel.

Trace: [[SPEC-028-daemon-receive-loop-liveness#REQ-001]] · [[SPEC-028-daemon-receive-loop-liveness#REQ-002]] · [[SPEC-028-daemon-receive-loop-liveness#REQ-003]].

## 8. Enable path

The change activates in the release containing this specification. No runtime flag is required because the previous behaviour consumes host CPU without operator control.

Rollback selects the previous immutable release. The release note identifies the closed optional receiver fix before deployment.

## 9. Reading paths

**Reviewer:** [[SPEC-028-daemon-receive-loop-liveness#ADR-001]] → [[SPEC-028-daemon-receive-loop-liveness#BUG-001]].

**Implementer:** [[SPEC-028-daemon-receive-loop-liveness#CON-001]] → [[SPEC-028-daemon-receive-loop-liveness#TEST-001]] → [[SPEC-028-daemon-receive-loop-liveness#REQ-001]].

**Stakeholder:** [[SPEC-028-daemon-receive-loop-liveness#BUG-001]] → [[SPEC-028-daemon-receive-loop-liveness#REQ-002]] → [[SPEC-028-daemon-receive-loop-liveness#OBS-001]].

## 10. Gate status

**Tier:** 2. The liveness fix protects the host-wide daemon runtime. It does not change a trust boundary.

**Synthesis trajectory:** The issue's stack sample identified Tokio workers. Code inspection found the ready-on-close `ds_rx.recv()` branch. The red test will reproduce the repeated-ready state before the repair.

**Review:** A fresh-context adversarial review found no correctness blocker. Cross-model and human maintainer reviews remain required before status changes to `implemented`.

## Changelog

<details>
<summary>Revision history — 0.1.0</summary>

- 0.1.0 — Initial specification from `anuna-research/hark#43`.
</details>
