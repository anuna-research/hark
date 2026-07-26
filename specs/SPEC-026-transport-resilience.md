---
id: SPEC-026
title: Transport Resilience — Hub Reconnect and Durable Pairing
status: draft
tier: 2 (the re-join replays a signed-member handshake and re-arms an MLS session; the pairing store holds a channel capability)
version: 0.1.0
audience: agent, human
author: Anuna Research (drafted with Claude Opus 5)
last-updated: 2026-07-26
owner-repo: hark
affects-repos: none (cbcl-bus already carries the browser-side equivalent)
depends-on: SPEC-003 (chat transport), SPEC-013 (MLS private channels — the REQ-023 encryption pin), SPEC-016 (pairing), SPEC-024 (mls-ds/v1 pull loop, whose reconnect this mirrors)
traces-to: "[[#BUG-001]] (anuna-research/hark#25 — \"no reconnect: a hub redeploy permanently kills every paired agent\")"
note-on-numbering: SPEC-025 is deliberately not allocated. `IMPL-025` is already the
  implementation plan for [[SPEC-024-mls-ds-v1|SPEC-024]] (the IMPL sequence ran ahead of the
  SPEC sequence), so a `SPEC-025` would pair ambiguously with an `IMPL-025` that belongs to a
  different specification. This spec and its plan take the next number that pairs cleanly.
---

# SPEC-026 — Transport Resilience: Hub Reconnect and Durable Pairing

## Orientation

**Intent.** A hark agent must survive the hub going away and coming back. Today a single
ordinary redeploy of the hub permanently kills every paired agent: the transport loop marks
the handle unhealthy and exits, nothing ever reconnects it, and the only cure is a human
minting a fresh pairing code. This specification makes a hub restart a *blip* rather than a
*bereavement*.

**Metaphor.** *A phone call that survives walking through a tunnel.* The call does not end
because the signal dropped; the handset keeps trying, the other party's number is still in
the phone, and when coverage returns the same conversation resumes. What ends a call is the
other party hanging up on you — not the tunnel.

**Structure.**

```
  operator                 ┌──────────────────── hark daemon ────────────────────┐
      │                    │                                                     │
  hark emit ──────────────▶│  AgentStore ◀───── state ────── transport loop      │
  hark recv ──────────────▶│  (CON-003)                     (chat.rs, CON-001)   │
  hark daemon status ─────▶│      ▲                              │  ▲            │
                           │      │ reconnecting/connected       │  │ delay      │
                           │      │                              ▼  │            │
                           │  ┌───┴────────────┐        ┌────────────────────┐   │
                           │  │ PairingStore   │        │ ReconnectSchedule  │   │
                           │  │ (CON-002)      │        │ (pure — CON-004)   │   │
                           │  │ durable, 0600  │        └────────────────────┘   │
                           │  └────────────────┘                 │               │
                           └─────────────────────────────────────┼───────────────┘
                                                                 │ re-join
                                                                 ▼
                                                        ┌──────────────────┐
                                                        │  cbcl-bus hub    │
                                                        │  /chat/v1        │
                                                        └──────────────────┘
        arrows point inward → the pure schedule imports nothing (Purity Boundary Map)
```

**Decisions.** [[#ADR-001]] reconnect inside the transport loop, not a supervisor ·
[[#ADR-002]] mirror the browser's 1 s → 15 s jittered schedule · [[#ADR-003]] refuse outbound
during the gap rather than queue it · [[#ADR-004]] retry indefinitely; terminal only on active
rejection · [[#ADR-005]] the pairing record lives beside the signing keys · [[#ADR-006]] the
agent handle survives a daemon restart.

**Load-bearing.** [[#REQ-001]] reconnect on transport end · [[#REQ-004]] the handle stays
usable across the gap · [[#REQ-005]] what is still terminal · [[#REQ-007]] the pairing record
is durable · [[#NFR-001]] recovery latency.

**Open.** [[#OQ-001]] whether the [[MLS]] `keypub` republication on every re-join needs a
hub-side ceiling (owner: hark; deferred — see the question for why it is not blocking).

**Detail.** [[IMPL-026-transport-resilience]] is the execution plan; [[SPEC-003]] owns the
transport this extends; [[SPEC-013-mls-private-channels]] owns the encryption pin the re-join
must re-check.

---

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED,
MAY, and OPTIONAL in this document are to be interpreted as described in BCP 14
([RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119),
[RFC 8174](https://datatracker.ietf.org/doc/html/rfc8174)) when, and only when, they appear
in all capitals.

## 0. Defect record

### BUG-001 — A hub redeploy permanently kills every paired agent

**Severity:** S2 (core feature broken; the only workaround is a human minting a fresh pairing
code) · **Priority:** P1 · **Status:** confirmed · **Reported by:** elf-02
(`anuna-research/hark#25`) · **Assigned to:** this specification.

**Specification reference.** Violates no existing requirement — the transport specification
([[SPEC-003]]) is silent on what happens after a transport-level end. This is therefore a
**specification gap**, which is why the fix begins with requirements rather than a patch.
Related: no TEST existed that could have caught it, because no requirement described the
behaviour.

**Environment.** hark 0.1.5 against `wss://cbcl-bus.fly.dev/chat/v1`; an ordinary
single-instance hub redeploy; the hub itself healthy throughout (`https://chat.anuna.io/`
→ 200).

**Steps to reproduce.** (1) `hark pair <code>` into a channel; confirm `hark recv` receives.
(2) Redeploy the hub — a single-instance immediate deploy replaces the machine and drops every
socket at once. (3) Observe the agent go `unhealthy / hub_closed` and stay there. (4) `hark
recv` and `hark emit` both fail with `agent_handle_unhealthy`. No retry ever happens.

**Expected behaviour.** The hub's durable state survives the redeploy, so the membership is
still valid and the drop should be a brief interruption — the posture the browser client
already takes.

**Actual behaviour.**

```
agent_handle_unhealthy: agent handle is unhealthy: hub_closed
hint: IO error: peer closed connection without sending TLS close_notify

1K65XWE7NSPZMCVJFFAWS02SHR unhealthy router_agent_id=@anuna546 dialects=[] queued_messages=0
  unhealthy_reason=hub_closed
  unhealthy_detail=IO error: peer closed connection without sending TLS close_notify
```

**Root cause.** *Category:* `spec-gap` (with an `implementation-error` surface). `src/chat.rs`
`spawn_receive_loop` handles all three socket-end cases — `Close` frame, stream `None`, and
stream `Err` — by marking the handle unhealthy and `break`ing out of the loop; the task then
ends and nothing respawns it. The behaviour was never specified, so nothing flagged it.

**Resolution.** [[#REQ-001]] … [[#REQ-010]] below, verified by [[#TEST-001]] … [[#TEST-014]].
Regression test: [[#TEST-001b]] asserts the absence of the exact observed symptom.

## 1. Context

### 1.1 What happens today

`src/chat.rs` runs one task per agent. Every way its WebSocket can end — a `Close` frame, the
stream returning `None`, or an IO error — does the same two things: mark the handle
`unhealthy / hub_closed` and `break` out of the loop. The task then ends. Nothing respawns it.

```
agent_handle_unhealthy: agent handle is unhealthy: hub_closed
hint: IO error: peer closed connection without sending TLS close_notify
```

`reconnect`, `backoff`, `respawn`, and `supervis*` appear nowhere in `src/chat.rs` or
`src/daemon.rs`. The one retry concept that does exist — `OutboundReject::retryable` — covers
a rejected *outbound frame* (the [[SPEC-013-mls-private-channels#REQ-023]] membership-pending
case) and deliberately keeps the handle healthy. It does nothing for a dropped socket.

### 1.2 Why this is a defect and not a design choice

The hub is a **single instance with an immediate deploy strategy**. Every redeploy replaces
the machine and drops every socket at once. Its durable state is built to survive exactly
that — the control plane on Mnesia-on-`/data`, the [[SPEC-055 membership grant]]s included —
so a drop is *meant* to be a brief interruption of a still-valid membership, not the end of
one.

Two other clients of the same hub already treat it that way:

- The **browser client** was fixed for this and carries the rationale in-tree
  (`cbcl-bus` `apps/cbcl_chat/priv/web/chat-reconnect.mjs`): a pure `createBackoff({ minMs:
  1000, maxMs: 15000, jitter: 0.25 })`, a `scheduleReconnect()`, a `reconnectNow()` on
  `online`/`visibilitychange`, and a `restoreChannels()` on reopen.
- **hark's own [[SPEC-024-mls-ds-v1|mls-ds/v1]] pull loop** (`src/mls_ds/task.rs`) already
  reconnects on bounded exponential backoff, and its module doc even claims the chat socket
  does the same: *"the DS socket rides hub restarts with the same bounded backoff the chat
  socket uses."* That claim is currently false. This specification makes it true.

The chat transport is the one client of this hub that gives up.

### 1.3 The secondary gap: pairing is not durable

Agent records live only in daemon memory. The config file holds nothing but the hub URL, so
`hark daemon stop && hark daemon start` drops every agent (`agents: 0`) and re-pairing is
mandatory — even though the hub remembers the membership durably. Reconnect alone fixes the
redeploy case; a daemon restart, an OS reboot, or a `hark upgrade` still needs a human with a
fresh pairing code. Both halves are in scope here, because either alone leaves the recovery
story half-finished.

## 2. Scope

**In scope.** Reconnection of the `/chat/v1` transport after any transport-level end; the
re-join handshake replay (bootstrap, signed `hello`, acknowledgement, MLS key publication,
`announce`); handle usability across the gap; the observability of a reconnecting agent; a
durable per-agent pairing record and its rehydration on daemon start.

**Out of scope.** The router transport (`src/router.rs`) — it has the same shape but a
different handshake and no reported incident; changing the DS pull loop's existing schedule;
any change to what the hub does; the browser-side dead-socket bug noted in issue #25
(tracked separately in `cbcl-bus`).

## 3. Users and happy paths

**Profile — Agent Operator.** Runs one or more hark agents against a hosted hub they do not
control. Notices agent failures only when a task silently stops producing output, or when
`hark recv` starts erroring. Has no appetite for re-pairing an agent every time the hub ships.

### HP-1 — the hub redeploys under a running agent

| Step | Operator action | Expected system response |
|------|-----------------|--------------------------|
| 1 | `hark pair <code>`; `hark recv` is receiving | agent `connected` |
| 2 | (the hub is redeployed; every socket drops) | the agent's socket ends; the daemon logs the drop once and schedules a retry |
| 3 | `hark daemon status` during the gap | the agent shows `reconnecting`, with attempt count and last error |
| 4 | `hark emit "…"` during the gap | refused as *retryable* — "not ready yet", not "unhealthy" |
| 5 | (the hub comes back, ~5–30 s later) | the agent re-joins and resumes; `hark recv` receives again |
| 6 | `hark daemon status` after | the agent shows `connected`; no re-pairing was needed |

**Failure modes.** The hub comes back but *rejects* the re-join (the channel was deleted, the
capability was revoked) → terminal, and the operator is told which slug the hub returned. The
hub comes back with `:enc false` on a channel pinned encrypted → terminal, downgrade refused.
The hub never comes back → the agent stays `reconnecting` indefinitely, visibly.

### HP-2 — the daemon restarts

| Step | Operator action | Expected system response |
|------|-----------------|--------------------------|
| 1 | `hark daemon stop` | the daemon exits; the pairing records stay on disk |
| 2 | `hark daemon start` | every persisted agent is re-established, keeping its agent handle |
| 3 | `hark daemon status` | the same handles as before, `connected` |
| 4 | `hark close` on one agent | that agent's record is deleted; it does not return on the next start |

**Failure modes.** The hub is down when the daemon starts → the agent is created in the
`reconnecting` state and rides HP-1's schedule; the daemon still reports ready. The pairing
store is corrupt → the daemon starts with no persisted agents and surfaces the parse error;
it never guesses at a partial record.

## 4. Requirements

### REQ-001 — Reconnect on transport end

The system SHALL, when an agent's hub WebSocket ends at the transport level — a `Close`
frame, an exhausted stream, an IO error on the read side, **or a failed write** — re-establish
the connection on the [[#REQ-002]] schedule instead of terminating the session task, and SHALL
NOT transition the agent handle to `unhealthy` for that reason alone.

The write side is named explicitly because it is the same event seen from the other direction.
A hub redeploy drops the socket; whether the agent notices by failing to read or by failing to
write is a matter of timing. Fixing only the read side would leave the reported failure intact
for any agent that happened to be emitting when the machine went away — the transport loop's
four write sites (an operator's outbound frame, an MLS protocol frame, a responder claim, and
the announce inside the re-join itself) are all reachable at that moment. The outbound frame
that lost the race is refused *retryably* per [[#REQ-004]], not dropped and not marked fatal.

Trace: [[#TEST-001]], [[#TEST-015]], [[#CON-001]], [[#OBS-001]]

### REQ-002 — Bounded, jittered, resetting backoff

The reconnect schedule SHALL delay the first attempt by 1000 ms, SHALL double each subsequent
base delay to a ceiling of 15000 ms, SHALL reduce each delay by a uniformly random fraction of
up to 25 % of its base (jitter applied *downward*, so a delay never exceeds the ceiling), and
SHALL reset to the first delay once a connection is re-established.

The values mirror `createBackoff({ minMs: 1000, maxMs: 15000, jitter: 0.25 })` in the browser
client, deliberately — see [[#ADR-002]]. Downward jitter is load-bearing, not decorative:
every client of this hub is dropped by the same event and would otherwise return in lockstep
onto the single machine that just came up.

Trace: [[#TEST-002]], [[#CON-004]], [[#NFR-002]]

### REQ-003 — Full re-join on reconnect

On each reconnect attempt the system SHALL replay the complete signed-member join for the
agent's channel before resuming frame delivery: receive the conn-nonce bootstrap and derive a
fresh per-connection signer; send the Ed25519-signed `hello` carrying the agent's original
capability; block on the hub's acknowledgement; where the channel is encrypted, re-publish the
[[MLS]] `keypub` / `idkey` / `keyready` frames; and re-send the `announce`.

The system SHALL NOT create the MLS group on a reconnect, regardless of the `mls_create`
intent recorded at first join. Re-creating the group would fork it.

This is the equivalent of the browser's `restoreChannels()` on reopen: a reconnected socket
that skipped the handshake would be a member of nothing.

Trace: [[#TEST-003]], [[#TEST-007]], [[#CON-001]]

### REQ-004 — The handle stays usable across the gap

While a reconnect is in progress the agent handle SHALL remain usable:

- a pending or new `recv` SHALL continue to wait rather than error;
- an `emit` / `reply` SHALL be refused as **retryable** (`AgentError::NotReady`), never as
  `AgentError::Unhealthy`;
- the handle SHALL remain the session's active handle.

Trace: [[#TEST-004]], [[#CON-003]]

### REQ-005 — What remains terminal

The system SHALL transition the handle to `unhealthy` during reconnection only when:

(a) the hub **actively rejects** the re-join — it answers the `hello` with an
`(error @room "slug")` verdict (`forbidden-room`, `no-such-channel`, `bad-signature`, …); or

(b) the re-join would violate the [[SPEC-013-mls-private-channels#REQ-023]] encryption pin —
the hub answers with `:enc false` for a channel pinned encrypted.

An unreachable hub, a refused TCP connection, a TLS failure, a timed-out handshake, and a
closed socket are all **not** terminal.

Trace: [[#TEST-005]], [[#TEST-006]], [[#CON-001]]

### REQ-006 — A reconnecting agent is visible

`hark daemon status` and `GET /v1/agents` SHALL report an agent whose socket is down with the
state `reconnecting`, the count of consecutive failed attempts, and the last transport error.
The daemon SHALL log the transition to `reconnecting` once per outage at `warn`, and SHALL NOT
log once per attempt.

An agent silently retrying every 15 s with no operator-visible signal is undiagnosable; this
requirement is the [[Observability Requirement|observability]] floor for the feature and is
not simplifiable away.

Trace: [[#TEST-008]], [[#OBS-001]], [[#OBS-002]]

### REQ-007 — The pairing record is durable

On a successful chat join the system SHALL persist a record sufficient to re-establish that
agent without human interaction — its agent handle, wire handle, channel, advertised dialects,
capability, adder, and receive-all mode — to the chat identity directory, with owner-only
permissions (mode `0600` on Unix-like systems).

The record carries a channel capability, which is a bearer credential. It is stored in the
same directory, at the same trust level, and with the same permissions as the Ed25519 signing
keys that already live there ([[#ADR-005]]).

Trace: [[#TEST-009]], [[#CON-002]], [[#NFR-003]]

### REQ-008 — Persisted agents are re-established on start

On start the daemon SHALL re-establish every persisted agent, preserving each agent's original
agent handle, and SHALL report ready without waiting for those joins to succeed. An agent
whose hub is unreachable at start SHALL enter the [[#REQ-001]] reconnect schedule rather than
being dropped.

Preserving the handle is what makes an exported `CBCL_AGENT_HANDLE` survive a daemon restart
([[#ADR-006]]).

Trace: [[#TEST-010]], [[#TEST-011]], [[#CON-002]]

### REQ-009 — Closing an agent deletes its record

Closing an agent SHALL delete its pairing record, so that a deliberately closed agent does not
return on the next daemon start.

Trace: [[#TEST-012]], [[#CON-002]]

### REQ-010 — The pairing store is recognised before use

The pairing store SHALL be fully recognised against the [[#CON-002]] grammar before any record
in it is acted upon. A store that is absent, unreadable, not well-formed, of an unknown
version, or containing any record that fails the grammar SHALL yield **no** persisted agents
and SHALL surface a diagnostic naming the file and the parse failure. The system SHALL NOT
act on a partially-parsed store, repair a malformed record, or skip a bad record and use the
rest.

This is [[LangSec]] Principle 4 (be conservative in what you accept) at a trust boundary: the
store carries capabilities, and a permissively-parsed record is a record whose capability
field may not be the one that was written.

Trace: [[#TEST-013]], [[#CON-002]]

## 5. Non-functional requirements

### NFR-001 — Recovery latency

An agent SHALL be re-joined within **2.0 s** of the hub becoming able to accept the connection
again, measured from hub availability to a completed join acknowledgement, for the first drop
of an outage (the schedule at its 1000 ms minimum, plus jitter and one handshake round-trip).

At the schedule's ceiling the corresponding bound is **15.0 s** plus one handshake. The tighter
bound attaches to the dominant profile — an ordinary hub redeploy, where the machine is back
within one or two attempts.

Trace: [[#TEST-002]], [[#OBS-002]]

### NFR-002 — At most one attempt in flight

There SHALL be at most one connection attempt in flight per agent at any instant. A reconnect
already in progress SHALL NOT be superseded or duplicated by any other event.

Trace: [[#TEST-002]]

### NFR-003 — No unbounded buffering across the gap

Memory held on behalf of an agent SHALL NOT grow with outage duration. Outbound frames offered
during a gap are refused ([[#REQ-004]]), not accumulated; the existing per-handle inbound queue
bounds (`max_messages_per_handle`, `max_bytes_per_handle`) are unchanged.

Trace: [[#TEST-004]], [[#ADR-003]]

## 6. Architecture decisions

### ADR-001 — Reconnect inside the transport loop, not in a supervisor task

**Context.** Two shapes are available: a supervisor task that respawns the session on exit, or
a session that reconnects in place.

**Decision.** Reconnect in place, inside the existing `spawn_receive_loop`.

**Rationale.** The receive loop *owns* the `MlsSession`, the `Responder`, the `SignedConn`, the
outbound receiver, and the close signal. A supervisor would have to thread all of that out of
the task and back into its replacement, and the MLS session in particular is not trivially
movable across a respawn without risking a state fork. Reconnecting in place leaves the entire
ownership graph unchanged: only the socket and the per-connection signer are replaced. This is
also the shape already proven in-tree by `spawn_ds_pull_loop` (Simplicity Ladder rung 4 — reuse
the pattern that is already here). The issue's own suggested fix says the same: *"mirror the
web client's schedule in the transport loop rather than breaking out of it."*

**Consequences.** The reconnect path must keep servicing the close signal and the outbound
channel while it waits, or a `hark close` during a gap would hang for up to 15 s.

### ADR-002 — Mirror the browser's schedule, not the DS loop's

**Context.** Two schedules already exist against this hub: the browser's 1 s → 15 s with 25 %
downward jitter, and hark's own DS pull loop at 1 s → 30 s with no jitter.

**Decision.** The chat transport takes the browser's schedule.

**Rationale.** The chat socket and the browser socket are the *same conversation* seen from two
clients; an operator watching a channel in a browser and an agent in a terminal should see them
come back on the same envelope. The DS loop's looser cap is appropriate to *it* — its records
are immutable and its cursor is durable, so lag costs nothing but latency — and is left alone
rather than harmonised for the sake of symmetry. The jitter is the property the DS loop is
actually missing, and is the one that matters most here: every client is dropped by one event.

**Consequences.** Two schedules coexist in the codebase. The DS loop's module doc claim that it
uses "the same bounded backoff the chat socket uses" becomes true in kind (bounded exponential)
but not in constants; the doc is corrected to say so.

### ADR-003 — Refuse outbound during the gap; do not queue it

**Context.** [[#REQ-004]] requires the handle stay usable. Issue #25 offers two ways: queue
outbound frames, or surface a retryable refusal.

**Decision.** Refuse, as `OutboundReject::retryable`.

**Rationale.** Three reasons, in order of weight. (1) **Correctness**: in an encrypted channel
an outbound frame is sealed against the *current* MLS epoch. A frame queued before a gap and
flushed after it may be sealed against an epoch the group has left; refusing forces the caller
to re-offer the message, which re-seals it. (2) **Boundedness**: a queue needs a bound and an
overflow policy, both new surface, for a benefit the caller can get for free by retrying
([[#NFR-003]]). (3) **Reuse**: `OutboundReject::retryable` → `AgentError::NotReady` already
exists for exactly this shape of transient refusal (the SPEC-013 membership-pending case), and
callers already handle it (Simplicity Ladder rung 4).

**Consequences.** A caller that treats every non-`Ok` as fatal will still fail during a gap.
`AgentError::NotReady` is already documented as retryable, so this is a pre-existing contract
rather than a new one.

### ADR-004 — Retry indefinitely; terminal only on active rejection

**Context.** Issue #25 suggests marking the handle terminally unhealthy "when the schedule
exhausts or the hub actively rejects the agent."

**Decision.** The schedule never exhausts. The only terminal conditions are the two in
[[#REQ-005]]: an active rejection by the hub, or an encryption-pin violation.

**Rationale.** This is a deliberate deviation from the issue's suggested fix, and the reference
implementation supports it: the browser's `createBackoff` has no exhaustion condition either —
it backs off to a ceiling and stays there. An exhaustion bound would reintroduce exactly the
failure being fixed, only later: a hub down for longer than the bound would still leave a dead
agent needing a human. The legitimate concern behind "exhausts" is *visibility* — an operator
must not be left believing an agent is fine when it has been retrying for an hour — and that
concern is met head-on by [[#REQ-006]] (a distinct `reconnecting` state carrying attempt count
and last error) rather than by killing the agent. Bounding it would also be a policy choice
with no defensible default: minutes is wrong for a long-running production agent, hours is
wrong for an interactive session.

**Consequences.** A permanently-dead hub leaves an agent in `reconnecting` forever, consuming
one task and one connect attempt per 15 s. That is cheap and visible. If an operator later
wants a bound, it becomes a config knob with a named default — deliberately not added now
(Simplicity Ladder rung 1: no requirement asks for it).

### ADR-005 — The pairing record lives beside the signing keys

**Context.** The record must survive reboot and must be found by the daemon at start. Three
candidate homes: the runtime directory (`daemon.json`'s neighbour), a new state directory, or
the existing chat identity directory.

**Decision.** `<chat.identity_dir>/paired-agents.json`.

**Rationale.** The runtime directory is wrong: on Linux it is `$XDG_RUNTIME_DIR`, which is
wiped on reboot, and its contents are deliberately ephemeral session state. A new state
directory is a new path to document, create, permission, and test (rung 6) for no gain. The
chat identity directory is already the durable, owner-only home of exactly this class of
material — one Ed25519 seed per wire handle — is already configurable and already isolated
per-test via `CBCL_CHAT_IDENTITY_DIR`, and the pairing record's most sensitive field (the
channel capability) is of the same trust class as the seeds already there. Constitutional
Principle 15: the capability belongs where the things that need it already are.

**Consequences.** An operator who deletes `chat-keys/` to reset their identity also drops
their pairings — which is the correct coupling, since the keys are what the pairings
authenticate with.

### ADR-006 — The agent handle survives a daemon restart

**Context.** Agent handles are ULIDs generated at join. On rehydration a fresh handle could be
generated, or the recorded one reused.

**Decision.** Reuse the recorded handle.

**Rationale.** `CBCL_AGENT_HANDLE` is exported into operator shells and scripts. Regenerating
would silently break every one of them across a daemon restart, converting a fixed problem
into a subtler one. The handle is an opaque local identifier with no hub-side meaning, so
reuse costs nothing.

**Consequences.** `AgentHandle` needs a constructor from a validated stored string. The
existing serde `try_from(String)` path already performs that validation and is reused rather
than duplicated (one recogniser per language — [[LangSec]] Principle 5).

## 7. Contracts

### CON-001 — The (re-)join handshake

**Interface.** `join_hub(params, identity, mls, mls_create) -> Result<Joined, ChatError>` —
the single implementation of the signed-member join, called once by `create_chat_agent` at
first join and once per attempt by the reconnect path.

**Pre-conditions.**
- `params` carries a hub URL, channel, wire handle, advertised dialects, optional capability,
  and optional adder — the complete set needed to reproduce the original join. *(REQ-003)*
- `identity` is the same Ed25519 identity used at first join. *(REQ-003)*
- `mls_create` is `true` at most once per agent, at first join only. *(REQ-003)*

**Post-conditions.**
- On `Ok`, the hub has acknowledged the join, the returned socket is a joined member socket,
  and the returned `SignedConn` is primed from *this* connection's nonce. *(REQ-003)*
- On `Ok` for an encrypted channel, the MLS key publication frames have been sent. *(REQ-003)*
- On `Ok`, the `announce` has been sent. *(REQ-003)*
- On `Err(JoinRejected)`, the hub returned a verdict; the caller MUST treat it as terminal.
  *(REQ-005a)*
- On `Err(DowngradeRefused)`, the encryption pin was violated; the caller MUST treat it as
  terminal. *(REQ-005b)*
- On any other `Err`, the failure is transport-level; the caller MUST retry. *(REQ-005)*

**Error model.** `ChatError`, unchanged. The terminal/retryable partition above is the only new
obligation on it, and is carried by the existing variants rather than by a new one.

Implements: [[#REQ-003]], [[#REQ-005]] · Verified by: [[#TEST-003]], [[#TEST-005]],
[[#TEST-006]], [[#TEST-007]]

### CON-002 — The pairing store

**Interface.** A JSON document at `<chat.identity_dir>/paired-agents.json`, mode `0600`.

**Grammar** (the declared input language; recognition is total and precedes any use —
[[#REQ-010]]):

```abnf
store        = %s"{" version "," agents "}"      ; JSON object, exactly these two members
version      = %s"\"version\":" %s"1"            ; unknown version => reject the whole store
agents       = %s"\"agents\":" "[" [ record *( "," record ) ] "]"

record       = "{" agent-handle "," wire-handle "," channel "," dialects
                   "," receive-all [ "," cap ] [ "," added-by ] "}"

agent-handle = %s"\"agent_handle\":" json-string  ; MUST satisfy the AgentHandle recogniser
wire-handle  = %s"\"wire_handle\":"  json-string  ; MUST satisfy validate_chat_handle
channel      = %s"\"channel\":"      json-string  ; MUST satisfy validate_chat_handle
dialects     = %s"\"dialects\":" "[" [ json-string *( "," json-string ) ] "]"
                                                  ; each MUST satisfy validate_dialect_id
receive-all  = %s"\"receive_all\":" ( %s"true" / %s"false" )
cap          = %s"\"cap\":"      json-string
added-by     = %s"\"added_by\":" json-string      ; MUST satisfy validate_chat_handle
```

The field recognisers (`AgentHandle`, `validate_chat_handle`, `validate_dialect_id`) are the
*same* functions the live API uses on the request path — one recogniser per language
([[LangSec]] Principle 5), so a record that round-trips through the store is accepted on
exactly the same terms as one that arrived over the wire.

**Pre-conditions.**
- Writing: the join it describes succeeded. *(REQ-007)*
- Reading: none; absence is a valid state meaning "no persisted agents". *(REQ-010)*

**Post-conditions.**
- After a successful join, the store contains exactly one record for that agent handle, and
  the file's mode is `0600`. *(REQ-007)*
- After a close, the store contains no record for that agent handle. *(REQ-009)*
- `load()` returns either the complete, fully-recognised list of records, or an empty list
  plus a diagnostic. It never returns a partial list. *(REQ-010)*
- A record round-trips: `load(save(records)) == records`. *(REQ-007, REQ-008)*

**Error model.** Read failures and grammar failures are non-fatal to the daemon: they yield an
empty list and a `warn` diagnostic naming the path and the failure. Write failures are
non-fatal to the join: the agent is live either way, and the failure is surfaced as a warning
on the create response, so an operator learns the agent will not survive a restart.

Implements: [[#REQ-007]], [[#REQ-009]], [[#REQ-010]] · Verified by: [[#TEST-009]],
[[#TEST-012]], [[#TEST-013]]

### CON-003 — Agent state across a gap

**Interface.** `AgentState` gains a third value, `reconnecting`, between `connected` and
`unhealthy`.

**Pre-conditions.** A transition to `reconnecting` is made only by the transport loop, only
after a transport-level end, and only for an agent currently `connected`. *(REQ-001)*

**Post-conditions.**
- `reconnecting` is **healthy** for admission purposes: `recv` waits, `send_outbound` is
  admitted to the transport loop and refused there as retryable. *(REQ-004)*
- A successful re-join returns the state to `connected` and zeroes the attempt count.
  *(REQ-001)*
- A terminal condition ([[#REQ-005]]) transitions to `unhealthy` with a reason and detail, as
  today. *(REQ-005)*
- The snapshot exposes `reconnect_attempts` and `reconnect_detail` whenever the state is
  `reconnecting`. *(REQ-006)*

**Error model.** Unchanged. `AgentError::Unhealthy` continues to mean terminal;
`AgentError::NotReady` continues to mean retry.

Implements: [[#REQ-001]], [[#REQ-004]], [[#REQ-006]] · Verified by: [[#TEST-001]],
[[#TEST-004]], [[#TEST-008]]

### CON-004 — The reconnect schedule (pure)

**Interface.**

```rust
pub struct ReconnectSchedule { /* … */ }
impl ReconnectSchedule {
    pub fn new(min: Duration, max: Duration, jitter: f64) -> Self;
    pub fn default() -> Self;                 // 1 s, 15 s, 0.25
    pub fn next_delay(&mut self, random: f64) -> Duration;  // advances the schedule
    pub fn reset(&mut self);
    pub fn attempts(&self) -> u32;
    pub fn at_ceiling(&self) -> bool;
}
```

`random` is a caller-supplied value in `[0, 1)` so the spread is exact under test rather than
merely probable — the same injection the browser's `createBackoff` uses.

**Pre-conditions.** `random ∈ [0, 1)`; `min ≤ max`; `jitter ∈ [0, 1]`.

**Post-conditions.**
- The first `next_delay` after construction or `reset` has base `min`. *(REQ-002)*
- Each subsequent base is `min(previous × 2, max)`. *(REQ-002)*
- Every returned delay lies in `[base × (1 − jitter), base]`, hence in `[0, max]` — never
  above the ceiling, never negative. *(REQ-002)*
- `attempts()` counts calls to `next_delay` since construction or `reset`. *(REQ-006)*
- `at_ceiling()` is true exactly when the current base has reached `max`. *(REQ-006)*

**Error model.** Total: every input in the pre-condition domain yields a delay. There is no
failure case and no exhaustion ([[#ADR-004]]).

Implements: [[#REQ-002]] · Verified by: [[#TEST-002]]

## 8. Purity Boundary Map

### Pure core (no I/O, no shared state, deterministic)
- `ReconnectSchedule` ([[#CON-004]]): computes the next delay from the attempt count and an
  injected random value.
- The pairing-store recogniser ([[#CON-002]]): bytes → `Vec<PairingRecord>` or a parse error.

### Effectful shell (orchestrates I/O, calls the pure core)
- `join_hub` ([[#CON-001]]): the socket, the handshake, the frames.
- The reconnect arm of `spawn_receive_loop`: sleeps, retries, mutates store state.
- `PairingStore::{load, save, remove}`: the filesystem, permissions.
- The daemon-start rehydration pass: reads the store, drives `create_chat_agent`.

### Boundary contracts (data crossing the boundary)
- `Duration` — pure core → shell (how long to sleep).
- `PairingRecord` — shell → pure recogniser → shell (validated, typed; never raw JSON).
- `Joined { socket, conn, roomcfg }` — shell → shell.

### Dependency rule
Dependencies point inward: shell → core. `ReconnectSchedule` and the recogniser import nothing
from `chat`, `daemon`, or `local_api`.

### Enforcement
Code review plus the module's own test placement: the pure core's tests use no `tokio::spawn`,
no sockets, and no filesystem.

## 9. Observability

### OBS-001 — Reconnect transitions

A `warn`-level event on entering an outage, carrying the agent handle, channel, and the
transport error that ended the socket; an `info`-level event on recovery, carrying the handle,
channel, attempt count, and outage duration. Exactly one of each per outage — per-attempt
narration is `debug` only ([[#REQ-006]]).

Trace: [[#REQ-006]], [[#TEST-008]]

### OBS-002 — Reconnect state in the agent snapshot

`reconnect_attempts` (consecutive failed attempts, `0` when connected) and `reconnect_detail`
(the last transport error) on every agent status snapshot, surfaced by `GET /v1/agents` and
`hark daemon status`.

Trace: [[#REQ-006]], [[#NFR-001]], [[#TEST-008]]

## 10. Test specification

Techniques selected per the risk profile: the schedule is a pure function over a well-defined
domain → **property-based / exhaustive example testing**; the transport loop is a state machine
over a real socket → **integration testing against a purpose-built fake hub** (no mocks of our
own code — Constitutional Principle 5); the store is a parser at a trust boundary → **negative
input testing** and a **round-trip property**.

The fake hub is a real `tokio-tungstenite` server on `127.0.0.1:0` that speaks the genuine
`/chat/v1` framing (`len ‖ payload ‖ sig`), following the precedent in
`tests/ds_socket_interop.rs`. It is scripted per test: how many connections to accept, and
what to do on each.

| TEST | Validates | Type | Scenario |
|------|-----------|------|----------|
| **TEST-001** | [[#REQ-001]] | positive | Fake hub accepts, then closes the socket, then accepts again. The agent re-joins (the hub observes a second `hello`) and the handle is never `unhealthy`. |
| **TEST-001b** | [[#REQ-001]] | negative-output | Same, asserting the *absence* of the old behaviour: after the drop the snapshot state is never `unhealthy` with reason `hub_closed`. |
| **TEST-002** | [[#REQ-002]], [[#NFR-001]], [[#NFR-002]] | positive + negative-output | Pure schedule: first base is 1000 ms; bases double 1000→2000→4000→8000→15000→15000; with `random = 0.0` each delay equals its base, with `random → 1.0` each delay is 75 % of base; **no** delay exceeds 15000 ms or is negative for any `random ∈ [0,1)`; `reset()` returns the base to 1000 ms; `attempts()` counts; `at_ceiling()` flips exactly at 15000 ms. |
| **TEST-003** | [[#REQ-003]] | positive | On the second connection the fake hub observes, in order: a signed `hello` carrying the original capability, then an `announce` naming the original dialects. |
| **TEST-004** | [[#REQ-004]], [[#NFR-003]] | negative-output | `emit` during a gap returns `AgentError::NotReady`, **not** `Unhealthy`; the handle remains the active handle; a `recv` outstanding across the gap does not error and receives a message delivered after recovery. |
| **TEST-005** | [[#REQ-005]]a | negative-input | The fake hub accepts the reconnect's socket and answers the `hello` with `(error @room "forbidden-room")`. The handle goes `unhealthy` with the slug in the detail, and no further attempt is made. |
| **TEST-006** | [[#REQ-005]]b | negative-input | On an encryption-pinned channel the fake hub answers the reconnect with `roomcfg :enc false`. The handle goes `unhealthy`, downgrade refused, and no further attempt is made. |
| **TEST-007** | [[#REQ-003]] | negative-output | An agent created with `mls_create = true` does **not** send a second group creation on reconnect: the fake hub sees exactly one group-creating exchange across two connections. |
| **TEST-008** | [[#REQ-006]], [[#OBS-002]] | positive | During the gap the snapshot reports state `reconnecting` with `reconnect_attempts ≥ 1` and a non-empty `reconnect_detail`; after recovery, `connected` with `reconnect_attempts == 0`. |
| **TEST-009** | [[#REQ-007]] | positive | After a successful join the store file exists, is mode `0600`, and contains exactly one record with the join's handle, channel, dialects, capability, and receive-all mode. |
| **TEST-010** | [[#REQ-008]] | positive | Given a store with one record and a live fake hub, daemon start re-establishes the agent under the **same** agent handle. |
| **TEST-011** | [[#REQ-008]] | negative-output | Given a store with one record and **no** hub, daemon start still reports ready, and the agent exists in state `reconnecting` — it is neither dropped nor `unhealthy`. |
| **TEST-012** | [[#REQ-009]] | positive | After closing an agent the store holds no record for it, and a subsequent start creates no agent. |
| **TEST-013** | [[#REQ-010]] | negative-input | Each of: absent file; non-JSON bytes; `version: 2`; a record missing `channel`; a record whose `channel` fails `validate_chat_handle`; a record whose `dialects` contains an invalid id; a well-formed record *alongside* a malformed one. Each yields **zero** agents and a diagnostic — in particular the last case yields zero, not one. |
| **TEST-014** | [[#REQ-007]], [[#REQ-010]] | property | Round-trip: for a generated set of valid records, `load(save(records)) == records`. |
| **TEST-015** | [[#REQ-001]] (write side), [[#REQ-004]] | positive + negative-output | The hub drops the socket while the agent is emitting. The failing `emit` returns `AgentError::NotReady` — **not** `Unhealthy` — the agent reconnects, and a subsequent `emit` after recovery succeeds. Discovered during implementation: the original REQ-001 named only the read-side ends, which would have left the reported failure intact for an agent that was writing when the hub went away. |

Attribution map π is recorded in the "Validates" column and is total over the requirements in
§4–§5: every REQ and NFR has at least one TEST, and every TEST names at least one REQ.

## 11. Open questions

### OQ-001 — Does re-publishing KeyPackages on every re-join need a ceiling?

`join_frames()` mints a fresh last-resort KeyPackage plus a one-time pool on every call. Under
[[#REQ-003]] that now happens once per successful re-join rather than once per process, so a
flapping hub grows the agent's published pool on the hub side.

**Why it is not blocking.** Re-publication is *required* for correctness after a hub restart —
a hub that lost its KeyPackage store would otherwise never be able to add the agent — and the
browser client re-publishes on reopen for the same reason. The growth is hub-side, bounded by
the hub's own retention policy, and no incident has been attributed to it. **Owner:** hark.
**Resolution path:** measure the published pool size against a flapping hub before adding any
client-side suppression; a client that skips publication because it *believes* the hub still
has its keys is the worse failure.

## Changelog

<details>
<summary>Revision history — 0.1.0</summary>

- 0.1.0 — initial draft, from issue #25 (`anuna-research/hark#25`, reported by elf-02) with a
  live incident against `wss://cbcl-bus.fly.dev/chat/v1` on hark 0.1.5. Deviates from the
  issue's suggested fix in one place, recorded and argued in [[#ADR-004]]: the schedule does
  not exhaust.

</details>
