# Router Protocol Mapping

## Purpose

This spec defines how `hark` maps local daemon and CLI actions to
`cbcl-router` HTTP and WebSocket behavior.

The MVP is an agent interface. It focuses on persistent WebSocket agent
connections, receiving dispatched asks, and sending progress or terminal
messages. HTTP producer commands are optional later extensions.

The daemon itself is not a router-visible participant. It has no daemon-level
router identity, no daemon-level router WebSocket, and no router startup
handshake. Every router WebSocket connection in the MVP belongs to exactly one
daemon-managed agent instance created by `init`.

## Router Endpoints

The MVP client uses:

```text
WSS  /agent/v1
```

Router HTTP paths are outside the client scope.

## Authentication

The current router requires an authorization header on `/agent/v1`.

Supported current form:

```text
Authorization: Bearer shr_<key_id>.<secret>
```

Example:

```text
Authorization: Bearer shr_prod-agent.<secret>
```

The client should support this shared-secret bearer credential in the MVP. The
newer Ed25519/JWT enrollment system in the router repository is not currently
the `/agent/v1` authentication path and is out of scope for the first client
implementation.

## Agent Init

`hark init` creates one daemon-managed agent instance.

This is the first router-facing step in the normal client lifecycle. Running
`hark daemon start` before `init` only starts the local daemon; it
does not contact `/agent/v1`.

For each agent instance, the daemon:

1. mints a local `agent_handle`
2. derives a router-visible `agent-id`
3. opens one WebSocket connection to `/agent/v1`
4. sends a CBCL `hello` frame advertising capabilities and dialects
5. stores the connection under the local handle after the binary hello frame is
   successfully written

The capability list must be non-empty and supplied by the agent's `init`
request. Capabilities are per-agent; there are no daemon-level capability
defaults in the MVP. The daemon must not open a router WebSocket for a
zero-capability agent.

Recommended router-visible id:

```text
local-agent-<agent_handle>
```

The router-visible id must be unique among currently connected local agent
instances. It does not need to be semantically meaningful or durable across
daemon restarts.

A daemon with zero agent instances therefore has zero router-visible ids and
zero router WebSocket connections.

## Hello Frame

The daemon sends a CBCL frame shaped like:

```lisp
(lang cbcl-router
  (tell @router "hello"
    :agent-id "local-agent-01JX8F4V2QK8GZP9H6W5"
    :capabilities ("code:edit" "code:test")
    :dialects ()))
```

The current router extracts:

* `:agent-id`
* `:capabilities`
* `:dialects`

from the `hello` frame and stores them in the connected-agent registry for the
life of that WebSocket connection.

The current router does not send an explicit hello ACK. A malformed CBCL frame
causes the router to send an error frame and keep the connection open; a valid
hello produces no response.

For MVP, the daemon should treat `init` as successful after the WebSocket
upgrade succeeds and the binary hello frame is successfully written to the
socket. This confirms local connection establishment and local send success; it
does not prove that the router registered the agent. The daemon must not pause
after hello to wait for a possible router error. If the router later sends an
error frame or closes the connection, the daemon should mark the handle
unhealthy and expose that state through `recv`, `send`, and `daemon status`.

Current router implementation detail: `/agent/v1` sends frames from the router
to agents in two known situations:

* dispatched work arrives as a binary CBCL ask through the router's
  `dispatch-ask` path
* a CBCL `error` frame is sent back to the agent when the agent sends malformed
  CBCL to the router

The daemon should therefore treat router-originated CBCL `error` frames as
router diagnostics for frames the client sent, mark the handle unhealthy with
`router_error`, and expose the error through status and subsequent handle
operations. They should not be delivered as ordinary dispatched work by `recv`.
If the router error frame includes useful text, the daemon should retain a
sanitized diagnostic detail for `daemon status` while continuing to redact all
router and local daemon credentials.

## Receiving Work

When the router dispatches an ask, it sends a binary WebSocket frame to the
agent connection.

The daemon should:

1. receive the WebSocket frame
2. treat the frame bytes as CBCL text
3. enqueue the message in the per-handle inbound queue
4. wake one pending `recv` call if present

The daemon should not require an active `recv` command at the moment the router
frame arrives. Buffering behavior is defined in [`daemon.md`](daemon.md).

## Sending Agent Messages

The following CLI commands send over the selected handle's WebSocket
connection:

```bash
hark reply
hark error
hark progress
```

`reply` and `error` should:

1. read CBCL from an argument or stdin
2. validate the CBCL with `cbcl-rs`
3. check that the CBCL message matches the selected command
4. resolve `CBCL_AGENT_HANDLE`
5. send the frame through the daemon over that handle's WebSocket as a binary
   CBCL frame

`progress` should build a CBCL `tell @router "progress"` frame from flags,
validate the generated CBCL with `cbcl-rs`, resolve `CBCL_AGENT_HANDLE`, and
send the frame through the daemon over that handle's WebSocket as a binary CBCL
frame.

Terminal messages must be CBCL `reply` or `error` messages. Progress messages
must be CBCL `tell` messages to `@router` whose content is the string
`"progress"`.

The daemon must repeat validation and command-kind checking before forwarding
the frame to the router.

`reply` and `error` may be bare CBCL messages or dialect-wrapped CBCL messages.
Kind checking is performed after unwrapping any `(lang ...)` wrapper.

Example progress frame:

```lisp
(lang elf
  (tell @router "progress"
    :thread "rcp-ABCDEF"
    :text "running tests"))
```

If no progress text is supplied, the generated frame omits `:text`:

```lisp
(lang elf
  (tell @router "progress"
    :thread "rcp-ABCDEF"))
```

Both forms are valid CBCL under the local `cbcl-rs` parser; `:thread` is
mandatory for router receipt correlation, and `:text` is optional.

## Thread and Receipt Correlation

The current router injects `:thread "<receipt-id>"` into dispatched asks. Agent
terminal messages should preserve that `:thread` value so the router can append
the reply or error to the same receipt log.

Example:

```lisp
(lang elf
  (reply @router "ok"
    :thread "rcp-ABCDEF"
    :text "done"))
```

The client should not invent a new thread for replies to dispatched work unless
the agent intentionally starts a separate conversation.

The daemon does not track in-flight thread ids in the MVP. It rejects missing
`:thread` values but does not reject an otherwise valid message simply because
the thread is unknown locally.

For local validation, `:thread` must appear exactly once on the unwrapped inner
message and must be a non-empty CBCL string. Duplicate, empty, or non-string
thread values are rejected locally even if the router would otherwise accept or
store the frame under a fallback receipt id.

Progress messages also use `:thread` for receipt correlation. The current router
persists `(tell ... "progress" :thread "...")` frames as receipt entries with
kind `tell`.

Current router behavior:

* inbound WebSocket frames are parsed as CBCL and unwrapped to the inner message
  when dialect-wrapped with `(lang ...)`
* `(tell ... "progress" ...)` is appended to receipt storage using the `:thread`
  value as the receipt id
* the original frame bytes are stored in the router receipt log
* progress does not call the dispatcher terminal ACK path and does not complete
  or clear the in-flight ask
* the router does not send an application-level ACK for progress persistence
* non-progress `tell` frames from agents are ignored, except for `hello`

If `:thread` is missing, the current router stores the frame under receipt id
`"unknown"`. The client must reject progress messages without `:thread` to
avoid orphaning receipt entries.

## R5 Runtime Behavioural Verification

In addition to the static R1–R4 well-formedness checks `cbcl-rs` applies on
every parse, the daemon runs the cbcl-rs R5 pipeline (`run_pipeline_full`)
against the installed dialect at two boundaries:

* **Outbound** — between the local-api `/send` parse step and the router
  WebSocket write. The handler resolves the agent handle, snapshots the
  per-handle dialect registry from the agent's dialect cache, and runs the
  parsed envelope through `run_pipeline_full` with that registry and the
  per-handle `ThreadedMessageStore`. On success the innermost simple message is
  content-hashed (sha256 over the canonical s-expression encoding), inserted
  into the store keyed by `(hash, thread)`, and only then handed to the router
  writer.
* **Inbound** — between the agent WebSocket receive and the per-handle `recv`
  queue, for ordinary (non-meta) frames. The router-dispatched message is
  parsed, then passed through the same `run_pipeline_full` against the same
  per-handle registry and store. On success the message is appended to the
  store and enqueued for `recv` as today. Meta frames (`teach`, `query`,
  `subscribe`, …) continue to use the existing R1–R5 well-formedness path and
  do not enter the R5 behavioural pipeline.

The pipeline enforces two classes of constraints from the installed dialect:

* `(shape …)` constraints attached to a performative. These match against the
  *expanded* form: a `(require :target string)` on performative `greet` only
  fires if the dialect's performative template surfaces `:target` after
  template expansion. This is upstream cbcl-rs behaviour, not a hark choice.
* `(protocol …)` causal-predecessor declarations. The pipeline looks up the
  message's `:caused-by` digest in the per-handle `ThreadedMessageStore` and
  verifies that the predecessor's performative is permitted as a cause by the
  declared protocol.

Policy on unknown causal predecessors is `UnknownPredecessorPolicy::Reject`:
if `:caused-by` references a hash the per-handle store has never seen, the
daemon surfaces a `causal_violation` to the caller. We deliberately do not
implement `Buffer` — there is no pending-queue retry, no later replay, and no
out-of-order tolerance in the MVP.

Outbound fallback for unknown dialects: if the outer `(lang <name> …)` wrapper
names a dialect that is not present in the per-handle registry, the daemon
falls back to the lightweight `run_pipeline` (R1–R4 well-formedness only).
This preserves existing behaviour for tests and agents that have not yet
installed the dialect locally. `hark dialect publish` installs the dialect
into the publishing handle's local cache on successful router ack so the
publishing agent is subject to its own constraints immediately; agents that
receive a dialect via `subscribe` or fetch it via `query` likewise get the
local install. An agent that never installs a dialect locally — and is not
the publisher — will not have shape or protocol constraints from that
dialect enforced on its outbound traffic.

Scope of an installed dialect: the pipeline composes constraints across *all*
dialects in the per-handle registry, not just the one named in `(lang …)`. If
any installed dialect declares a `(shape …)` or `(protocol …)` clause that
matches the message's performative — including core performatives such as
`reply` or `tell` — that constraint applies. Consequently, an unwrapped
`(reply …)` is still checked against any installed dialect whose protocol
mentions `reply`. This follows cbcl-rs REQ-231 (complete monitoring: every
matching constraint must pass via conjunction).

Inbound violation policy: any `ShapeViolation`, `CausalViolation`, or
`PipelineResult::Pending` on an ordinary inbound frame causes the daemon to
drop the message before it reaches `enqueue_inbound`. A
`tracing::warn!(target: "hark::r5", …)` event is emitted with `performative`,
`thread`, and `blame` fields so operators can correlate the drop. The message
never reaches `recv`, and the daemon does not surface a separate inbound error
channel for these drops in the MVP. The handle itself remains healthy.

## Disconnect and Close

`hark close` closes the selected handle's WebSocket connection.

When the WebSocket closes, the router removes that connected agent from its
active registry. The same handle should not be reused after close.

The local daemon removes the handle from its active state after explicit close.
Subsequent commands using the same handle should fail as `unknown_agent_handle`.

If an agent queue overflows, the daemon should close the corresponding
WebSocket as a backpressure signal, as described in [`daemon.md`](daemon.md).

## Non-Goals

The MVP does not require:

* Ed25519/JWT enrollment
* durable router identity across daemon restarts
* router dialect gossip
* router firehose subscriptions
