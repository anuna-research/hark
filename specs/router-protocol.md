# Router Protocol Mapping

## Purpose

This spec defines how `cbcl-router-client` maps local daemon and CLI actions to
`cbcl-lfe-router` HTTP and WebSocket behavior.

The MVP is an agent interface. It focuses on persistent WebSocket agent
connections, receiving dispatched asks, and sending progress or terminal
messages. HTTP producer commands are optional later extensions.

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

`cbcl-router-client init` creates one daemon-managed agent instance.

For each agent instance, the daemon:

1. mints a local `agent_handle`
2. derives a router-visible `agent-id`
3. opens one WebSocket connection to `/agent/v1`
4. sends a CBCL `hello` frame advertising capabilities and dialects
5. stores the connection under the local handle after the binary hello frame is
   successfully written

Recommended router-visible id:

```text
local-agent-<agent_handle>
```

The router-visible id must be unique among currently connected local agent
instances. It does not need to be semantically meaningful or durable across
daemon restarts.

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
does not prove that the router registered the agent. If the router later sends
an error frame or closes the connection, the daemon should mark the handle
unhealthy and expose that state through `recv`, `send`, and `daemon status`.

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
cbcl-router-client reply
cbcl-router-client error
cbcl-router-client progress
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

Example progress frame:

```lisp
(lang elf
  (tell @router "progress"
    :thread "rcp-ABCDEF"
    :text "running tests"))
```

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
* non-progress `tell` frames from agents are ignored, except for `hello` and
  `heartbeat`

If `:thread` is missing, the current router stores the frame under receipt id
`"unknown"`. The client must reject progress messages without `:thread` to
avoid orphaning receipt entries.

## Disconnect and Close

`cbcl-router-client close` closes the selected handle's WebSocket connection.

When the WebSocket closes, the router removes that connected agent from its
active registry. The same handle should not be reused after close.

If an agent queue overflows, the daemon should close the corresponding
WebSocket as a backpressure signal, as described in [`daemon.md`](daemon.md).

## Non-Goals

The MVP does not require:

* Ed25519/JWT enrollment
* durable router identity across daemon restarts
* router dialect gossip
* router firehose subscriptions
