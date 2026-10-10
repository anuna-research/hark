# Local Daemon API

## Purpose

CLI invocations communicate with the per-user daemon over loopback TCP. This
spec defines the first local API between short-lived CLI commands and the
long-lived daemon process.

The API is local-only. It is not a public network API and must not bind to a
non-loopback interface.

The local API is also the boundary between daemon startup and router-facing
agent creation. Starting the daemon only makes this API available. The daemon
does not communicate with the router until `POST /v1/agents` asks it to create
an agent instance.

## Transport

The first implementation should use HTTP with JSON request and response bodies
over loopback TCP.

The daemon address is discovered from `daemon.json` as described in
[`daemon.md`](daemon.md). Every request must authenticate with the local daemon
token from `daemon.json`.

Recommended header:

```text
Authorization: Bearer <daemon-token>
```

The daemon token is separate from the router credential. It authenticates local
CLI commands to the local daemon only.

## Response Format

Successful JSON responses should use ordinary JSON objects.

Errors should use a stable shape:

```json
{
  "error": {
    "code": "unknown_agent_handle",
    "message": "agent handle is not active",
    "hint": "run `hark daemon status` to list active handles"
  }
}
```

HTTP status guidance:

* `200` - success
* `400` - malformed request
* `401` - missing or invalid daemon token
* `408` - blocking receive timed out
* `404` - unknown agent handle
* `409` - handle is unhealthy, busy, or otherwise not currently usable
* `422` - CBCL validation failed
* `503` - daemon is shutting down or otherwise temporarily unavailable
* `500` - daemon internal error

Stable error codes used by the MVP local API:

* `missing_daemon_token` - local authorization header is absent.
* `invalid_daemon_token` - local authorization failed.
* `daemon_api_incompatible` - daemon local API version does not match the CLI.
* `missing_router_ws_url` - router WebSocket URL is not configured.
* `invalid_router_ws_url` - router WebSocket URL is malformed or not `ws://` or
  `wss://`.
* `router_auth_rejected` - the WebSocket upgrade was refused with HTTP 401/403
  (e.g. by a proxy in front of `/agent/v1`). The hub itself has no connection
  auth — identity is per-frame Ed25519, so a bad signature/identity arrives as
  an error frame after connect, not here. (`missing_router_auth_token` is legacy
  and no longer emitted.)
* `router_connection_failed` - router WebSocket connection failed for another
  network or protocol reason.
* `missing_dialect` - agent creation request has no dialects.
* `duplicate_dialect` - agent creation request repeats a dialect.
* `invalid_dialect` - dialect value does not match the configured grammar.
* `malformed_agent_handle` - handle path component does not match the handle
  grammar.
* `unknown_agent_handle` - handle is well-formed but not active in the daemon.
* `agent_handle_unhealthy` - handle exists but cannot send or receive.
* `recv_already_waiting` - a blocking receive is already parked for the handle.
* `recv_timeout` - blocking receive reached its timeout.
* `daemon_stopping` - daemon is shutting down.
* `cbcl_validation_failed` - CBCL parsing or validation failed.
* `shape_violation` - message failed the installed dialect's `(shape …)`
  constraint during R5 runtime verification. Returned as HTTP 422. The
  error body carries the standard `code` and `message` fields plus
  optional `performative` and `thread` strings extracted from the
  offending message so callers can correlate the rejection without
  re-parsing the body.
* `causal_violation` - message's `:caused-by` references a hash not present in
  the per-handle `ThreadedMessageStore`, or violates the installed dialect's
  `(protocol …)` predecessor declaration. Returned as HTTP 422 with the
  same `code` / `message` / `performative` / `thread` shape as
  `shape_violation`.
* `message_kind_mismatch` - message performative does not match `kind`.
* `missing_thread` - sent message has no `:thread`.
* `duplicate_thread` - sent message has more than one `:thread`.
* `invalid_thread` - sent message has an empty or non-string `:thread`.
* `invalid_subscribe_pattern` - subscribe pattern is empty or contains
  characters that would break the canonical envelope.
* `meta_send_busy` - another meta send is already awaiting a router reply
  for this agent handle. Single-slot per agent.
* `meta_reply_timeout` - the router did not reply to the meta send within
  the daemon's wait window.
* `dialect_unknown_to_router` - the router replied to a `query <name>`
  with `router-does-not-speak`.
* `meta_reply_malformed` - router reply could not be parsed as a CBCL
  reply / teach-back.
* `meta_reply_missing_digest`, `meta_reply_missing_name` - publish reply
  lacked the expected `:digest` or `:name` keyword.
* `internal_error` - unexpected daemon failure.

## Endpoints

Endpoint names and request/response shapes in this document are the MVP local
API contract. Later versions may add endpoints or fields, but the first
implementation should treat the endpoints below as stable enough for tests and
agent harnesses.

### `GET /v1/ping`

Proves daemon liveness and daemon-token validity.

Response:

```json
{
  "ok": true,
  "version": "0.1.0",
  "api_version": 4
}
```

The CLI is compatible with a daemon only when the daemon reports the same
`api_version`. Patch and minor binary version differences are allowed under the
same API version. If `api_version` differs or is missing, the CLI should treat
the daemon as incompatible, report both versions when available, and suggest
restarting the daemon with the current binary. In the implementation this is
`DiscoveryState::ApiIncompatible`, surfacing as exit code `12` with that hint.

`api_version` history. This document recorded `1` while the implementation had
already reached `3`; the gap is closed here rather than papered over by the jump
to `4`.

| version | change |
| --- | --- |
| 1 | initial local API |
| 2, 3 | shipped in the implementation while this document still said `1` — the intervening changes are not reconstructed here |
| 4 | `kind` enum: `emit` → `send`, `progress` dropped (SPEC-016 ADR-009, ADR-010) |

### `POST /v1/agents`

Creates an ephemeral agent instance and opens a WebSocket connection to the
router.

This endpoint is the first point in the normal lifecycle that requires router
WebSocket URL and router authentication configuration. A daemon may be running
and healthy before those values are configured, but this endpoint must fail
before opening a WebSocket if the effective router configuration is missing or
invalid.

Request:

```json
{
  "capabilities": ["code:edit", "code:test"],
  "dialects": []
}
```

Fields:

* `capabilities` - non-empty per-agent capability strings advertised in the
  router `hello`.
* `dialects` - optional dialect ids advertised in the router `hello`.
* `objects` - chat transport only; optional boolean, default `false`. The
  SPEC-086 object subscription (CON-003): every object content message (a `sha256-<64hex>` dialect) in
  the channel — the agent's own and replayed history included — is delivered
  to `recv` with an attestation record, independent of `dialects` and of the
  room's declared menu. Persisted in the pairing record, so a daemon restart
  resumes it. On the router transport `true` is rejected with `400` and
  `error.code = "objects_unsupported"`. An object dialect (`sha256-<64hex>`)
  in `dialects` turns the subscription on as well; such names are stripped
  before advertisement and never appear in the response's `dialects`.

The daemon must reject requests whose `capabilities` list is empty. Capability
and dialect values must follow the grammars defined in [`config.md`](config.md),
duplicates are rejected, and successful responses preserve request order. The
daemon does not apply capability defaults.

Response:

```json
{
  "agent_handle": "01JX8F4V2QK8GZP9H6W5",
  "router_agent_id": "local-agent-01JX8F4V2QK8GZP9H6W5",
  "capabilities": ["code:edit", "code:test"],
  "dialects": [],
  "state": "connected"
}
```

The daemon should not return success from this call until:

* the WebSocket upgrade has succeeded
* the binary `hello` frame has been successfully written to the WebSocket

The current router does not send an explicit hello ACK. It registers the agent
after parsing the `hello` frame and sends an error frame only for malformed
CBCL, so this endpoint cannot synchronously prove router-side registration.
Successful `POST /v1/agents` means local connection establishment and local
hello send succeeded. The daemon must not add a grace-period wait for a possible
immediate router error; that delay is not worth the CLI UX cost for the MVP.
If the router later sends an error frame or closes the connection, the daemon
should mark the handle unhealthy and expose that state through `recv`, `send`,
and `GET /v1/agents`.

### `GET /v1/agents`

Returns daemon status.

Response:

```json
{
  "daemon": {
    "pid": 12345,
    "addr": "127.0.0.1:49152",
    "version": "0.1.0",
    "api_version": 4
  },
  "agents": [
    {
      "agent_handle": "01JX8F4V2QK8GZP9H6W5",
      "router_agent_id": "local-agent-01JX8F4V2QK8GZP9H6W5",
      "capabilities": ["code:edit", "code:test"],
      "dialects": [],
      "state": "connected",
      "queued_messages": 0,
      "queued_bytes": 0,
      "unhealthy_reason": null
    }
  ]
}
```

Agent records additionally include an optional `connection` object:

```json
{
  "backend": "chat",
  "hub": "wss://example.org/chat/v1",
  "encryption": "mls",
  "socket": "connected",
  "ready": false,
  "reason": "awaiting MLS Welcome",
  "recovery": "wait for automatic recovery; hark --agent <handle> whoami"
}
```

`socket` retains the transport state (`connected`, `reconnecting`, or
`unhealthy`). `ready` is false during session initialization, pending MLS
membership, encryption downgrade refusal, MLS divergence, or a transport
failure. `encryption` is `none`, `mls`, or `unknown` during initialization.
A healthy connection has null `reason` and `recovery`. Readiness is a snapshot,
not a guarantee that a later send succeeds. Older daemons omit `connection`.
Hub URLs omit credentials, query parameters, and fragments.

`active_agent_handle`, when present, is informational. The CLI selects by
`--agent`, then `CBCL_AGENT_HANDLE`, then the sole registered connection; it
rejects an implicit selection when multiple agents exist.

### `GET /v1/config`

Returns the running daemon's captured configuration as a JSON object with
`router`, `chat`, `agent`, and `daemon` sections. Includes applied environment
overrides and resolved chat defaults. Authentication tokens are replaced by
`<redacted>`; URLs omit credentials, query parameters, and fragments. Requires
the same bearer authentication as every other endpoint. Used by `config show`.

### `GET /v1/agents/{handle}/recv`

Blocks until an inbound CBCL message is available for `handle`, then returns it.

`handle` must match the agent-handle grammar defined in [`daemon.md`](daemon.md).
Malformed handle path components should return `400` with
`error.code = "malformed_agent_handle"` rather than `404`.

The CLI `recv` command should print only the message bytes to stdout by
default. This endpoint may return JSON so the CLI can handle metadata.

Response:

```json
{
  "agent_handle": "01JX8F4V2QK8GZP9H6W5",
  "message": "(lang elf (ask @router \"echo\" :thread \"rcp-...\"))"
}
```

An object message delivered under the SPEC-086 object subscription carries an
additional `record` member (SPEC-086 CON-001; additive, ADR-002 — consumers
that do not know it ignore it). It is absent for every other message.

```json
{
  "agent_handle": "01JX8F4V2QK8GZP9H6W5",
  "message": "(lang sha256-<64hex> (check @room :item \"milk\" … :from @alice))",
  "record": {
    "room": "@room",
    "signer": "@alice",
    "attested_by": "mls",
    "own": false,
    "replayed": true
  }
}
```

* `room` - the room handle the frame arrived on.
* `signer` - the authenticated author (SPEC-086 REQ-006): in an MLS room the
  MLS sender (a message whose inner `:from` differs is dropped); in a cleartext
  room the `:from` of a frame the hub delivered. A frame with no establishable
  signer is never delivered as an object record.
* `attested_by` - `"mls"` or `"hub"`.
* `own` - `signer` is this agent's own wire handle.
* `replayed` - the frame arrived in join/reconnect backfill (announced by the
  hub's `backfilltimes` frame) or in a history reply.

The record carries no cid: the daemon never canonicalises, verifies, or
projects object messages (SPEC-086 ADR-001, REQ-007); the bytes in `message`
are exactly the plaintext as decoded or decrypted (REQ-005). Duplicates —
backfill overlap, the hub's echo of the agent's own sends — are delivered and
left to the SDK to deduplicate by cid (ADR-003).

Query parameters:

* `timeout_ms` - optional maximum wait time.

If `timeout_ms` is absent, the request may block until a message arrives, the
selected handle is removed or becomes unhealthy, the daemon stops, or the HTTP
connection fails. If `timeout_ms` expires before a message arrives, return a
timeout error rather than an empty success. The daemon should reject zero,
negative, and values greater than `7776000000` milliseconds (90 days) as
malformed requests.

If the handle has queued messages, the daemon should return the oldest queued
message immediately. Otherwise it should park the request until a message
arrives, the handle becomes unhealthy, is removed, or the timeout expires.

Failure behavior:

* unknown handle: `404` with `error.code = "unknown_agent_handle"`
* unhealthy handle: `409` with `error.code = "agent_handle_unhealthy"`
* second concurrent waiter for the same handle: `409` with
  `error.code = "recv_already_waiting"`
* timeout: `408` with `error.code = "recv_timeout"`
* daemon shutdown while waiting: `503` with `error.code = "daemon_stopping"`

The CLI should map unknown and unhealthy handles to exit code `7`, second
concurrent waiters to exit code `7`, timeouts to exit code `10`, and daemon
shutdown to exit code `12` unless a more specific daemon-lifecycle code applies.

### `POST /v1/agents/{handle}/send`

Sends a CBCL frame over the selected agent's WebSocket connection.

`handle` uses the same validation rules as `/recv`.

Request:

```json
{
  "kind": "reply",
  "message": "(lang elf (reply @router \"ok\" :thread \"rcp-...\"))"
}
```

Fields:

* `kind` - one of `reply`, `error`, or `send`.
* `message` - CBCL text to send over the router WebSocket.

The CLI should validate the CBCL with `cbcl-rs` before making this request. The
daemon must also validate before forwarding because local HTTP clients are not
trusted.

The daemon must enforce that `kind` matches the message:

* `reply` requires a CBCL performative of `reply` after unwrapping any `(lang
  ...)` dialect wrapper.
* `error` requires a CBCL performative of `error` after unwrapping any `(lang
  ...)` dialect wrapper.
* `send` accepts any performative, core or custom, bare or carried in a `(lang
  ...)`, `(envelope ...)`, `(signed ...)`, or `(with-limits ...)` envelope. It
  is validated by the full R1–R5 pipeline with no fixed performative; a `(meta
  ...)` form is refused. It is not rewritten.
* `reply` and `error` require a `:thread` parameter. `send` does not — a
  proactive frame need not belong to a dispatched ask.

`kind` history (SPEC-016 ADR-009, ADR-010): `emit` was renamed to `send`, and
`progress` was dropped with the CLI verb. A `progress` frame is now an ordinary
`send` payload, byte-identical on the wire. Both changes ride
`api_version` 4.

The required `:thread` parameter must appear exactly once after unwrapping any
`(lang ...)` dialect wrapper. Its value must be a non-empty CBCL string.
Missing, empty, non-string, or duplicate `:thread` values must return `422`
with a stable validation error code and must not be forwarded to the router.

Bare CBCL messages and dialect-wrapped CBCL messages are valid inputs for
`reply`, `error`, and `send` if they pass validation and kind checking. The
daemon validates the unwrapped shape rather than relying on any CLI behavior;
a `send` payload is caller-authored and carries no CLI-imposed shape at all.

If validation or kind checking fails, the daemon must return an error and must
not send the frame to the router.

After parse and kind checking, the daemon runs the cbcl-rs R5 behavioural
pipeline (`run_pipeline_full`) against the per-handle dialect registry
snapshot and the per-handle `ThreadedMessageStore`. Shape and causal-protocol
constraints declared by the installed dialect are enforced here. On success
the innermost simple message is content-hashed and inserted into the store
keyed by `(hash, thread)` before the frame is forwarded to the router. On
failure the daemon returns `422` with `error.code = "shape_violation"` or
`"causal_violation"` and does not write the frame. If the outer
`(lang <name> …)` wrapper names a dialect that is not installed in the
per-handle registry, the daemon falls back to the lightweight R1–R4 pipeline
and does not enforce shape or protocol constraints from that dialect.
[`router-protocol.md`](router-protocol.md) describes the full R5 runtime flow
and the inbound counterpart.

A successful `/send` response means:

1. the daemon validated the CBCL and command kind,
2. the selected handle was connected and healthy, and
3. the frame was successfully written to the selected router WebSocket.

The daemon must not return success merely because the frame was accepted into
an internal queue. If the local WebSocket write fails, the daemon should mark
the handle unhealthy with `local_send_failed` and return `409` with
`error.code = "agent_handle_unhealthy"` or `503` if the daemon is shutting down.

Handle failure behavior for `/send` should match `/recv`: unknown handles
return `404`, unhealthy handles return `409`, and daemon shutdown returns
`503`.

The daemon does not track dispatched `:thread` values in the MVP. It only
requires the local `:thread` shape defined above. The router remains responsible
for authoritative receipt correlation.

For a progress frame carried by `send`, successful local send means the daemon
wrote the frame to the selected WebSocket. The current router does not send an
application-level ACK for progress frames, so the local API cannot confirm
receipt persistence synchronously.

The CLI no longer builds progress frames: `progress` is retired (SPEC-016
ADR-010) and the caller authors the frame. The local API remains message-based
so the daemon has one validation and forwarding path for all agent-originated
frames.

Response:

```json
{
  "ok": true,
  "agent_handle": "01JX8F4V2QK8GZP9H6W5"
}
```

### `POST /v1/agents/{handle}/history`

SPEC-086 CON-002. Asks the hub for older room history on the agent's own
connection; the reply arrives through `recv` like any other traffic, with
object messages carrying `record.replayed = true`.

Request:

```json
{ "room": "@general", "limit": 1000 }
```

* `room` - the channel handle; must be the channel this agent joined.
* `limit` - an integer in `1`–`1000`. Any other value returns `400` with
  `error.code = "malformed_history_request"`. (cbcl-bus clamps a reply at its
  own ceiling, 500 frames at the time of writing.)

The daemon sends `(history <room> :limit <n> :from <agent-handle>)` as a hub
control frame — never MLS-sealed, even in an encrypted room. The hub replies
with raw archived frames, oldest first, with no end marker; a frame is
therefore counted as part of the reply positionally, up to `limit`, until a
settle gap ends the run.

Success: `202` with `{"ok": true}`.

Failure behavior:

* a request for that room still unanswered: `409` with
  `error.code = "history_in_flight"` (one in flight per room; the slot is held
  for a bounded window since the hub sends no end marker)
* a room the agent has not joined, or an agent on the router transport: `409`
  with `error.code = "room_not_joined"`
* unknown, unhealthy, and malformed handles: as for `/recv`

### Objects (SPEC-086 Stage B)

Four endpoints let an agent read, act on, and create hypermedia objects
through the daemon itself. They need the agent's object subscription
(`"objects": true` on create); otherwise they return `409` with
`error.code = "objects_not_subscribed"`. A daemon without the object runtime
returns `503` with `error.code = "objects_unavailable"`.

The daemon keeps one controller per agent in Rust; every judgement is
cbcl-rs's, linked natively at the revision cbcl-bus ships to browsers: the
SPEC-087 contract compile, SPEC-019 admission, the fold, the intent binder,
and the reads. Delivered object messages and taught dialects are journalled
per agent and room under `<chat.identity_dir>/objects/` (owner-only) and
replayed into a fresh controller after a daemon restart (SPEC-086 CON-004),
so private-room state survives where no hub replay could restore it. With the
runtime attached, a full `recv` queue sheds its oldest object records instead
of marking the handle unhealthy.

#### `POST /v1/objects/check`

Request `{"definition": <definition>}`. Compiles and verifies the definition
without an agent and without sending; returns `{dialect, label, opener,
verbs, state, roles, contract, cbcl}`: the dialect's self-address, the
contract's label, the opener verb, cbcl-rs's description of the verbs and
state rules, the exact contract bytes, and the `(define …)` text. `422
object_rejected` with cbcl-rs's own reason for an invalid one. See
`docs/object-definitions.md`.

#### `GET /v1/agents/{handle}/objects`

The object threads the agent's controller has learned:

```json
{ "agent_handle": "…", "objects": [ { "thread": "list-1", "dialect": "sha256-<64hex>" } ] }
```

#### `GET /v1/agents/{handle}/objects/{thread}`

The state — cbcl-rs's fold over the accepted acts, the same JSON every
browser computes:

```json
{ "agent_handle": "…", "thread": "list-1", "dialect": "sha256-<64hex>", "state": { "title": "Groceries", "items": { "milk": true } } }
```

`404` with `error.code = "object_unknown"` when the thread is not in loaded
history (its opener may be older than the backfill; a history request fetches
more). `thread` is percent-encoded in the path.

#### `POST /v1/agents/{handle}/objects/{thread}/act`

Request `{"verb": "check", "fields": {"item": "milk", "done": true}}`. A
caller supplies the verb and its data fields only; cbcl-rs's intent binder
(SPEC-019 R.5) admits the verb for the signer, binds recipients, `:thread`,
`:caused-by` and `:replaces` from the accepted set, builds and verifies the
act; the daemon signs and sends it on the agent's connection. A routing
keyword in `fields` is a forgery and is refused. Response
`{"ok": true, "agent_handle": "…", "thread": "…", "cid": "<64hex>"}` where
`cid` is the act's wire address. A rejection is `422` with
`error.code = "object_action_rejected"` and cbcl-rs's own reason as the
message; nothing rejected reaches the wire.

#### `POST /v1/agents/{handle}/objects`

Request `{"definition": <definition>, "thread": "list-1", "fields": {"title": "Groceries"}}`
where `definition` is an authoring definition (`{name, verbs, project}`), a
SPEC-087 version-3 contract (`{"kind": "contract", …}`), or the serialised
contract text. cbcl-rs compiles and verifies it; the daemon declares the
dialect to the room by self-address (`adddialect :def`, SPEC-087 REQ-005),
sends the opener, and the agent's own controller learns both at once.
Response:

```json
{ "ok": true, "agent_handle": "…", "thread": "list-1", "dialect": "sha256-<64hex>", "cid": "<64hex>", "message": "(lang sha256-… (open @room …))" }
```

An invalid definition is `422` with `error.code = "object_rejected"`.

### `DELETE /v1/agents/{handle}`

Closes the selected WebSocket connection and removes daemon state for the agent
handle.

`handle` uses the same validation rules as `/recv`.

If the handle is connected, the daemon should close the router WebSocket and
remove local handle state. If the handle is already unhealthy, the daemon should
still remove local handle state and return success. Explicit close is a local
cleanup command; callers should not have to recover an unhealthy handle before
removing it.

Failure behavior:

* malformed handle: `400` with `error.code = "malformed_agent_handle"`
* unknown handle: `404` with `error.code = "unknown_agent_handle"`
* daemon shutdown: `503` with `error.code = "daemon_stopping"`

Response:

```json
{
  "ok": true,
  "agent_handle": "01JX8F4V2QK8GZP9H6W5"
}
```

### `POST /v1/agents/{handle}/meta/subscribe`

Sends `(meta (subscribe (speak? <pattern>)))` to the router on behalf of the
agent. Fire-and-forget: no router reply is awaited. The router pins the
subscription to the agent's WebSocket pid; on disconnect the subscription is
auto-evicted.

Request body:

```json
{ "pattern": "arena-*" }
```

`pattern` is required and must be a CBCL symbol — non-empty and free of
whitespace, parens, and quote characters. Returns
`400 invalid_subscribe_pattern` otherwise.

Response (`200`):

```json
{ "ok": true, "agent_handle": "..." }
```

### `POST /v1/agents/{handle}/meta/unsubscribe`

Sends `(meta (unsubscribe))`. Drops the agent's single subscription without
closing the WebSocket. Idempotent; succeeds whether or not the agent had an
active subscription. Empty request body.

Response (`200`):

```json
{ "ok": true, "agent_handle": "..." }
```

### `POST /v1/agents/{handle}/meta/publish`

Runs cbcl-rs's R1–R5 pipeline on `(meta <define>)` first, rejecting locally
with `400 cbcl_validation_failed` on any violation. On pass, sends
`(meta (teach @router <define>))`, awaits the router's `(reply ...)`, and
returns the parsed `:digest` + `:name`. Single-slot meta-await per agent —
concurrent calls return `409 meta_send_busy`. Default wait is 10 seconds
before `408 meta_reply_timeout`.

Request body:

```json
{ "define": "(define <name> ...)" }
```

Response (`200`):

```json
{
  "ok": true,
  "agent_handle": "...",
  "digest": "<sha256 hex>",
  "name": "<dialect-name>"
}
```

### `POST /v1/agents/{handle}/meta/query`

Sends `(meta (query (speak? <name>)))`, awaits the router's reply. On hit
(router has the dialect) the reply is a teach-back
`(meta (teach @<self> (define <name> ...)))`; the daemon's receive loop
installs the inner define into the local dialect cache (validating R1–R5)
and the handler returns `digest`, `name`, and the canonical `define` form.
On miss returns `404 dialect_unknown_to_router` with the router's reason
text.

Request body:

```json
{ "name": "arena-v1" }
```

Response (`200`):

```json
{
  "ok": true,
  "agent_handle": "...",
  "digest": "<sha256 hex>",
  "name": "<dialect-name>",
  "define": "(define <name> ...)"
}
```

### `POST /v1/agents/{handle}/meta/list`

Sends `(meta (query (list)))`, awaits the router's `(reply ... :names "a b c")`,
and returns each name as a string. Empty request body.

Response (`200`):

```json
{
  "ok": true,
  "agent_handle": "...",
  "names": ["arena-v1", "arena-v2", "..."]
}
```

### `POST /v1/stop`

Requests daemon shutdown.

Response:

```json
{
  "ok": true
}
```

After accepting the stop request, the daemon should close all active agent
WebSocket connections, remove `daemon.json`, and exit. Releasing
`daemon.lock` happens by process exit.

If no agent instances exist, shutdown has no router WebSocket connections to
close. It should still remove local discovery state and exit normally.

The `daemon stop` CLI should treat shutdown as successful after a successful
`POST /v1/stop` once one of these conditions is observed before its stop
timeout expires:

* `daemon.json` has been removed
* the recorded local address refuses connections or no longer accepts HTTP
* authenticated `GET /v1/ping` no longer succeeds

This allows the CLI to handle the normal race between the stop response,
discovery-file deletion, listener shutdown, and process exit.

## Agent States

Agent status responses should use these MVP state values:

* `connected` - WebSocket upgrade succeeded and the hello frame was written.
* `unhealthy` - the handle still exists for diagnostics, but cannot receive or
  send messages.

Explicitly closing a handle removes it from daemon state. Later requests for
that handle should return `404 unknown_agent_handle`, not a persistent `closed`
state.

When `state` is `unhealthy`, `unhealthy_reason` should be a short stable code
such as `router_closed`, `router_error`, `queue_overflow`, or
`local_send_failed`.

When available, status may also include `unhealthy_detail` with a sanitized
human-readable diagnostic, such as the router error frame text. This field must
not contain router authentication material or the local daemon token.

## Blocking and Concurrency

Multiple `recv` calls for the same handle should not all receive the same
message. The daemon must deliver each inbound message to at most one waiting
`recv` call.

Recommended first behavior:

* allow at most one blocking `recv` waiter per handle
* if a second waiter arrives, return `409 recv_already_waiting`
* queued messages are delivered FIFO

The daemon may support multiple waiters later if it can preserve exactly-once
local delivery semantics.

## Validation Boundary

Local CLI commands should perform CBCL parse/validation before calling
`/send`. The daemon must still treat inbound local requests as untrusted and
must revalidate messages before forwarding them to the router.

Router validation remains authoritative.
