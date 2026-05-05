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
    "code": "missing_agent_handle",
    "message": "CBCL_AGENT_HANDLE is not set",
    "hint": "run `eval \"$(cbcl-router-client init ...)\"`"
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
  "api_version": 1
}
```

The CLI is compatible with a daemon only when the daemon reports the same
`api_version`. Patch and minor binary version differences are allowed under the
same API version. If `api_version` differs or is missing, the CLI should treat
the daemon as incompatible, report both versions when available, and suggest
restarting the daemon with the current binary.

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
    "api_version": 1
  },
  "agents": [
    {
      "agent_handle": "01JX8F4V2QK8GZP9H6W5",
      "router_agent_id": "local-agent-01JX8F4V2QK8GZP9H6W5",
      "capabilities": ["code:edit", "code:test"],
      "state": "connected",
      "queued_messages": 0,
      "queued_bytes": 0,
      "unhealthy_reason": null
    }
  ]
}
```

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

* `kind` - one of `reply`, `error`, or `progress`.
* `message` - CBCL text to send over the router WebSocket.

The CLI should validate the CBCL with `cbcl-rs` before making this request. The
daemon must also validate before forwarding because local HTTP clients are not
trusted.

The daemon must enforce that `kind` matches the message:

* `reply` requires a CBCL performative of `reply` after unwrapping any `(lang
  ...)` dialect wrapper.
* `error` requires a CBCL performative of `error` after unwrapping any `(lang
  ...)` dialect wrapper.
* `progress` requires a CBCL performative of `tell` after unwrapping any `(lang
  ...)` dialect wrapper, recipient `@router`, and content `"progress"`.
* all three kinds require a `:thread` parameter.

The required `:thread` parameter must appear exactly once after unwrapping any
`(lang ...)` dialect wrapper. Its value must be a non-empty CBCL string.
Missing, empty, non-string, or duplicate `:thread` values must return `422`
with a stable validation error code and must not be forwarded to the router.

Bare CBCL messages and dialect-wrapped CBCL messages are valid inputs for
`reply` and `error` if they pass validation and kind checking. The CLI-generated
`progress` message is always dialect-wrapped, but the daemon should validate the
unwrapped shape rather than relying on that CLI behavior.

If validation or kind checking fails, the daemon must return an error and must
not send the frame to the router.

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

For `progress`, successful local send means the daemon wrote the frame to the
selected WebSocket. The current router does not send an application-level ACK
for progress frames, so the local API cannot confirm receipt persistence
synchronously.

The CLI `progress` command builds its CBCL message from command-line flags and
then calls this endpoint with `kind = "progress"`. The local API remains
message-based so the daemon has one validation and forwarding path for all
agent-originated frames.

Response:

```json
{
  "ok": true,
  "agent_handle": "01JX8F4V2QK8GZP9H6W5"
}
```

### `DELETE /v1/agents/{handle}`

Closes the selected WebSocket connection and removes daemon state for the agent
handle.

`handle` uses the same validation rules as `/recv`.

Response:

```json
{
  "ok": true,
  "agent_handle": "01JX8F4V2QK8GZP9H6W5"
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
