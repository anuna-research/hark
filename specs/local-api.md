# Local Daemon API

## Purpose

CLI invocations communicate with the per-user daemon over loopback TCP. This
spec defines the first local API between short-lived CLI commands and the
long-lived daemon process.

The API is local-only. It is not a public network API and must not bind to a
non-loopback interface.

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
* `404` - unknown agent handle
* `409` - handle is closed, unhealthy, or otherwise not usable
* `422` - CBCL validation failed
* `500` - daemon internal error

## Endpoints

Endpoint names are provisional; command behavior is the stable contract.

### `GET /v1/ping`

Proves daemon liveness and daemon-token validity.

Response:

```json
{
  "ok": true,
  "version": "0.1.0"
}
```

### `POST /v1/agents`

Creates an ephemeral agent instance and opens a WebSocket connection to the
router.

Request:

```json
{
  "capabilities": ["code:edit", "code:test"],
  "dialects": []
}
```

Fields:

* `capabilities` - capability strings advertised in the router `hello`.
* `dialects` - optional dialect ids advertised in the router `hello`.

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
* the `hello` frame has been sent
* the connection remains open through a short implementation-defined readiness
  grace period
* no router error frame is received during that grace period

The current router does not send an explicit hello ACK. It registers the agent
after parsing the `hello` frame and sends an error frame only for malformed CBCL,
so this grace-period check is the MVP readiness signal.

### `GET /v1/agents`

Returns daemon status.

Response:

```json
{
  "daemon": {
    "pid": 12345,
    "addr": "127.0.0.1:49152",
    "version": "0.1.0"
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

If `timeout_ms` expires before a message arrives, return a timeout error rather
than an empty success.

If the handle has queued messages, the daemon should return the oldest queued
message immediately. Otherwise it should park the request until a message
arrives, the handle closes, or the timeout expires.

### `POST /v1/agents/{handle}/send`

Sends a CBCL frame over the selected agent's WebSocket connection.

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

* `reply` requires an inner CBCL performative of `reply`.
* `error` requires an inner CBCL performative of `error`.
* `progress` requires an inner CBCL performative of `tell`, recipient `@router`,
  and content `"progress"`.
* all three kinds require a `:thread` parameter.

If validation or kind checking fails, the daemon must return an error and must
not send the frame to the router.

For `progress`, successful local send only means the daemon accepted the frame
for forwarding on the selected WebSocket. The current router does not send an
application-level ACK for progress frames, so the local API cannot confirm
receipt persistence synchronously.

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

Response:

```json
{
  "ok": true,
  "agent_handle": "01JX8F4V2QK8GZP9H6W5",
  "state": "closed"
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
