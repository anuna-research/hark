# Daemon Singleton and Discovery

## Purpose

`cbcl-router-client` runs one daemon per OS user. The daemon owns local agent
instances, the router WebSocket connections created for those instances, and
per-agent inbound queues.

CLI commands such as `init`, `recv`, `reply`, `daemon status`, and `close` need
a reliable way to discover the daemon and fail clearly when no daemon is
running. The daemon lifecycle also needs to prevent a second live daemon for the
same user.

This spec defines the singleton and discovery mechanism.

## Runtime Directory

The client stores daemon runtime state in a per-user runtime directory:

```text
runtime-dir/
  daemon.lock
  daemon.json
```

Recommended locations:

```text
Linux:   $XDG_RUNTIME_DIR/cbcl-router-client/
         fallback: ~/.local/state/cbcl-router-client/runtime/

macOS:   ~/Library/Application Support/cbcl-router-client/runtime/

Windows: %LOCALAPPDATA%\cbcl-router-client\runtime\
```

The implementation should use `directories` or `dirs` to select platform
locations and should create the directory with user-only permissions where the
platform supports that.

On Unix-like systems, the runtime directory must be created with mode `0700`
or stricter, and `daemon.json` must be created with mode `0600` or stricter.
If existing runtime state is readable or writable by other users, commands
should fail closed with a diagnostic rather than trusting the local daemon
token. Equivalent owner-only protections should be used on platforms that
support ACLs rather than Unix modes.

On Unix-like systems, commands must also reject runtime directories,
`daemon.json`, or `daemon.lock` that are symlinks, not owned by the current user,
or otherwise fail owner-only checks. The local daemon token is a bearer
credential, so discovery files should be treated as sensitive local secrets.

## Files

### `daemon.lock`

`daemon.lock` is the singleton authority.

The daemon opens this file and acquires an exclusive non-blocking OS file lock
before it starts listening. The daemon must keep the lock file handle open for
its entire lifetime. If the daemon exits or crashes, the operating system
releases the lock.

Suggested Rust crates:

* `fs2`
* `fd-lock`

The implementation must not rely on PID checks as the primary singleton
mechanism. PIDs are reusable and cross-platform process probing is unreliable.

### `daemon.json`

`daemon.json` is the client discovery record.

Example:

```json
{
  "pid": 12345,
  "addr": "127.0.0.1:49152",
  "token": "base64url-random-32-bytes",
  "started_at": "2026-05-05T12:34:56Z",
  "version": "0.1.0",
  "api_version": 1
}
```

Fields:

* `pid` - informational only; not authoritative for singleton detection.
* `addr` - loopback TCP address where the daemon accepts local client requests.
* `token` - random local authentication secret for CLI-to-daemon requests.
* `started_at` - timestamp for diagnostics.
* `version` - daemon binary version for diagnostics and compatibility checks.
* `api_version` - local API major version supported by the daemon.

The token should contain at least 32 bytes of randomness, encoded with base64url
or another shell-safe representation.

The CLI is compatible with the daemon only when `api_version` matches the CLI's
compiled local API version. Binary `version` is diagnostic under a matching API
version. If `api_version` is absent or different, the CLI should fail with exit
code `12`, include the stable error code `daemon_api_incompatible`, and suggest
restarting the daemon.

## Daemon Startup

`daemon start` is an adb-style command: it starts a background daemon and then
returns after the daemon is reachable on the local loopback API. Users should
not need to append `&` or manage process detachment themselves.

Daemon startup is local-only. A newly started daemon with no agent instances
must not open a router WebSocket, send a router `hello`, or require router URL
or router authentication configuration. Router communication begins only when a
local `init` request creates an agent instance.

The CLI should expose two daemon execution modes:

```bash
cbcl-router-client daemon start   # detached/background startup
cbcl-router-client daemon run     # foreground daemon for debugging or service managers
```

`daemon start` should:

1. Resolve and create the runtime directory.
2. Check whether a daemon is already discoverable.
   * if authenticated `ping` succeeds, exit successfully; `daemon start` is
     idempotent
   * if discovery state exists but `ping` fails, probe `daemon.lock` before
     deciding whether stale discovery state can be replaced
3. Spawn the same binary in foreground daemon mode, for example
   `cbcl-router-client daemon run --internal`.
4. Detach the child process from the terminal as far as the platform reasonably
   supports.
5. Poll `daemon.json` and authenticated `ping` until the daemon is reachable or
   startup times out.
6. Exit successfully only after the daemon is ready.

The default startup timeout should be 10 seconds. Implementations may expose a
debug/service-manager override later, but the MVP `daemon start` command should
not wait indefinitely for a child that failed before writing usable discovery
state.

If stale `daemon.json` exists, `daemon start` should use the file lock only as
a short-lived probe:

1. Try to acquire `daemon.lock`.
2. If acquisition fails, report stale state with a held lock and do not remove
   files.
3. If acquisition succeeds, remove stale `daemon.json`, then release the lock
   before spawning `daemon run`.
4. Let the spawned `daemon run` process acquire and hold `daemon.lock` for the
   actual daemon lifetime.

The parent `daemon start` process must not keep `daemon.lock` across the child
daemon's startup. This avoids a parent-child lock handoff and keeps
`daemon.lock` as the sole live-daemon authority. If another process starts a
daemon in the small window between the probe release and child acquisition,
the child should fail with "daemon already running" and the parent should treat
the now-responsive daemon as success after authenticated `ping`.

`daemon run` should:

1. Resolve and create the runtime directory.
2. Open `daemon.lock`.
3. Try to acquire an exclusive non-blocking lock.
4. If the lock is acquired:
   * bind a loopback TCP listener
   * generate a new local auth token
   * write `daemon.json` atomically
   * keep the lock handle open while serving requests
5. If the lock is not acquired:
   * read `daemon.json` if present
   * send an authenticated `ping` request to the recorded `addr`
   * if `ping` succeeds, exit with a descriptive "daemon already running" error
   * if `ping` fails, report stale daemon state and suggest manual cleanup

The daemon should bind only to loopback addresses. It must not listen on a
public interface.

`daemon run` has the same local-only startup contract as `daemon start`. It may
load router configuration for later use, but it must not validate router
reachability or open router connections until handling an agent-creation
request.

`daemon run` is not idempotent. If it cannot acquire `daemon.lock` and an
authenticated `ping` to the recorded daemon succeeds, it should fail with a
"daemon already running" diagnostic. The idempotent behavior belongs to
`daemon start`, which is the user-facing launcher.

Process detachment is necessarily platform-specific:

* Unix and macOS: redirect stdio to null or log files and create a new session
  where practical.
* Windows: redirect stdio and use process creation flags such as a detached
  process or new process group.

This project only requires best-effort detachment for a developer CLI. Strong
login-session survival should be handled later through optional service-manager
integration.

## Client Discovery

All commands that need the daemon should:

1. Resolve the runtime directory.
2. Read `daemon.json`.
3. Connect to `addr`.
4. Authenticate with `token`.
5. Send a lightweight `ping` or the requested command.

If `daemon.json` is missing, the command should fail with:

```text
error: cbcl-router-client daemon is not running
hint: run `cbcl-router-client daemon start`
```

If `daemon.json` exists but no daemon responds at `addr`, the command should
fail with:

```text
error: daemon state exists but no daemon responded at 127.0.0.1:49152
hint: run `cbcl-router-client daemon status`; if stale, `cbcl-router-client daemon start` can replace it when the lock is free
```

If the daemon responds but authentication fails, the command should fail closed
and should not attempt to remove state automatically.

`daemon status` should use the same discovery checks, but it should be useful
even when discovery is broken:

* If `daemon.json` is missing, report that the daemon is not running.
* If `daemon.json` exists and authenticated `ping` succeeds, report live daemon
  and agent status.
* If `daemon.json` exists but no daemon responds, probe `daemon.lock` without
  removing files and report whether stale state appears cleanable.
* If the daemon responds but authentication fails, report a fail-closed local
  authentication error and do not remove files.

## Stale State

Stale state means `daemon.json` exists, but the recorded daemon does not respond
to authenticated loopback requests.

The client should provide:

```bash
cbcl-router-client daemon status
cbcl-router-client daemon stop
```

`daemon start` may remove stale `daemon.json` only during the short-lived lock
probe described in "Daemon Startup". If the lock is still held, startup must
fail because another daemon process or lock owner may still be alive.

`daemon stop` uses the same authenticated discovery flow as other local
commands. For a responsive daemon, `daemon stop` closes active agent WebSocket
connections, removes `daemon.json`, releases `daemon.lock` by exiting, and then
terminates. If no daemon responds but `daemon stop` can acquire `daemon.lock`,
it may remove stale `daemon.json` and then exit successfully. If the lock is
held and no daemon responds, `daemon stop` should fail with a stale-state
diagnostic rather than removing files blindly.

After a responsive daemon accepts a stop request, the `daemon stop` CLI should
treat shutdown as successful once `daemon.json` has been removed, the recorded
local address refuses connections or no longer accepts HTTP, or authenticated
`ping` no longer succeeds. This avoids depending on one exact ordering between
the stop response, discovery-file deletion, listener shutdown, and process exit.

## Local Protocol

The daemon's local protocol should include at least:

* `ping` - proves liveness and token validity.
* `init` - creates an ephemeral agent instance, opens that instance's router
  WebSocket, and returns an agent handle.
* `recv` - blocks until the selected agent handle has an inbound message.
* `send` - sends a validated CBCL frame over the selected agent handle's WebSocket
  connection.
* `status` - returns daemon state, active handles, connection states, and queue
  lengths.
* `close` - closes the WebSocket connection and removes state for an agent
  handle.
* `stop` - closes all WebSocket connections, removes `daemon.json`, and exits.

The wire format can be JSON over HTTP on loopback TCP for the first
implementation. The daemon token should be sent in an authorization header or
equivalent request field on every request.

## Message Buffering

The daemon buffers inbound router messages per agent handle. A message may
arrive while no local process is currently blocked in `recv`; in that case the
daemon should enqueue it for the next `recv` call.

Initial buffering should be in-memory only. Agent instances are ephemeral, and
the first version does not need to preserve queued messages across daemon
restarts.

Queues must be bounded. Recommended defaults:

```text
max_messages_per_handle = 1000
max_bytes_per_handle    = 64 MiB
overflow_policy         = reject_new_and_close
```

The daemon should drain each handle's queue in FIFO order.

When a queue reaches its configured limit, the daemon should not silently drop
old messages. Because the router has already delivered the WebSocket frame by
the time the local daemon observes the overflow, this is not a router-visible
rejection. The default overflow behavior should be:

1. do not enqueue the newly arrived frame
2. mark the handle unhealthy with an overflow reason
3. close that handle's WebSocket connection to the router
4. expose the unhealthy state through `daemon status`

Closing the WebSocket is the current backpressure signal. The router already
treats disconnected agent WebSocket processes as unavailable for further
routing.

Future versions may add other policies, such as durable queues or
`drop_oldest`, but those should be explicit opt-ins. Silent loss is not an
acceptable default for task dispatch.

## Agent Handles

`init` creates one daemon-managed agent instance. This is the operation that
turns a local daemon process into a router-visible agent:

```bash
eval "$(cbcl-router-client init \
  --capability code:edit \
  --capability code:test)"
```

Shell output:

```bash
export CBCL_AGENT_HANDLE='01JX8F4V2QK8GZP9H6W5'
```

JSON output:

```bash
cbcl-router-client init --json --capability code:edit
```

```json
{
  "agent_handle": "01JX8F4V2QK8GZP9H6W5",
  "router_agent_id": "local-agent-01JX8F4V2QK8GZP9H6W5",
  "capabilities": ["code:edit"],
  "state": "connected"
}
```

The handle is a local daemon routing key. The daemon maps it to:

```text
handle -> router agent-id -> WebSocket connection -> inbound queue
```

No such mapping exists immediately after `daemon start`. A daemon with no
agent handles has no router-visible identity and no router WebSocket
connections.

Agent handles should be generated as ULIDs or as an equivalent 128-bit random
identifier encoded in Crockford base32. The MVP handle grammar is exactly 26
characters matching `[0-9A-HJKMNP-TV-Z]{26}`. Handles are local-only, shell-safe,
and URL-path-safe.

The router-visible `agent-id` may be derived from the handle, for example:

```text
local-agent-01JX8F4V2QK8GZP9H6W5
```

Commands such as `recv`, `reply`, `error`, `progress`, and `close` should
select the agent instance from `CBCL_AGENT_HANDLE`.

An agent instance must advertise at least one capability. Capabilities are
per-agent and are supplied by that agent's `init` request. The daemon has no
daemon-level capability defaults. The CLI should reject `init` requests with no
`--capability` value before calling the daemon, and the daemon should reject
local API requests whose `capabilities` list is empty.

## Error Handling Principles

Errors should be descriptive and action-oriented:

* missing daemon: tell the user to run `daemon start`
* live daemon already running: include the daemon address
* stale state: suggest `daemon status` and manual cleanup
* missing `CBCL_AGENT_HANDLE`: suggest running `eval "$(cbcl-router-client init ...)"`
* unknown handle: suggest `daemon status` to list active handles
* local auth failure: fail closed and avoid automatic cleanup

## Non-Goals

This spec does not require:

* OS service manager integration
* Unix domain sockets or Windows named pipes
* automatic daemon startup from `init`
* automatic stale-state replacement
* daemon clustering
* durable persistence of agent instances across daemon restarts

Those can be added later without changing the core singleton/discovery model.

Future service-manager integrations may include systemd user services, launchd
agents, or Windows service/startup-task support. Those integrations should wrap
`daemon run`; they are not required for the first implementation.
