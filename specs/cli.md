# CLI UX Contract

## Purpose

`hark` is a shell-friendly CLI for local agents. Commands should
compose with ordinary Unix-style tools and agent harnesses:

* machine-readable data goes to stdout
* diagnostics and validation errors go to stderr
* exit codes distinguish success from failure
* agent state is selected with environment variables

## Environment Variables

### `CBCL_AGENT_HANDLE`

Local daemon routing key for an ephemeral agent instance.

Commands that operate on an agent WebSocket connection require this variable
for the MVP.

Required by:

* `recv`
* `reply`
* `error`
* `progress`
* `close`

No daemon address or daemon-token environment variable is exported. Commands
discover the local daemon address and token together from `daemon.json` as
described in [`daemon.md`](daemon.md). This keeps service discovery in one
place and avoids exposing the local daemon token through shell environment
inheritance.

## Commands

### `daemon start`

Starts the per-user daemon in the background and exits once the daemon responds
to authenticated `ping`.

This command is local-only. It must not open a router WebSocket, send a router
`hello`, or fail merely because router URL or router authentication
configuration is missing. Router configuration errors surface when `init`
attempts to create an agent instance.

Stdout:

* concise success message or nothing

Stderr:

* startup diagnostics
* stale-state hints

Exit codes:

* `0` - daemon is running and reachable, including when it was already running
* nonzero - daemon could not be started or stale daemon state blocks startup

### `daemon run`

Runs the daemon in the foreground. Intended for debugging and future
service-manager integration.

Unlike `daemon start`, `daemon run` treats an already-running daemon as an
error because it is the long-lived daemon process, not the idempotent launcher.

### `daemon status`

Shows daemon status and active agent handles.

Default output should be human-readable.

Status should distinguish these cases:

* live daemon: print daemon address, version, active handles, connection states,
  capabilities, and queue sizes; exit `0`.
* no `daemon.json`: print that the daemon is not running; exit `3`.
* stale `daemon.json` with free lock: print stale discovery details and say that
  `daemon start` or `daemon stop` can clean it; exit `5`.
* stale `daemon.json` with held lock: print that discovery is stale but the
  singleton lock is still held; exit `5`.
* daemon responds but local authentication fails: print a fail-closed diagnostic;
  exit `11`.
* daemon local API version is incompatible with the CLI: print the CLI API
  version, daemon API version if available, daemon binary version if available,
  and a restart hint; exit `12`.

### `daemon stop`

Asks the running daemon to shut down and exits after the daemon has stopped
responding to authenticated `ping`.

The daemon should close active agent WebSocket connections, remove
`daemon.json`, release `daemon.lock` by exiting, and then terminate.

Exit codes:

* `0` - daemon stopped, was not running, or stale discovery state was cleaned
* nonzero - daemon was running but could not be stopped cleanly

### `init`

Creates a new ephemeral agent instance and prints shell exports.

This is the command that asks the daemon to open a router WebSocket for the new
agent. If router URL or router authentication configuration is missing or
rejected, `init` fails and no handle is printed.

Example:

```bash
hark daemon start

eval "$(hark init \
  --capability code:edit \
  --capability code:test)"
```

Default stdout:

```bash
export CBCL_AGENT_HANDLE='01JX8F4V2QK8GZP9H6W5'
```

No non-export diagnostics should be printed to stdout in default mode, because
callers may pass the output directly to `eval`.

`init` requires the daemon to already be running. It must not auto-start the
daemon. If discovery fails because `daemon.json` is missing, `init` should fail
with a hint to run `hark daemon start`.

With `--json`, stdout:

```json
{
  "agent_handle": "01JX8F4V2QK8GZP9H6W5",
  "router_agent_id": "local-agent-01JX8F4V2QK8GZP9H6W5",
  "capabilities": ["code:edit", "code:test"],
  "dialects": [],
  "state": "connected"
}
```

Useful options:

* `--capability <name>` - required at least once; may be repeated.
* `--dialect <id>` - may be repeated.
* `--json` - print JSON instead of shell exports.

An agent must advertise at least one capability. Capabilities are per-agent,
not daemon-level defaults. If no `--capability` value is supplied, `init` fails
with a usage error and does not call the daemon.

The CLI should reject duplicate capability values and duplicate dialect values
before calling the daemon. Preserving the user-supplied order in successful
requests is useful for predictable status output, but duplicate advertisements
do not add information and make tests and diagnostics noisier.

### `recv`

Blocks until a CBCL message is available for `CBCL_AGENT_HANDLE`, prints the
message to stdout, and exits.

Stdout:

```text
(lang elf (ask @router "echo" :thread "rcp-..."))
```

Stderr:

* daemon discovery errors
* missing handle errors
* unknown/unhealthy handle errors
* timeout diagnostics

No prompt, prefix, or extra explanatory text should be printed to stdout.

Useful options:

* `--timeout <duration>` - fail if no message arrives before the timeout.

Without `--timeout`, `recv` blocks until a message arrives, the selected handle
is removed or becomes unhealthy, the daemon stops, or the local HTTP request
fails.
Durations use a simple unit suffix: `ms`, `s`, `m`, or `h`. The CLI converts the
duration to `timeout_ms` for the local API and rejects zero or negative values.
The maximum finite timeout is `2160h` (90 days). This supports agents that wait
for work for days or weeks while still rejecting values likely to overflow
local timers. Omitting `--timeout` means no finite client-side timeout.

### `reply`, `error`, and `progress`

`reply` and `error` read CBCL from stdin or an argument, validate it with
`cbcl-rs`, check that the message matches the selected command, and send it
over the WebSocket connection selected by `CBCL_AGENT_HANDLE`.

MVP input rules:

* `reply [MESSAGE]` and `error [MESSAGE]` accept at most one positional CBCL
  message argument.
* If the positional argument is present, the command uses it as the complete
  CBCL message and does not read stdin.
* If the positional argument is absent, the command reads the complete CBCL
  message from stdin until EOF.
* If the positional argument is absent and stdin is an interactive TTY, the
  command fails with a usage error instead of waiting silently.
* `--file` is not part of the MVP; callers can use shell redirection instead.

`progress` builds a CBCL progress message from flags, validates the generated
message with `cbcl-rs`, and sends it over the same handle-selected WebSocket
path.

Examples:

```bash
hark reply < reply.cbcl
hark error '(lang elf (error @router "failed" :thread "rcp-..."))'
hark progress --thread rcp-... --text "running tests"
```

Command-specific message rules:

* `reply` accepts only CBCL whose performative, after unwrapping any `(lang ...)`
  dialect wrapper, is `reply`.
* `error` accepts only CBCL whose performative, after unwrapping any `(lang ...)`
  dialect wrapper, is `error`.
* `progress` builds a CBCL message whose performative, after unwrapping the
  generated `(lang ...)` dialect wrapper, is `tell`, recipient is `@router`, and
  content is the string `"progress"`.
* all sent messages require a `:thread` parameter so router receipt storage can
  correlate the message with a dispatched ask.

Thread validation is deliberately stricter than the current router fallback
behavior. After unwrapping any `(lang ...)` dialect wrapper, the inner message
must contain exactly one `:thread` parameter, and that value must be a non-empty
CBCL string. Missing, empty, non-string, or duplicate `:thread` values are
validation failures and must not be sent to the router.

Bare CBCL messages and dialect-wrapped CBCL messages are both accepted for
`reply` and `error` as long as they pass `cbcl-rs` validation and the unwrapped
performative matches the command.

Useful `progress` options:

* `--thread <receipt-id>` - required.
* `--text <text>` - optional human-readable progress detail.
* `--dialect <id>` - optional dialect wrapper; defaults to `elf`.

The generated progress frame is still validated with `cbcl-rs` before it is
sent to the daemon.

`progress` always generates a dialect-wrapped message:

```text
(lang <dialect> (tell @router "progress" :thread "<receipt-id>"))
```

If `--text <text>` is supplied, `progress` includes exactly one additional
`:text` parameter:

```text
(lang <dialect> (tell @router "progress" :thread "<receipt-id>" :text "<text>"))
```

Progress messages are non-terminal. A successful `progress` command means the
daemon validated the generated CBCL and successfully wrote the frame to the
selected WebSocket. The current router does not send an application-level ACK
for progress frames, so success does not prove receipt persistence. Agents
should still send a later `reply` or `error` for the same `:thread`.

Stdout:

* default: nothing

Stderr:

* validation errors
* daemon discovery errors
* missing handle errors
* disconnected handle errors

Validation errors must not be sent to the router.

### `close`

Closes the WebSocket connection and removes daemon state for
`CBCL_AGENT_HANDLE`.

After `close`, commands using the same handle should fail with an unknown handle
error.

Stdout:

* default: nothing

Stderr:

* daemon discovery errors
* missing handle errors
* unknown handle errors
* malformed handle errors

Exit codes:

* `0` - handle was closed and removed
* `6` - `CBCL_AGENT_HANDLE` is missing
* `7` - handle is unknown
* `2` - handle value is malformed

Closing an unhealthy handle should succeed if the daemon can remove local state.
The command is primarily cleanup; it should not require the router WebSocket to
still be healthy.

## Exit Codes

The MVP CLI should use stable numeric exit codes so shell harnesses can branch
on common failure modes:

* `0` - success
* `2` - command-line usage error or malformed local request
* `3` - daemon not running
* `4` - daemon already running when invoking non-idempotent foreground
  `daemon run`
* `5` - stale daemon state
* `6` - missing `CBCL_AGENT_HANDLE`
* `7` - unknown, unhealthy, or busy agent handle
* `8` - CBCL validation or command-kind validation failure
* `9` - router connection or router authentication failure
* `10` - timeout
* `11` - local daemon authentication failure
* `12` - daemon local API incompatibility or internal error

When exit code `12` is caused by daemon API incompatibility, stderr must include
the stable error code `daemon_api_incompatible` so callers can distinguish it
from an unexpected internal error.

Commands may include more specific machine-readable error codes in local API
responses, but process exit codes should map to the categories above.

## Output Discipline

Commands intended for command substitution or `eval` must keep stdout clean:

* `init` default stdout contains only shell exports.
* `init --json` stdout contains only JSON.
* `recv` stdout contains only the CBCL message.
* validation and daemon diagnostics go to stderr.

This is required for composition with shells and agent harnesses.
