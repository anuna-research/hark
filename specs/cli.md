# CLI UX Contract

## Purpose

`cbcl-router-client` is a shell-friendly CLI for local agents. Commands should
compose with ordinary Unix-style tools and agent harnesses:

* machine-readable data goes to stdout
* diagnostics and validation errors go to stderr
* exit codes distinguish success from failure
* agent state is selected with environment variables

## Environment Variables

### `CBCL_AGENT_HANDLE`

Local daemon routing key for an ephemeral agent instance.

Commands that operate on an agent WebSocket connection require this variable
unless a future explicit `--handle` override is added.

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

Stdout:

* concise success message or nothing

Stderr:

* startup diagnostics
* already-running errors
* stale-state hints

Exit codes:

* `0` - daemon is running and reachable
* nonzero - daemon could not be started or stale daemon state blocks startup

### `daemon run`

Runs the daemon in the foreground. Intended for debugging and future
service-manager integration.

### `daemon status`

Shows daemon status and active agent handles.

Default output should be human-readable. A future `--json` flag may return the
raw local API status response.

### `daemon stop`

Asks the running daemon to shut down and exits after the daemon has stopped
responding to authenticated `ping`.

The daemon should close active agent WebSocket connections, remove
`daemon.json`, release `daemon.lock` by exiting, and then terminate.

Exit codes:

* `0` - daemon stopped or was not running
* nonzero - daemon was running but could not be stopped cleanly

### `init`

Creates a new ephemeral agent instance and prints shell exports.

Example:

```bash
cbcl-router-client daemon start

eval "$(cbcl-router-client init \
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
with a hint to run `cbcl-router-client daemon start`.

With `--json`, stdout:

```json
{
  "agent_handle": "01JX8F4V2QK8GZP9H6W5",
  "router_agent_id": "local-agent-01JX8F4V2QK8GZP9H6W5",
  "capabilities": ["code:edit", "code:test"],
  "state": "connected"
}
```

Useful options:

* `--capability <name>` - may be repeated.
* `--dialect <id>` - may be repeated.
* `--json` - print JSON instead of shell exports.

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
* closed/unhealthy handle errors
* timeout diagnostics

No prompt, prefix, or extra explanatory text should be printed to stdout.

Useful options:

* `--timeout <duration>` - fail if no message arrives before the timeout.

### `reply`, `error`, and `progress`

Read CBCL from stdin or an argument, validate it with `cbcl-rs`, check that the
message matches the selected command, and send it over the WebSocket connection
selected by `CBCL_AGENT_HANDLE`.

Examples:

```bash
cbcl-router-client reply < reply.cbcl
cbcl-router-client error '(lang elf (error @router "failed" :thread "rcp-..."))'
```

Command-specific message rules:

* `reply` accepts only CBCL whose inner performative is `reply`.
* `error` accepts only CBCL whose inner performative is `error`.
* `progress` accepts only CBCL whose inner performative is `tell` and whose
  recipient is `@router` and content is the string `"progress"`.
* all three commands require a `:thread` parameter so router receipt storage can
  correlate the message with a dispatched ask.

Example progress message:

```bash
cbcl-router-client progress \
  '(lang elf (tell @router "progress" :thread "rcp-..." :text "running tests"))'
```

Progress messages are non-terminal. A successful `progress` command means the
frame was accepted by the local daemon for forwarding; the current router does
not send an application-level ACK for progress frames. Agents should still send
a later `reply` or `error` for the same `:thread`.

Stdout:

* default: nothing
* with future `--json`: structured send result

Stderr:

* validation errors
* daemon discovery errors
* missing handle errors
* disconnected handle errors

Validation errors must not be sent to the router.

### `close`

Closes the WebSocket connection and removes daemon state for
`CBCL_AGENT_HANDLE`.

After `close`, commands using the same handle should fail with an unknown or
closed handle error.

## Optional Future Commands

These are not MVP agent-interface requirements:

```bash
cbcl-router-client submit
cbcl-router-client receipt
```

If added, they should be producer/debug commands and should not require
`CBCL_AGENT_HANDLE`.

## Exit Code Categories

Exact numeric codes can be finalized during implementation, but commands should
distinguish these categories:

* success
* daemon not running
* daemon already running
* stale daemon state
* missing `CBCL_AGENT_HANDLE`
* unknown or closed handle
* CBCL validation failure
* router connection/auth failure
* timeout
* internal error

## Output Discipline

Commands intended for command substitution or `eval` must keep stdout clean:

* `init` default stdout contains only shell exports.
* `init --json` stdout contains only JSON.
* `recv` stdout contains only the CBCL message.
* validation and daemon diagnostics go to stderr.

This is required for composition with shells and agent harnesses.
