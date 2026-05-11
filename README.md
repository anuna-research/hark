# hark

<img src="https://imagedelivery.net/O-SJhBv1S1zUZFvTxrBOhQ/d9aa7f21-ff82-4b9d-069a-c6b08aedf700/smalllogo" alt="hark logo" width="120">

`hark` is a Rust CLI and local per-user daemon for agents that
communicate through `cbcl-router`.

The daemon owns router WebSocket connections and local inbound queues. Short
CLI invocations discover the daemon over loopback HTTP, authenticate with the
local daemon token from `daemon.json`, and operate on an agent connection
selected by `CBCL_AGENT_HANDLE`.

## Related Projects

* `cbcl-router` - the dialect-based router this client connects to.
* `cbcl-rs` - the Rust CBCL parser and validation implementation used locally
  before outbound messages are sent to the router.

## Build

From this directory:

```bash
cargo build
cargo test
```

During development, commands can be run with:

```bash
cargo run -- daemon status
```

After installing or copying the binary onto `PATH`, use:

```bash
hark --help
```

## Configuration

Configuration is loaded in this order:

1. built-in defaults
2. platform config file
3. environment variables

Recommended config file locations:

```text
Linux:   ~/.config/hark/config.toml
macOS:   ~/Library/Application Support/hark/config.toml
Windows: %APPDATA%\hark\config.toml
```

Discover the exact path for the current machine:

```bash
hark config path
```

Print a sample config:

```bash
hark config show-example
```

Create the config file if it does not already exist:

```bash
hark config init
$EDITOR "$(hark config path)"
```

Example config:

```toml
[router]
ws_url = "wss://cbcl-lfe.anuna.io/agent/v1"
auth_token = "shr_prod-agent.REPLACE_ME"

[agent]
agent_id_prefix = "local-agent"

[daemon]
bind = "127.0.0.1:0"
max_messages_per_handle = 1000
max_bytes_per_handle = 67108864
overflow_policy = "reject_new_and_close"
```

Environment overrides:

```bash
export CBCL_ROUTER_WS='wss://cbcl-lfe.anuna.io/agent/v1'
export CBCL_ROUTER_AUTH_TOKEN='shr_key-id.REPLACE_ME'
export CBCL_AGENT_ID_PREFIX='local-agent'
export CBCL_DAEMON_BIND='127.0.0.1:0'
export CBCL_DAEMON_MAX_MESSAGES_PER_HANDLE='1000'
export CBCL_DAEMON_MAX_BYTES_PER_HANDLE='67108864'
export CBCL_DAEMON_OVERFLOW_POLICY='reject_new_and_close'
```

Daemon startup is local-only. `daemon start` does not require router URL or
router auth, and it does not open a router WebSocket. Router configuration is
validated lazily when `init` creates an agent instance.

Restart the daemon after changing config files or environment variables.

## Workflow

Start the local daemon:

```bash
hark daemon start
```

Create an agent connection and export its local handle:

```bash
eval "$(hark init \
  --dialect elf)"
```

Default `init` output is suitable for `eval`:

```bash
export CBCL_AGENT_HANDLE='0123456789ABCDEFGHJKMNPQRS'
```

For non-shell harnesses:

```bash
hark init --dialect elf --json
```

Receive dispatched work:

```bash
task="$(hark recv)"
task="$(hark recv --timeout 30s)"
```

Timeout units are `ms`, `s`, `m`, and `h`; the maximum finite timeout is
`2160h`.

Send progress and a terminal reply:

```bash
hark progress --thread rcp-123 --text "running tests"
hark reply '(lang elf (reply "done" :thread "rcp-123"))'
```

Send an error:

```bash
hark error '(lang elf (error "failed" :thread "rcp-123"))'
```

`reply` and `error` accept one positional CBCL message or read the complete
message from stdin:

```bash
hark reply < reply.cbcl
```

Close the current agent handle and stop the daemon:

```bash
hark close
hark daemon stop
```

## Commands

### `config path`

Prints the platform-specific config file path.

### `config show-example`

Prints an example `config.toml` to stdout.

### `config init`

Creates the config file with an example config if it does not already exist.
It refuses to overwrite an existing config file.

### `daemon start`

Starts the per-user daemon if needed and exits after authenticated local
`ping` succeeds. This command is idempotent and does not contact the router.

### `daemon run`

Runs the daemon in the foreground. It fails if another daemon already holds the
singleton lock.

### `daemon status`

Prints daemon state and active agent handles in a human-readable format.

### `daemon stop`

Requests daemon shutdown, removes `daemon.json`, closes active router
connections, and waits until the daemon stops responding.

### `init`

Creates one ephemeral agent instance. `--dialect` is required at least once and
is repeatable. Duplicate dialects are rejected before the daemon is called.

### `recv`

Requires `CBCL_AGENT_HANDLE`. Blocks until one CBCL message is available, then
prints only that message to stdout.

### `reply`, `error`, and `progress`

Require `CBCL_AGENT_HANDLE`. The CLI validates CBCL locally, the daemon
validates again, and the daemon returns success only after the frame is written
to the selected router WebSocket.

Validation rules:

* `reply` requires an unwrapped CBCL `reply` performative.
* `error` requires an unwrapped CBCL `error` performative.
* `progress` builds a `(lang <dialect> (tell @router "progress" ...))` message.
* all outbound messages require exactly one non-empty string `:thread`.

### `close`

Requires `CBCL_AGENT_HANDLE`. Removes the local handle and closes the selected
router WebSocket. Successful `close` prints nothing.

## Exit Codes

| Code | Meaning |
| ---: | --- |
| 0 | success |
| 2 | usage error or malformed local request |
| 3 | daemon not running |
| 4 | daemon already running for foreground `daemon run` |
| 5 | stale daemon discovery state |
| 6 | `CBCL_AGENT_HANDLE` is missing |
| 7 | agent handle is unknown, unhealthy, or busy |
| 8 | CBCL validation or command-kind validation failed |
| 9 | router configuration, connection, or authentication failure |
| 10 | timeout |
| 11 | local daemon authentication failed |
| 12 | daemon API incompatibility or unexpected internal error |

## Local API Error Codes

The daemon returns stable JSON errors on its loopback API. Common codes include:

* `missing_daemon_token`, `invalid_daemon_token`
* `daemon_api_incompatible`
* `missing_router_ws_url`, `invalid_router_ws_url`,
  `missing_router_auth_token`
* `router_auth_rejected`, `router_connection_failed`
* `missing_dialect`, `duplicate_dialect`, `invalid_dialect`
* `malformed_agent_handle`, `unknown_agent_handle`,
  `agent_handle_unhealthy`
* `recv_already_waiting`, `recv_timeout`, `daemon_stopping`
* `cbcl_validation_failed`, `message_kind_mismatch`, `missing_thread`,
  `duplicate_thread`, `invalid_thread`
* `internal_error`

See [Local daemon API](specs/local-api.md) and [CLI UX contract](specs/cli.md)
for the detailed contract.

## Troubleshooting

`daemon_not_running` or exit code `3`:

```bash
hark daemon start
```

Stale daemon state or exit code `5`:

```bash
hark daemon stop
hark daemon start
```

Router config errors during `init`:

```bash
hark config init
$EDITOR "$(hark config path)"
```

Or set environment overrides:

```bash
export CBCL_ROUTER_WS='wss://cbcl-lfe.anuna.io/agent/v1'
export CBCL_ROUTER_AUTH_TOKEN='shr_prod-agent.REPLACE_ME'
hark daemon stop
hark daemon start
```

`router_auth_rejected`:

Check that `CBCL_ROUTER_AUTH_TOKEN` or `[router].auth_token` is current and
belongs to the expected router environment.

Missing dialects:

```bash
hark init --dialect elf
```

Unhealthy handles:

Run `hark daemon status` to see active handles. Then create a
fresh handle with `init`, or remove the unhealthy one:

```bash
hark close
eval "$(hark init --dialect elf)"
```

CBCL validation failures:

Ensure the outbound message is valid CBCL, matches the command kind, and has
exactly one non-empty string `:thread`.

## Specs

* [Daemon singleton and discovery](specs/daemon.md)
* [Local daemon API](specs/local-api.md)
* [Router protocol mapping](specs/router-protocol.md)
* [CLI UX contract](specs/cli.md)
* [Configuration and authentication](specs/config.md)
