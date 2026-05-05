# cbcl-router-client

This project defines a focused Rust CLI for agents that communicate through
`cbcl-lfe-router`.

The client is responsible for local agent ergonomics: starting a per-user
daemon, opening router WebSocket connections for local agent instances,
advertising capabilities, validating CBCL with `cbcl-rs`, and providing
shell-friendly commands for receiving work and sending replies.

## Related Projects

* `cbcl-lfe-router` - the capability-based router this client connects to.
* `cbcl-rs` - the Rust implementation of the CBCL language, used for local
  parsing and validation before messages are sent to the router.

## Design Specs

* [Daemon singleton and discovery](specs/daemon.md)
* [Local daemon API](specs/local-api.md)
* [Router protocol mapping](specs/router-protocol.md)
* [CLI UX contract](specs/cli.md)
* [Configuration and authentication](specs/config.md)

## Model

The client runs one daemon per OS user. The daemon listens on loopback TCP for
local CLI invocations and manages any number of agent instances.

Each agent instance has:

* one daemon-minted local handle
* one persistent WebSocket connection to `/agent/v1`
* one router-visible `agent-id`, derived from the handle
* one capability advertisement sent in the WebSocket `hello`
* one inbound queue for dispatched CBCL messages

The local handle is exported into the agent's shell environment:

```bash
cbcl-router-client daemon start

eval "$(cbcl-router-client init \
  --capability code:edit \
  --capability code:test)"
```

The command prints shell exports similar to:

```bash
export CBCL_AGENT_HANDLE='01JX8F4V2QK8GZP9H6W5'
```

Subsequent commands use `CBCL_AGENT_HANDLE` to select the correct daemon-managed
WebSocket connection:

```bash
cbcl-router-client recv
cbcl-router-client reply < reply.cbcl
cbcl-router-client close
```

For non-shell harnesses, `init --json` returns the same information as JSON.

`init` does not auto-start the daemon. If the daemon is not running, `init`
fails with a hint to run `cbcl-router-client daemon start`.

## Command Shape

### `daemon start`

Starts the per-user daemon if it is not already running. The daemon owns router
connections and local queues. It should bind only to loopback TCP and require
local clients to present a daemon token or equivalent local credential.

Users must start the daemon before creating agent instances.

### `daemon status`

Show daemon state, including active handles, router agent ids, capabilities,
connection state, and queued message counts.

### `daemon stop`

Ask the running daemon to close active WebSocket connections, remove its
discovery record, and exit.

### `init`

Creates a new ephemeral agent instance.

`init` opens a WebSocket connection to the router, sends a CBCL `hello` frame
with the requested capabilities, stores the connection under a daemon-minted
handle, and prints environment exports for later commands.

Useful options:

* `--capability <name>` - may be repeated.
* `--dialect <id>` - may be repeated when the agent wants to advertise known
  dialects.
* `--json` - print machine-readable JSON instead of shell exports.

### `recv`

Blocks until a message is available for the current `CBCL_AGENT_HANDLE`, prints
the CBCL message to stdout, and exits.

This is intended to compose with existing agent harnesses:

```bash
task="$(cbcl-router-client recv)"
```

### `reply`, `error`, and `progress`

Validate CBCL with `cbcl-rs`, then send it over the WebSocket connection
associated with the current `CBCL_AGENT_HANDLE`.

`reply` must send a CBCL `reply` message and `error` must send a CBCL `error`
message. `progress` is a convenience command that builds and sends a CBCL
`tell @router "progress"` message from command-line flags. All sent messages
must include the `:thread` value from the dispatched ask so the router can
append them to the same receipt.

Progress is non-terminal: it records an intermediate receipt entry but does not
complete the dispatched ask. Agents should still send a later `reply` or
`error` for the same `:thread`.

### `close`

Close the WebSocket connection and remove daemon state for the current
`CBCL_AGENT_HANDLE`.

## Configuration

Configuration uses the Rust `config` and `dirs` crates for cross-platform
defaults. The daemon loads configuration at startup. Users should restart the
daemon after changing config files or relevant environment variables.

Expected config values include:

* router WebSocket address
* router authentication material
* local daemon bind preferences
* default capabilities and dialects

Capabilities can be supplied from config or directly to `init`. Direct command
line values should override configured defaults for that `init` request.

## Validation

Before forwarding messages, both the CLI command and the daemon should use
`cbcl-rs` to parse and validate CBCL locally. This gives agents fast, precise
feedback when a message is malformed or violates known CBCL constraints, instead
of relying only on router-side rejection.

The router remains authoritative. Local validation is an ergonomics and safety
layer, not a substitute for router validation.

## Agent Skill Definition

The repository should include a Markdown skill definition describing the CLI
workflow for agents. The skill should defer to the CLI's built-in help for
exact flags and examples where possible, so the skill remains stable as the CLI
evolves.
