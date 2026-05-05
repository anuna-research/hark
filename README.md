# cbcl-lfe-router-client

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
eval "$(cbcl-router-client init \
  --capability code:edit \
  --capability code:test)"
```

The command prints shell exports similar to:

```bash
export CBCL_AGENT_HANDLE='01JX8F4V2QK8GZP9H6W5'
export CBCL_ROUTER_CLIENT='http://127.0.0.1:49152'
```

Subsequent commands use `CBCL_AGENT_HANDLE` to select the correct daemon-managed
WebSocket connection:

```bash
cbcl-router-client recv
cbcl-router-client reply < reply.cbcl
cbcl-router-client close
```

For non-shell harnesses, `init --json` returns the same information as JSON.

## Command Shape

### `daemon start`

Starts the per-user daemon if it is not already running. The daemon owns router
connections and local queues. It should bind only to loopback TCP and require
local clients to present a daemon token or equivalent local credential.

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

Validate a CBCL message with `cbcl-rs`, then send it over the WebSocket
connection associated with the current `CBCL_AGENT_HANDLE`.

Terminal messages such as `reply` and `error` should preserve the `:thread`
value from the dispatched ask so the router can append them to the same receipt.

### `submit`

Submit a new CBCL ask to the router's HTTP ingress endpoint. This is the
producer path, distinct from agent replies over WebSocket.

`submit` validates the CBCL message with `cbcl-rs`, posts it to
`/ingress/v1/messages`, and prints the router response containing the receipt
id and dispatch status.

### `receipt`

Fetch a receipt from the router and print the newline-delimited CBCL message
sequence.

### `status`

Show daemon state, including active handles, router agent ids, capabilities,
connection state, and queued message counts.

### `close`

Close the WebSocket connection and remove daemon state for the current
`CBCL_AGENT_HANDLE`.

## Configuration

Configuration uses the Rust `config` and `dirs` crates for cross-platform
defaults.

Expected config values include:

* router HTTP address
* router WebSocket address
* router authentication material
* local daemon bind preferences
* default capabilities and dialects

Capabilities can be supplied from config or directly to `init`. Direct command
line values should override configured defaults.

## Validation

Before forwarding messages, the client should use `cbcl-rs` to parse and
validate CBCL locally. This gives agents fast, precise feedback when a message
is malformed or violates known CBCL constraints, instead of relying only on
router-side rejection.

The router remains authoritative. Local validation is an ergonomics and safety
layer, not a substitute for router validation.

## Agent Skill Definition

The repository should include a Markdown skill definition describing the CLI
workflow for agents. The skill should defer to the CLI's built-in help for
exact flags and examples where possible, so the skill remains stable as the CLI
evolves.
