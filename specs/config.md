# Configuration and Authentication

## Purpose

The client needs configuration for:

* router WebSocket address
* router authentication material
* local daemon runtime behavior
* queue limits

This spec captures the MVP configuration model and the current router
authentication requirements.

## Configuration Sources

The implementation should use the Rust `config` and `dirs` or `directories`
crates.

Configuration should be loaded in this order, with later sources overriding
earlier sources:

1. built-in defaults
2. config file
3. environment variables
4. command-line flags

Recommended config file locations:

```text
Linux:   ~/.config/cbcl-router-client/config.toml
macOS:   ~/Library/Application Support/cbcl-router-client/config.toml
Windows: %APPDATA%\cbcl-router-client\config.toml
```

Runtime daemon state is separate from configuration and is defined in
[`daemon.md`](daemon.md).

The daemon owns router connections for agent instances, so it loads
configuration at daemon startup and keeps that configuration as its runtime
view. Changes to config files or relevant environment variables do not affect
an already-running daemon; users must restart the daemon for those changes to
take effect. Agent capabilities and dialect advertisements are not part of the
daemon's loaded configuration; they are supplied in each local `init` request.

Daemon startup does not require router configuration. A daemon may start,
answer local `ping`, report status, and stop without a router WebSocket URL or
router authentication token. Router URL and authentication are required only
when creating an agent instance with `init`, because that operation opens a
router WebSocket.

Configuration validation has two phases:

* daemon-runtime config is validated at daemon startup. Invalid local bind
  addresses, non-loopback bind addresses, invalid queue limits, invalid
  overflow policies, and invalid `agent_id_prefix` values fail `daemon start`
  and `daemon run`.
* router config is validated when `init` creates an agent instance. Missing
  router URL, malformed router URL, missing router auth token, and router
  authentication rejection fail `init` without creating a local handle.

The daemon may parse router config at startup for diagnostics, but it must not
make missing router URL or missing router auth fatal until an agent-creation
request needs those values.

## MVP Config Shape

Example TOML:

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

## Router Authentication

The current `cbcl-lfe-router` `/agent/v1` WebSocket path requires:

```text
Authorization: Bearer shr_<key_id>.<secret>
```

The client should support this shared-secret bearer token in the MVP.

Config key:

```toml
[router]
auth_token = "shr_prod-agent.REPLACE_ME"
```

Environment override:

```bash
export CBCL_ROUTER_AUTH_TOKEN='shr_prod-agent.REPLACE_ME'
```

The daemon uses this value when `init` opens an agent WebSocket connection to
the router:

```text
Authorization: Bearer ${CBCL_ROUTER_AUTH_TOKEN}
```

The token is sensitive. The client should avoid printing it in logs, status
output, error messages, or JSON responses.

## Router URLs

MVP requires only the WebSocket URL:

```toml
[router]
ws_url = "wss://cbcl-lfe.anuna.io/agent/v1"
```

Environment override:

```bash
export CBCL_ROUTER_WS='wss://cbcl-lfe.anuna.io/agent/v1'
```

HTTP router configuration is out of MVP.

## Agent Configuration

Capabilities and dialect advertisements are owned by each agent instance. They
are not daemon-level configuration and there are no configured default
capabilities or default dialects in the MVP.

An agent supplies capabilities and optional dialects through `init` flags:

```bash
cbcl-router-client init --capability code:edit --capability code:test --dialect elf
```

`init` must include at least one `--capability`. If no capability is supplied,
the CLI fails with a clear missing-capability error before calling the daemon.
The daemon must also reject local API agent-creation requests whose
`capabilities` list is empty.

Duplicate capability values are rejected rather than deduplicated silently.
Duplicate dialect values are also rejected. Successful requests preserve the
user-supplied order of capabilities and dialects.

Dialect advertisements are optional. If no `--dialect` is supplied, the agent
advertises an empty dialect list.

The only agent-related daemon configuration in the MVP is the router-visible
agent-id prefix:

```toml
[agent]
agent_id_prefix = "local-agent"
```

The router-visible agent id is derived from:

```text
<agent_id_prefix>-<agent_handle>
```

Environment overrides:

```bash
export CBCL_AGENT_ID_PREFIX='local-agent'
```

`CBCL_AGENT_ID_PREFIX` must follow the same grammar as `agent_id_prefix`.

MVP string grammar:

* `agent_id_prefix` - ASCII, 1-63 characters, matching
  `[A-Za-z0-9][A-Za-z0-9._-]*`.
* capability name - ASCII, 1-128 characters, matching
  `[A-Za-z0-9][A-Za-z0-9._:/-]*`.
* dialect id - ASCII, 1-64 characters, matching
  `[A-Za-z][A-Za-z0-9._-]*`.

These restrictions are narrower than general CBCL symbols on purpose. They keep
agent ids shell-safe, URL-path-safe, and readable in status output while still
covering the current examples such as `code:edit`, `code:test`, `elf`, and
`cbcl-router`.

## Daemon Config

The daemon bind address should default to an ephemeral loopback port:

```toml
[daemon]
bind = "127.0.0.1:0"
```

Queue defaults:

```toml
[daemon]
max_messages_per_handle = 1000
max_bytes_per_handle = 67108864
overflow_policy = "reject_new_and_close"
```

The daemon must reject non-loopback bind addresses unless an explicit future
unsafe override is added.

Environment overrides:

```bash
export CBCL_DAEMON_BIND='127.0.0.1:0'
export CBCL_DAEMON_MAX_MESSAGES_PER_HANDLE='1000'
export CBCL_DAEMON_MAX_BYTES_PER_HANDLE='67108864'
export CBCL_DAEMON_OVERFLOW_POLICY='reject_new_and_close'
```

Numeric environment values must parse as positive base-10 integers. Invalid
daemon-runtime values should fail configuration loading before the daemon
starts. The only MVP overflow policy is `reject_new_and_close`; any other value
should be rejected.

## Secret Handling

The MVP may read the router shared-secret token directly from config or
environment.

Recommended behavior:

* environment variables override config file secrets at daemon startup
* status output redacts secrets
* logs redact secrets
* `init --json` does not include secrets
* `daemon.json` contains only the local daemon token, not the router token
* the local daemon token is not exported through environment variables

Future versions may add OS keychain integration. That is not required for MVP.

## Future Auth Support

The router repository contains Ed25519/JWT enrollment machinery, but the current
`/agent/v1` path described by the code uses the shared-secret bearer mechanism.

Future client versions may support:

* enrollment flows
* Ed25519 keypair storage
* challenge/verify token acquisition
* token refresh

Those are out of MVP. The first client implementation should use the current
shared-secret bearer token required by `/agent/v1`.

## Error Handling

Missing router auth config should not prevent `daemon start`, `daemon run`,
`daemon status`, or `daemon stop`. It should fail an agent `init` request before
opening a WebSocket:

```text
error: router auth token is not configured
hint: set `CBCL_ROUTER_AUTH_TOKEN` or configure `router.auth_token`
```

Missing router URL should likewise fail before agent init opens a WebSocket.
The daemon may start without router configuration, but it cannot create router
WebSocket connections until a URL is available:

```text
error: router WebSocket URL is not configured
hint: set `CBCL_ROUTER_WS` or configure `router.ws_url`
```

Malformed router URLs should fail the same `init` path before the daemon opens a
WebSocket:

```text
error: router WebSocket URL is invalid
hint: set `CBCL_ROUTER_WS` or configure `router.ws_url` to a ws:// or wss:// URL
```

Authentication failure from the router should be surfaced distinctly from
network failure:

```text
error: router rejected WebSocket authentication
hint: check `CBCL_ROUTER_AUTH_TOKEN`
```
