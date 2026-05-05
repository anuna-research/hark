# Configuration and Authentication

## Purpose

The client needs configuration for:

* router WebSocket address
* router authentication material
* local daemon runtime behavior
* default agent capabilities and dialects
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

## MVP Config Shape

Example TOML:

```toml
[router]
ws_url = "wss://cbcl-lfe.anuna.io/agent/v1"
auth_token = "shr_prod-agent.REPLACE_ME"

[agent]
default_capabilities = []
default_dialects = []
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

The daemon uses this value when opening WebSocket connections to the router:

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

HTTP router configuration is out of MVP. Future producer/debug commands such as
`submit` or `receipt` may add an HTTP base URL when they are specified.

## Agent Defaults

Capabilities and dialects can come from config or from `init` flags.

Config:

```toml
[agent]
default_capabilities = ["code:edit", "code:test"]
default_dialects = []
agent_id_prefix = "local-agent"
```

Command-line flags replace configured defaults:

* if `--capability` is supplied, use supplied capabilities
* otherwise use `agent.default_capabilities`
* if neither is present, fail with a clear missing-capability error
* if `--dialect` is supplied, use supplied dialects
* otherwise use `agent.default_dialects`

The router-visible agent id is derived from:

```text
<agent_id_prefix>-<agent_handle>
```

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

## Secret Handling

The MVP may read the router shared-secret token directly from config or
environment.

Recommended behavior:

* environment variables override config file secrets
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

Missing router auth config should fail before opening a WebSocket:

```text
error: router auth token is not configured
hint: set `CBCL_ROUTER_AUTH_TOKEN` or configure `router.auth_token`
```

Missing router URL should fail before agent init. The daemon may start without
router configuration, but it cannot create router WebSocket connections until a
URL is available:

```text
error: router WebSocket URL is not configured
hint: set `CBCL_ROUTER_WS` or configure `router.ws_url`
```

Authentication failure from the router should be surfaced distinctly from
network failure:

```text
error: router rejected WebSocket authentication
hint: check `CBCL_ROUTER_AUTH_TOKEN`
```
