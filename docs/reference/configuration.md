---
title: Configuration
mode: reference
---

# Configuration

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

Example config:

```toml
[router]
ws_url = "wss://cbcl-lfe.anuna.io/agent/v1"

[agent]
agent_id_prefix = "local-agent"

[daemon]
bind = "127.0.0.1:0"
max_messages_per_handle = 1000
max_bytes_per_handle = 67108864
overflow_policy = "reject_new_and_close"
```

The router connection has no bearer token — the daemon authenticates per frame
with an Ed25519 key it creates at `<config-dir>/router-agent.key` (the hub
trust-on-first-use enrols the public key). There is nothing to configure but the
URL.

Environment overrides:

```bash
export CBCL_ROUTER_WS='wss://cbcl-lfe.anuna.io/agent/v1'
export CBCL_AGENT_ID_PREFIX='local-agent'
export CBCL_DAEMON_BIND='127.0.0.1:0'
export CBCL_DAEMON_MAX_MESSAGES_PER_HANDLE='1000'
export CBCL_DAEMON_MAX_BYTES_PER_HANDLE='67108864'
export CBCL_DAEMON_OVERFLOW_POLICY='reject_new_and_close'
```

Daemon startup is local-only. `daemon start` does not require router URL or
router auth, and it does not open a router WebSocket. Router configuration is
validated lazily when `init` creates an agent instance.

Configuration changes take effect after a daemon restart.

Setup: [How to configure hark](../how-to/how-to-configure-hark.md).

## Agent selection and advertised dialects

`CBCL_AGENT_HANDLE` selects a local handle or a chat agent's wire `@name`.
When it is unset, session commands use the daemon's active agent.

`CBCL_AGENT_AUTO_INSTALL_ADVERTISED` defaults to enabled.
The value `false` disables initialization's best-effort queries for advertised dialects.
Misses and timeouts log under `hark::auto_install` without failing initialization.
