---
title: How to recover hark
mode: how-to
---

# How to recover hark

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

Or set the router URL override:

```bash
export CBCL_ROUTER_WS='wss://cbcl-lfe.anuna.io/agent/v1'
hark daemon stop
hark daemon start
```

`router_auth_rejected`:

The `/agent/v1` upgrade was refused with HTTP 401/403 — usually a proxy in front
of the hub, since the hub itself has no connection auth. Check the URL and any
proxy in the path. (A bad agent *identity* is not this error; it arrives as a
post-connect error frame and marks the handle unhealthy — see `daemon status`.)

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

Note that a handle showing `reconnecting` is **not** unhealthy and needs no
action — see [Recovery](../explanation/about-recovery.md). Closing it is how you give up on it.

`agent_not_ready`:

The agent is alive but cannot send right now.
Its hub connection is reconnecting, or its encrypted channel still awaits the MLS Welcome. Retry the same message; this is
not a handle failure and the handle is still good.

CBCL validation failures:

Ensure the outbound message is valid CBCL, matches the command kind, and has
exactly one non-empty string `:thread` for `reply` and `error`.
`tell` and `send` do not require that field.
