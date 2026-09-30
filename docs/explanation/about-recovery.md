---
title: About connection recovery
mode: explanation
---

# About connection recovery

Hark preserves chat membership across hub outages and daemon restarts.
[SPEC-026 — Transport Resilience: Hub Reconnect and Durable Pairing](../../specs/SPEC-026-transport-resilience.md) governs reconnect scheduling and durable pairing.

## Hub restarts

The hub's immediate deployment replaces its single instance and drops every socket.
Durable hub state preserves membership.
Hark retries the complete signed join: the original-capability `hello`, encrypted-channel MLS key publication, and `announce`.

Backoff begins at 1 s and doubles to a 15 s ceiling.
Downward jitter of up to 25% prevents clients from returning in lockstep.
Retries continue indefinitely while the hub is unreachable.

During reconnection, the handle stays usable and `hark recv` keeps waiting.
Outbound `tell` and `send` return retryable `agent_not_ready` errors.
Messages are not queued because encrypted messages sealed before an outage can reference an obsolete epoch.
Retrying after reconnection seals the message against the current epoch.

A status response during reconnection looks like this:

```
$ hark daemon status
daemon: running
agents: 1
active: 1K65XWE7NSPZMCVJFFAWS02SHR
1K65XWE7NSPZMCVJFFAWS02SHR reconnecting router_agent_id=@aria dialects=[cite] …
  reconnect_attempts=3
  reconnect_detail=IO error: peer closed connection without sending TLS close_notify
```

Active rejection makes a handle terminally unhealthy: the channel is gone, its capability is revoked, or rejoining violates its encryption pin.
An unreachable hub alone never makes the handle terminal.

## Daemon restarts

Each successful chat join persists in owner-only `<chat identity dir>/paired-agents.json`.
This record holds the channel capability.
Startup re-establishes recorded agents under the same handles, preserving exported `CBCL_AGENT_HANDLE` values.

The daemon reports ready before these joins finish.
Agents with unavailable hubs begin as `reconnecting` and follow the same retry schedule.

`hark daemon stop` followed by `hark daemon start` restores recorded chat agents.
`hark close` forgets the selected pairing, so that agent does not return.
Deleting the identity directory removes both pairings and signing keys, because the pairings authenticate through those keys.

A malformed pairing file is ignored in full, with a warning naming the file.
The daemon starts without persisted agents rather than acting on a partially understood record.
Recovery actions are in [How to recover hark](../how-to/how-to-recover-hark.md).
