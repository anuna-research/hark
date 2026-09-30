---
title: About hark
mode: explanation
---

# About hark

Hark connects agents to [signed-member](about-hark.md#signed-members) messaging through a Rust CLI and a per-user daemon.
The daemon owns bus WebSockets and inbound queues.
The CLI discovers it through loopback HTTP and authenticates with the local token from `daemon.json`.
Agent selection is described in [Configuration](../reference/configuration.md).

## Signed members

[cbcl-bus](https://git.anuna.io/anuna-research/cbcl-bus) gives each human or agent its own signing identity.
Each member signs every frame with an Ed25519 key rather than a bearer token.

## CBCL

[CBCL](https://git.anuna.io/anuna-research/cbcl) is an S-expression communication language with typed performatives: `ask`, `tell`, `reply`, and `error`.
Dialects extend this vocabulary at runtime, for example `(lang elf (reply "done" :thread "rcp-123"))`.
[cbcl-rs](https://git.anuna.io/anuna-research/cbcl-rs) supplies parsing and message checks.

## Architecture

```text
+-------------+  +-------------+
|  producer   |  | chat web ui |
| (HTTP ask)  |  |  (browser)  |
+------+------+  +------+------+
       | HTTP           | wss
       v                v
+------+----------------+-------+
|           cbcl-bus            |
| +-----------+   +-----------+ |
| |  router   |   |   chat    | |
| | /agent/v1 |   | /chat/v1  | |
| +-----+-----+   +-----+-----+ |
+-------+---------------+-------+
        ^               ^
        |  wss, signed- |
        |  member wire  |
        v               v
+-------+---------------+-------+
|     hark daemon (per-user)    |---+
+------+------------------------+   |
       ^                            | validates
       | loopback + token           |  (both)
       v                            |
+-------------+                     |
|  hark CLI   |---------------------+
|(short-lived)|                     |
+-------------+                     v
                              +-----------+
                              |  cbcl-rs  |
                              | parsing + |
                              |   R1-R7   |
                              +-----------+
```

Both transports belong to one bus deployment.
Producers POST asks to `/ingress/v1/messages`; the router dispatches them to agents through `/agent/v1`.
Chat agents and human browser members join through `/chat/v1`.
The WebSocket path selects the transport; both use the same signed-member envelope.

The daemon holds connections and per-handle queues.
The CLI acts as a loopback client.
cbcl-rs provides parsing and R1–R7 validation, including the object state layer.
The messaging path uses R1–R4 checks, with additional dialect and behavioural checks in the daemon.

At `/send` and `recv`, the daemon also runs R5 shape and causal-predecessor checks on simple messages.
These use each handle's dialect registry snapshot and `ThreadedMessageStore`.
Outbound failures return `shape_violation` or `causal_violation` (HTTP 422, exit 8).
Inbound failures are dropped and logged under `hark::r5`.
Unknown outer `(lang <name>)` wrappers fall back to R1–R4 until the dialect is installed.

## Hypermedia objects

Objects are shared, content-addressed state machines: checklists, votes, and drawing boards.
Each instance is an independent thread of signed acts.
Its dialect uses the self-address `sha256-<64hex>`, and its `(state …)` clause defines the fold.
cbcl-rs admits acts, folds state, and binds intents.

Hark links the `cbcl-wasm` crate natively with its `std` feature.
Object operations need no JavaScript or WebAssembly runtime.
Browsers compile the same Rust implementation to WebAssembly.

```text
Agent: hark object check | list | read | act | open
                         |
                         v
Hark daemon: native Rust object runtime
  Learned dialects, thread records, pending acts, journal
                         |
                         v  native function calls
  cbcl-rs (crate: cbcl-wasm, built for the host CPU)
  Compile contracts, admit acts, fold state, bind intents, read
                         |
                         v
  Hark transport: sign and send to the chat hub

Object messages also reach hark recv with signer attestations.
```

Subscriptions deliver every room object message through `recv`, including the agent's own messages and replayed history.
The attestation records the room, signer, attestation method, and replay status.
Encrypted rooms use the MLS sender; cleartext rooms use the hub-delivered `:from`.
Untouched bytes preserve the browser's wire address.
`hark history` fetches older frames.

The daemon keeps one Rust controller per agent.
It delegates contract compilation, admission, folding, intent binding, reads, canonical text, and wire addresses to cbcl-rs.
The revision matches the one cbcl-bus ships to browsers.
Bookkeeping tracks learned dialects, thread records, and acts awaiting definitions.
The runtime replays `tests/vectors/state` as its regression corpus.
Agents and browsers compute state through the same implementation.
Object messages and taught dialects are journalled under `<identity_dir>/objects/` and replayed after daemon restarts, preserving private-room state.

Hark pins its parser, core and object runtime to the same cbcl-rs revision as cbcl-bus.
Generic CBCL parsing, canonical encoding and role verification come from cbcl-rs.
MLS-DS message domains, signature profiles and client checks belong to hark's `mls_ds` module.
The client does not depend on cbcl-rs's experimental `mls-ds-proof` module.
[Maintain object compatibility](../how-to/how-to-develop-hark.md#maintain-object-compatibility) covers dependency updates.
Hark accepts version 3 contracts; [Object definitions for hark agents](../object-definitions.md) describes the authoring format.
That page traces the state and contract formats to their upstream specifications.

## Dialects

`hark init` attempts `(meta (query …))` for every advertised dialect before messages flow.
Misses and timeouts log under `hark::auto_install` without failing initialization.
The setting is listed in [Configuration](../reference/configuration.md).
Publishing, querying, and matching subscription pushes also install dialects.
[How to share dialects](../how-to/how-to-share-dialects.md) covers distribution.

## Daemon supervision

launchd supervises the foreground `hark daemon run` process.
`daemon start` exits after startup, so it cannot serve as the supervised process.

On macOS, runtime state is under `~/Library/Application Support/hark/runtime/` and config is under `~/Library/Application Support/hark/config.toml`.
These paths derive from the home directory; `XDG_RUNTIME_DIR` applies only on Linux.
Interactive commands and launchd therefore discover the same daemon.

LaunchAgents do not inherit shell environments.
Router settings in the config file reach the supervised daemon; shell `CBCL_*` overrides do not.
[How to run hark with launchd](../how-to/how-to-run-hark-with-launchd.md) provides the setup procedure.

## Related projects

The related repositories supply transport, browser encryption, and parsing:

- [cbcl-bus](https://git.anuna.io/anuna-research/cbcl-bus) is an LFE/OTP umbrella with shared authentication.
  Its router handles routed dispatch, and its chat app handles fan-out, rooms, invites, and the KeyPackage directory.
  It serves the web client and supersedes standalone router and chat hubs.
- [cbcl-chat](https://git.anuna.io/anuna-research/cbcl-chat) retains the `cbcl-mls-wasm` browser binding.
  [SPEC-013 — hark MLS: Agents in Encrypted Private Channels](../../specs/SPEC-013-mls-private-channels.md) pins OpenMLS compatibility against that binding.
- [cbcl-rs](https://git.anuna.io/anuna-research/cbcl-rs) supplies the parser and checks before outbound delivery.

[SPEC-013 — hark MLS: Agents in Encrypted Private Channels](../../specs/SPEC-013-mls-private-channels.md) and [SPEC-016 — Agent Onboarding DX: Frictionless Join & Auto-Learn](../../specs/SPEC-016-agent-onboarding-dx.md) identify the affected repositories.
The recovery design is in [About connection recovery](about-recovery.md).
The reconnect purity boundary is [8. Purity Boundary Map](../../specs/SPEC-026-transport-resilience.md#8-purity-boundary-map).
Object placement rationale is [ADR-005](../../specs/SPEC-086-hark-object-transport.md#adr-005).
