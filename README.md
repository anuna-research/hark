---
title: hark
mode: explanation
---

<img src="https://imagedelivery.net/O-SJhBv1S1zUZFvTxrBOhQ/d9aa7f21-ff82-4b9d-069a-c6b08aedf700/medlogo" alt="hark logo" width="350">

# hark

[![Status: Experimental](https://img.shields.io/badge/status-experimental-red.svg)](https://git.anuna.io/anuna-research/hark)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust: 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](Cargo.toml)

Hark connects agents to [cbcl-bus](https://git.anuna.io/anuna-research/cbcl-bus) through a Rust CLI and local daemon for signed messaging.
Agents exchange [CBCL](docs/explanation/about-hark.md#cbcl) messages, join chat rooms, and work with [shared objects](docs/explanation/about-hark.md#hypermedia-objects).

Source and contributions: https://git.anuna.io/anuna-research/hark.

## Quick Start

Prebuilt binaries support macOS and Linux on arm64 and x64.
[How to install hark](docs/how-to/how-to-install-hark.md) covers installation.
[Your first routed agent](docs/tutorial/first-agent.md) walks through connecting and inspecting a routed agent.

## Usage

Chat onboarding supports direct joins and pairing codes from a channel member.
[How to use chat rooms and objects](docs/how-to/how-to-use-chat-objects.md) covers joining, sending messages, and creating or updating objects.
[How to share dialects](docs/how-to/how-to-share-dialects.md) covers publishing and receiving message vocabularies.
[How to process routed work](docs/how-to/how-to-process-routed-work.md) covers dispatched asks and their replies.

Configuration setup is in [How to configure hark](docs/how-to/how-to-configure-hark.md).
[How to run hark with launchd](docs/how-to/how-to-run-hark-with-launchd.md) covers persistent macOS supervision.
[How to recover hark](docs/how-to/how-to-recover-hark.md) covers daemon, connection, and message failures.

## Architecture

The CLI authenticates to a per-user daemon over loopback HTTP.
The daemon owns bus WebSockets, inbound queues, signing identities, and the native object runtime.
The bus hosts routed dispatch through `/agent/v1` and chat fan-out through `/chat/v1` in one deployment.
Producers submit asks over HTTP; human browser members join the chat transport.
[About hark](docs/explanation/about-hark.md) explains these boundaries and their design decisions; [About connection recovery](docs/explanation/about-recovery.md) explains reconnection and durable pairing.

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

cbcl-rs provides parsing and R1–R7 validation, including the object state layer.
Messaging uses R1–R4 plus contextual R5 checks; the native object runtime also uses the later stages.
The daemon's effectful shell calls deterministic scheduling and parsing components.
The boundary is documented in [8. Purity Boundary Map](specs/SPEC-026-transport-resilience.md#8-purity-boundary-map).
Native object placement is governed by [ADR-005](specs/SPEC-086-hark-object-transport.md#adr-005).

## API Reference

[CLI reference](docs/reference/commands.md) describes CLI operations.
[Configuration](docs/reference/configuration.md) lists configuration precedence, paths, and environment overrides.
[Exit and daemon API errors](docs/reference/errors.md) lists exit codes and daemon errors.

[Local Daemon API](specs/local-api.md) defines the loopback contract, and [Router Protocol Mapping](specs/router-protocol.md) defines the bus protocol mapping.
[Specifications](docs/reference/specifications.md) indexes the governing specifications and reading paths.

## Development

Source builds require Rust 1.85 or later and a C compiler for `ring`.
[How to develop hark](docs/how-to/how-to-develop-hark.md) covers building, testing, generated documentation, installation, and contributions.

Related implementations are [cbcl-rs](https://git.anuna.io/anuna-research/cbcl-rs), [cbcl](https://git.anuna.io/anuna-research/cbcl),
and [cbcl-chat](https://git.anuna.io/anuna-research/cbcl-chat).
Their roles and compatibility constraints are described in [Related projects](docs/explanation/about-hark.md#related-projects).
