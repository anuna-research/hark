---
title: CLI reference
mode: reference
---

# CLI reference

The CLI exposes configuration, daemon lifecycle, routed agents, chat membership, dialects, and object operations.
Generated command help is available through `hark --help` and `hark <command> --help`.
The generated man page is `man hark`.
Select an existing agent with global `--agent <handle|@name>` (before or after the command).
It overrides `CBCL_AGENT_HANDLE`. With neither, the sole registered agent is selected;
multiple registered agents cause a usage error (exit 2), even if one is active.
A wire `@name` must identify exactly one connection; duplicates require the internal handle.
Use `hark agents` to discover handles and `hark --agent @aria whoami --json` to inspect one.

CBCL and dialect terminology: [CBCL](../explanation/about-hark.md#cbcl).

## `update`

`hark update [--install-dir DIR]` downloads the latest published release using
`https://files.anuna.io/hark/version.json` and the immutable release directory
it identifies. Selects the macOS/Linux arm64/x64 artifact, requires its SHA-256
checksum, and atomically installs it as `DIR/hark`. Defaults to `HARK_INSTALL_DIR`
or `~/.local/bin`, matching the installer; `HARK_BASE_URL` overrides the metadata
source. A checksum-identical executable is already up to date. A download,
checksum, or installation error leaves the prior binary intact and exits 12;
unsupported platforms or invalid release URLs exit 2. The daemon is not restarted
and no agent selection is required.

## `config path`

Prints the platform-specific config file path.

## `config show`

Prints the running daemon's effective configuration as JSON, including resolved
chat defaults. Requires a running daemon. This queries its captured settings,
so later environment changes in the calling shell do not change the result.
Authentication tokens are redacted; hub URLs omit credentials, query parameters,
and fragments. Restart an older daemon if it lacks this endpoint.

## `config show-example`

Prints an example `config.toml` to stdout.

## `config init`

Creates the config file with an example config if it does not already exist.
It refuses to overwrite an existing config file.

## `daemon start`

Starts the per-user daemon if needed and exits after authenticated local
`ping` succeeds. This command is idempotent and does not contact the router.

## `daemon run`

Runs the daemon in the foreground. It fails if another daemon already holds the
singleton lock.

## `daemon status`

Prints daemon state and agent connections in a human-readable format.
`--json` returns the daemon API's `{daemon, agents, active_agent_handle?}` object.
The active handle is informational; it does not resolve ambiguous selections.

## `agents` and `whoami`

`hark agents [--json]` lists registered connections. `hark whoami [--json]`
inspects the selected connection. Their text output includes the local handle,
wire identity, channel, backend, redacted hub URL, encryption, socket state,
and readiness. A blocked connection includes a reason and recovery guidance.

`agents --json` uses the same envelope as `daemon status --json`; `whoami --json`
returns one agent record. Its `connection` object contains `backend`, `hub`,
`encryption`, `socket`, `ready`, `reason`, and `recovery`. `socket` describes transport
connectivity; `ready` describes current transport and encryption readiness.
A connected socket awaiting an MLS Welcome or recovering a fork has `ready: false`.
Readiness is a snapshot, so callers must still handle send errors and exit 13.
Older daemons omit `connection`; text output reports readiness as unknown.

Example:

```sh
hark agents --json
hark --agent @aria whoami --json
hark --agent @aria recv --timeout 30s
```

## `daemon stop`

Requests daemon shutdown, removes `daemon.json`, closes active router
connections, and waits until the daemon stops responding.

## `init`

Creates one ephemeral agent instance. `--dialect` is required at least once and
is repeatable.
Default output exports the local handle as `export CBCL_AGENT_HANDLE='…'`; `--json` returns structured output for non-shell harnesses. Duplicate dialects are rejected before the daemon is called.

## `recv`

Requires a selected agent. Blocks until one CBCL message is available, then
prints only that message to stdout. Each invocation consumes one queued message.
Timeout units are `ms`, `s`, `m`, and `h`; the maximum finite timeout is `2160h`. `--record` prints the JSON response
instead, with the [SPEC-086 — Object transport for SDK agents](../../specs/SPEC-086-hark-object-transport.md) attestation record when the message is an object
delivered under `--objects`.

`--follow` keeps the process alive and prints one JSON response per line, with
`agent_handle`, `message`, and any object attestation `record`. It flushes each
line and pins the selected handle for the process lifetime. `--timeout` applies
to each receive; an idle wait ends the stream with exit 10 and no extra output
record. `--record` has the same per-message JSON shape for a single receive.
A closed stdout pipe ends successfully.

```sh
hark --agent @aria recv --follow --timeout 5m
```

## `history`

`hark history [--limit 1–1000] [--room @name]` — ask the hub for older room
history on the current agent's own connection ([SPEC-086 — Object transport for SDK agents](../../specs/SPEC-086-hark-object-transport.md)). The frames arrive
through `recv`, object messages with `replayed: true` in their records; the
object runtime learns them too. Only one request per room can be in flight.

## `object`

`hark object check|list|read|act|open` — read, act on, and create hypermedia
objects through the daemon's native Rust runtime ([SPEC-086 — Object transport for SDK agents](../../specs/SPEC-086-hark-object-transport.md)). `check`
validates a definition without an agent or a send and prints its dialect
self-address, label, opener, verbs, state rules, roles, contract, and verified
CBCL. The other commands require an agent with the object subscription.
`list` names learned threads.
`read` prints an object's projected state as JSON.
`act <thread> <verb>` binds routing, causal predecessors, and replacements from accepted history through cbcl-rs.
It checks the resulting frame before sending.
`open --define <file|json> --thread <t>` verifies a definition, declares its
dialect to the room, and sends the opener. Recipients fetch an unknown
dialect from the room by digest. Views are separate from the contract.

Fields are a JSON object or repeated `--field k=v`. Each flag value is parsed
as JSON when possible, otherwise as text: `done=true` is a boolean,
`count=3` an integer, and `item=milk` a string. To preserve a numeric string,
the flag is `--field 'item="123"'`. Types are checked against the contract; numbers
are integers only, and null or object-valued fields are unsupported. A
rejected action reports the reason and sends nothing.

An agent can also construct a complete object action and use `hark send`;
`object act` handles construction and validation from intent and history.
See [docs/object-definitions.md](../object-definitions.md).

## `tell`, `reply`, `error`, and `send`

Require a selected agent. The CLI validates CBCL locally, the daemon
validates again, and the daemon returns success only after the frame is written
to the selected router WebSocket.

A verb that pins its frame to one performative is named for that performative;
the verb that carries anything is named for the transport.

Validation rules:

* `tell` takes literal text and never parses it as CBCL.
* `reply` requires a CBCL `reply` performative after dialect-wrapper removal.
* `error` requires a CBCL `error` performative after dialect-wrapper removal.
* `send` accepts any performative, core or custom, and refuses `(meta ...)`.
* `reply` and `error` require exactly one non-empty string `:thread`. `tell`
  and `send` do not.

## `dialect publish`

Requires a selected agent. Reads a complete `(define <name> ...)` CBCL form from `--define` or stdin.
The daemon checks it through cbcl-rs's R1–R5 pipeline, then sends `(meta (teach @router <define>))`.
The command awaits the router's reply synchronously and prints `<digest> <name>` on success. `--json` prints
`{"digest", "name", "define"}` instead.

On router acknowledgement, the daemon installs the published define in the publishing handle's dialect cache.
Subsequent outbound traffic obeys that dialect's R5 constraints without a separate query.
Local installation failure after acknowledgement is non-fatal; publication still succeeds.
The failure logs under `tracing` target `hark::dialect_cache`.

Content-addressed and idempotent: republishing identical bytes returns the
same digest.

## `dialect query`

Requires a selected agent. Asks the router whether it knows a dialect by
name. On a hit, the router replies with `(meta (teach @<self> (define ...)))`.
The receive loop checks R1–R5, installs the inner define in the local cache, and returns `<digest> <name>`.
On miss the CLI exits 2 with `dialect_unknown_to_router`.

## `dialect list`

Requires a selected agent. Sends `(meta (query (list)))`, awaits the
router's reply, and prints every dialect name the router knows on its own
line.

## `dialect subscribe` and `dialect unsubscribe`

Require a selected agent. `subscribe <pattern>` (default `*`) sends
`(meta (subscribe (speak? <pattern>)))` fire-and-forget; subsequent matching
teach pushes from the router validate through R1–R5 in the daemon and land
in `hark recv`. `unsubscribe` drops the agent's single subscription without
closing the WebSocket. Pattern grammar: exact name, `<prefix>*`, or `*`.

## `join`

`hark join <@channel> --as <@handle> [--speak d1,d2] [--cap <token>] [--hub <url>] [--objects]`
This command scaffolds missing config and starts the daemon if needed.
It sends the signed hello and emits `announce`, so chat clients render the member as an agent. `--speak` advertises only the listed dialects
(never the channel's whole menu); when the hub conveys a declared menu, an
undeclared `--speak` is rejected. The joined handle becomes the session's
active agent. Follow-up commands need no selector when it is the sole registered
connection; with multiple agents use `--agent` or `CBCL_AGENT_HANDLE`.

`--objects` ([SPEC-086 — Object transport for SDK agents](../../specs/SPEC-086-hark-object-transport.md)) subscribes the agent to every channel object message, identified by a `sha256-<64hex>` dialect.
This includes its own messages and replayed history.
Messages reach `hark recv` with attestations and feed the daemon's object runtime for reading, acting, and creation. An
object dialect (`sha256-<64hex>`) given to `--speak` means the same thing and
is never advertised. The subscription persists with the pairing across a
daemon restart; a rejoin without it disables the subscription. See
[Hypermedia objects](../explanation/about-hark.md#hypermedia-objects) and the `object` command.

## `tell` and `send`

`hark tell [text]` (or stdin) — proactive plain chat into the joined channel.
The text becomes a CBCL `(tell @channel "…" :from @handle)` body.
`tell` never parses its input as CBCL.
For example, `hark tell '(tell @x "y")'` sends that string as the message body.

`hark send [frame]` (or stdin) — transmit a frame you wrote yourself. Any
performative, core or custom, bare or wrapped in `(lang ...)`, `(envelope ...)`,
`(signed ...)`, or `(with-limits ...)`. It never wraps, rewrites, or injects a
parameter. The wire frame is always valid CBCL.

These replaced `emit`, which chose between the two contracts by testing whether
the argument began with `(`. `progress` is retired; complete frames use `send`. Both remain as hidden aliases for one minor release, warning on stderr.
See [CLI Verb Set / CBCL Convention Merge — ADR-008, ADR-009, ADR-010 (PROPOSED)](../decisions/SPEC-016-cli-verb-set-cbcl-merge.md).

## `pair`

`hark pair <id>-word-word [--objects]` — redeem a pairing code minted by the
web app's "add agent" flow. Runs a SPAKE2 handshake (RFC 9382) with the hub.
The words never cross the wire; the pairing record is bound to the PAKE-derived session key. On success the agent joins under the adder-set
name (`--as` overrides) and the roster records who added it. For private channels, the encryption pin derives from the record's invite-cap presence.
A record claiming `enc=true` without a cap fails closed. `--objects` enables the object subscription.
A listed object dialect also enables it automatically, reflecting the adder's selection from the room menu. The flag enables object support when
the invite lists no object dialect; it is redundant when one is already
listed. Either way, the subscription covers all objects in the channel.

## `close`

Requires a selected agent. Removes the local handle and closes the selected
router WebSocket. Successful `close` prints nothing.

## Structured output conventions

Existing output shapes are preserved: `init --json` returns a connection response;
object commands return their operation-specific JSON (including a bare array for
`object list` and projected state for `object read`); dialect publication/query
return their operation results. Inspection uses daemon envelopes for lists and
an agent record for a single selection. Streaming receive uses JSON Lines rather
than a JSON array. Diagnostics remain on stderr, and nonzero exit codes still
signal failure. Commands without a JSON mode retain their existing output.
