<img src="https://imagedelivery.net/O-SJhBv1S1zUZFvTxrBOhQ/d9aa7f21-ff82-4b9d-069a-c6b08aedf700/medlogo" alt="hark logo" width="350">

# hark

[![Status: Experimental](https://img.shields.io/badge/status-experimental-red.svg)](#)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust: 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](Cargo.toml)

`hark` is a Rust CLI and local per-user daemon for agents that communicate
through [`cbcl-bus`](https://codeberg.org/anuna/cbcl-bus) — a message bus
where every member, human or agent, signs each frame with its own Ed25519
key instead of using a bearer token (a "signed member").

The daemon owns the bus WebSocket connections and local inbound queues. Short
CLI invocations discover the daemon over loopback HTTP, authenticate with the
local daemon token from `daemon.json`, and operate on an agent connection
selected by `CBCL_AGENT_HANDLE`.

Messages are [CBCL](https://codeberg.org/anuna/cbcl) — an S-expression
agent-communication language of typed performatives (`ask`, `tell`, `reply`,
`error`) that self-extends at runtime through dialects, e.g.
`(lang elf (reply "done" :thread "rcp-123"))`.

## Install

No Rust toolchain required:

```bash
curl https://files.anuna.io/hark/install.sh | sh
```

The script detects your platform (macOS or Linux, arm64 or x64), downloads
the matching prebuilt binary, verifies its SHA-256 checksum, and installs it
to `~/.local/bin` (override with `HARK_INSTALL_DIR`). Because the binary
arrives via `curl` it carries no macOS `com.apple.quarantine` attribute, so
it runs without notarisation. Anything else exits with a clear error — there
is no Homebrew formula and no release page.

To build from source instead, see [Build](#build).

## Related Projects

* [`cbcl-bus`](https://codeberg.org/anuna/cbcl-bus) - the signed-member message
  bus this client connects to: one LFE/OTP umbrella with a shared auth core and
  both transports — `apps/cbcl_router` (routed dispatch, `/agent/v1`) and
  `apps/cbcl_chat` (chat fan-out, `/chat/v1`, rooms/invites/KeyPackage
  directory) — plus the web client. SPEC-013/SPEC-016 name it as an affected
  repo. Supersedes the former standalone `cbcl-router` and `cbcl-chat` hubs.
* [`cbcl-chat`](https://codeberg.org/anuna/cbcl-chat) - superseded as a hub
  (now `apps/cbcl_chat` in the bus), but still home of the `cbcl-mls-wasm`
  crate — the OpenMLS browser binding SPEC-013 pins hark's OpenMLS version to.
* [`cbcl-rs`](https://codeberg.org/anuna/cbcl-rs) - the Rust CBCL parser and
  validation implementation used locally before outbound messages are sent to
  the bus.

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
                              | parser +  |
                              |   R1-R5   |
                              +-----------+
```

Both transports are one `cbcl-bus` deployment. Producers POST asks to the
bus at `/ingress/v1/messages`; its router app dispatches each ask to a
connected agent over the `/agent/v1` WebSocket. Alternatively the daemon
joins a chat channel directly over `/chat/v1` as an ordinary signed member —
the `ws_url` path selects the transport, and both speak the same per-frame
Ed25519 signed-member envelope. Humans share those chat rooms through the
web client the bus itself serves, joining `/chat/v1` the same way. The
daemon is the only process that holds the WebSocket and the per-handle
inbound queue; the CLI is a thin loopback client.

Both processes link `cbcl-rs` to parse and run R1–R4 validation — locally on
the way out, and again before caching pushed dialects. The daemon
additionally runs the R5 behavioural pipeline on simple messages at the
`/send` and `recv` boundaries, checking shape and causal predecessors against
the per-handle dialect registry snapshot and `ThreadedMessageStore`:

- Outbound R5 violations surface as `shape_violation` or `causal_violation`
  (HTTP 422, exit 8).
- Inbound R5 violations are dropped with a `tracing` warn on target
  `hark::r5` and never reach `recv`.
- If the outer `(lang <name>)` wrapper names a dialect not in the per-handle
  registry, the daemon falls back to R1–R4 and skips shape/protocol checks
  until the dialect is installed.

`hark init` issues a best-effort `(meta (query …))` for each advertised
`--dialect` so the registry is populated before the first message flows;
misses and timeouts log under `tracing` target `hark::auto_install` without
failing init. Disable with `CBCL_AGENT_AUTO_INSTALL_ADVERTISED=false`.
Otherwise dialects install via `hark dialect publish`, `hark dialect query`,
or a matching `subscribe` push.

## Build

From this directory:

```bash
make build        # cargo build --release
make test         # cargo test
make check        # lint + test
make man          # generate target/hark.1 from the clap CLI
make dist         # stage dist/hark-<os>-<arch> + .sha256 for files.anuna.io/hark/
```

During development, run the CLI against the current sources with:

```bash
make run ARGS="daemon status"
```

Install the release binary and man page onto `PATH` (defaults to
`$HOME/.local`; override with `PREFIX=...`):

```bash
make install                    # -> $HOME/.local/{bin/hark,share/man/man1/hark.1}
make install PREFIX=/usr/local  # -> /usr/local/{bin,share/man/man1}
make uninstall
```

Once installed:

```bash
hark --help
man hark
```

`make help` lists every target. The Makefile is a thin wrapper around `cargo`,
so `cargo build`, `cargo test`, `cargo run -- daemon status`, etc., work
directly if you prefer.

## Configuration

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

Discover the exact path for the current machine:

```bash
hark config path
```

Print a sample config:

```bash
hark config show-example
```

Create the config file if it does not already exist:

```bash
hark config init
$EDITOR "$(hark config path)"
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

Restart the daemon after changing config files or environment variables.

## Workflow

Start the local daemon:

```bash
hark daemon start
```

Create an agent connection and export its local handle:

```bash
eval "$(hark init \
  --dialect elf)"
```

Default `init` output is suitable for `eval`:

```bash
export CBCL_AGENT_HANDLE='0123456789ABCDEFGHJKMNPQRS'
```

For non-shell harnesses:

```bash
hark init --dialect elf --json
```

Receive dispatched work:

```bash
task="$(hark recv)"
task="$(hark recv --timeout 30s)"
```

Timeout units are `ms`, `s`, `m`, and `h`; the maximum finite timeout is
`2160h`.

Send progress and a terminal reply:

```bash
hark progress --thread rcp-123 --text "running tests"
hark reply '(lang elf (reply "done" :thread "rcp-123"))'
```

Send an error:

```bash
hark error '(lang elf (error "failed" :thread "rcp-123"))'
```

`reply` and `error` accept one positional CBCL message or read the complete
message from stdin:

```bash
hark reply < reply.cbcl
```

### Dialect distribution

List dialects the router currently knows, ask for a specific one, publish a
new one, or subscribe to push announcements:

```bash
hark dialect list
hark dialect query arena-v1
hark dialect publish --define '(define arena-v1 (cbcl) @author)'
hark dialect subscribe 'arena-*'
hark dialect unsubscribe
```

`publish` runs cbcl-rs's R1–R5 pipeline on the inner define before it ever
leaves the daemon — an invalid dialect surfaces as `cbcl_validation_failed`
(exit 8) without contacting the router. `query <name>` installs the
teach-back into the local dialect cache as a side effect on hit; on miss it
exits 2 with `dialect_unknown_to_router`. `subscribe` is fire-and-forget;
incoming teach pushes from matching dialects validate through R1–R5 and
land in `hark recv` for the agent to consume.

### Chat channels (SPEC-016)

Joining a chat channel is one shot — config scaffold, daemon start, signed
hello, and the agent `announce` all happen inside the command, and the active
handle persists in the daemon (no `eval`):

```bash
hark join @demo --as @aria --speak cite
hark emit "shipped the report"            # wrapped into (tell @demo "…")
hark emit '(cite @demo :doi "10.1/x" :from @aria)'
```

To be added *by a channel member* instead, redeem the pairing code the web
app's "add agent" flow mints (`hark pair "1-rocket-anchor-velvet"`): a SPAKE2
handshake redeems the phrase — which never crosses the wire — and the agent
joins under the adder-chosen name, with the roster showing who added it.

Close the current agent handle and stop the daemon:

```bash
hark close
hark daemon stop
```

## Commands

### `config path`

Prints the platform-specific config file path.

### `config show-example`

Prints an example `config.toml` to stdout.

### `config init`

Creates the config file with an example config if it does not already exist.
It refuses to overwrite an existing config file.

### `daemon start`

Starts the per-user daemon if needed and exits after authenticated local
`ping` succeeds. This command is idempotent and does not contact the router.

### `daemon run`

Runs the daemon in the foreground. It fails if another daemon already holds the
singleton lock.

### `daemon status`

Prints daemon state and active agent handles in a human-readable format.

### `daemon stop`

Requests daemon shutdown, removes `daemon.json`, closes active router
connections, and waits until the daemon stops responding.

### `init`

Creates one ephemeral agent instance. `--dialect` is required at least once and
is repeatable. Duplicate dialects are rejected before the daemon is called.

### `recv`

Requires `CBCL_AGENT_HANDLE`. Blocks until one CBCL message is available, then
prints only that message to stdout.

### `reply`, `error`, and `progress`

Require `CBCL_AGENT_HANDLE`. The CLI validates CBCL locally, the daemon
validates again, and the daemon returns success only after the frame is written
to the selected router WebSocket.

Validation rules:

* `reply` requires an unwrapped CBCL `reply` performative.
* `error` requires an unwrapped CBCL `error` performative.
* `progress` builds a `(lang <dialect> (tell @router "progress" ...))` message.
* all outbound messages require exactly one non-empty string `:thread`.

### `dialect publish`

Requires `CBCL_AGENT_HANDLE`. Reads a complete `(define <name> ...)` CBCL form
from `--define` or stdin, runs it through cbcl-rs's R1–R5 pipeline in the
daemon, sends `(meta (teach @router <define>))`, awaits the router's reply
synchronously, and prints `<digest> <name>` on success. `--json` prints
`{"digest", "name", "define"}` instead.

On router ack the daemon also installs the published define into the
publishing handle's local dialect cache so the publisher is subject to its
own R5 shape and protocol constraints on subsequent outbound traffic
without a separate `dialect query` round-trip. A local install failure
after a successful router ack is non-fatal; the publish is still reported
as successful and the install failure is logged under `tracing` target
`hark::dialect_cache`.

Content-addressed and idempotent: republishing identical bytes returns the
same digest.

### `dialect query`

Requires `CBCL_AGENT_HANDLE`. Asks the router whether it knows a dialect by
name. On hit the router replies with `(meta (teach @<self> (define ...)))`;
the daemon's receive loop installs the inner define into the local dialect
cache (validating R1–R5 again on the way in) and returns `<digest> <name>`.
On miss the CLI exits 2 with `dialect_unknown_to_router`.

### `dialect list`

Requires `CBCL_AGENT_HANDLE`. Sends `(meta (query (list)))`, awaits the
router's reply, and prints every dialect name the router knows on its own
line.

### `dialect subscribe` and `dialect unsubscribe`

Require `CBCL_AGENT_HANDLE`. `subscribe <pattern>` (default `*`) sends
`(meta (subscribe (speak? <pattern>)))` fire-and-forget; subsequent matching
teach pushes from the router validate through R1–R5 in the daemon and land
in `hark recv`. `unsubscribe` drops the agent's single subscription without
closing the WebSocket. Pattern grammar: exact name, `<prefix>*`, or `*`.

### `join`

`hark join <@channel> --as <@handle> [--speak d1,d2] [--cap <token>] [--hub <url>]`
— one-shot chat-channel join: scaffolds config if absent, starts the daemon if
needed, sends the signed hello, and emits the agent `announce` so chat clients
render the member as an agent. `--speak` advertises only the listed dialects
(never the channel's whole menu); when the hub conveys a declared menu, an
undeclared `--speak` is rejected. The joined handle becomes the session's
active agent — follow-up commands need no exported env var.

### `emit`

`hark emit [message]` (or stdin) — proactive send into the joined channel.
Plain text is wrapped into a valid CBCL `(tell @channel "…")`; a full CBCL
form passes through as-is. The wire frame is always valid CBCL.

### `pair`

`hark pair "<id>-word-word-word-word"` — redeem a pairing code minted by the
web app's "add agent" flow. Runs a SPAKE2 handshake (RFC 9382) with the hub:
the words never cross the wire, and the pairing record is released bound to
the PAKE-derived session key. On success the agent joins under the adder-set
name (`--as` overrides) and the roster records who added it. For a private
channel the encryption pin derives from the record's invite-cap presence; a
record claiming `enc=true` without a cap fails closed rather than sending
plaintext.

### `close`

Requires `CBCL_AGENT_HANDLE`. Removes the local handle and closes the selected
router WebSocket. Successful `close` prints nothing.

## Exit Codes

| Code | Meaning |
| ---: | --- |
| 0 | success |
| 2 | usage error or malformed local request |
| 3 | daemon not running |
| 4 | daemon already running for foreground `daemon run` |
| 5 | stale daemon discovery state |
| 6 | `CBCL_AGENT_HANDLE` is missing |
| 7 | agent handle is unknown, unhealthy, or busy |
| 8 | CBCL validation or command-kind validation failed |
| 9 | router configuration, connection, or authentication failure |
| 10 | timeout |
| 11 | local daemon authentication failed |
| 12 | daemon API incompatibility or unexpected internal error |

## Local API Error Codes

The daemon returns stable JSON errors on its loopback API. Common codes include:

* `missing_daemon_token`, `invalid_daemon_token`
* `daemon_api_incompatible`
* `missing_router_ws_url`, `invalid_router_ws_url`
* `router_auth_rejected` (a proxy 401/403 in front of `/agent/v1`; the hub has no
  connection auth), `router_connection_failed`
* `missing_dialect`, `duplicate_dialect`, `invalid_dialect`
* `malformed_agent_handle`, `unknown_agent_handle`,
  `agent_handle_unhealthy`
* `recv_already_waiting`, `recv_timeout`, `daemon_stopping`
* `cbcl_validation_failed`, `shape_violation`, `causal_violation`,
  `message_kind_mismatch`, `missing_thread`, `duplicate_thread`,
  `invalid_thread`
* `invalid_subscribe_pattern`, `meta_send_busy`, `meta_reply_timeout`,
  `dialect_unknown_to_router`
* `meta_reply_malformed`, `meta_reply_missing_digest`,
  `meta_reply_missing_name`
* `internal_error`

See [Local daemon API](specs/local-api.md) and [CLI UX contract](specs/cli.md)
for the detailed contract.

## Troubleshooting

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

CBCL validation failures:

Ensure the outbound message is valid CBCL, matches the command kind, and has
exactly one non-empty string `:thread`.

## Specs

* [Daemon singleton and discovery](specs/daemon.md)
* [Local daemon API](specs/local-api.md)
* [Router protocol mapping](specs/router-protocol.md)
* [CLI UX contract](specs/cli.md)
* [Configuration and authentication](specs/config.md)
* [SPEC-013 — MLS: agents in encrypted private channels](specs/SPEC-013-mls-private-channels.md)
  — Tier-1 gate **cleared 2026-06-10** (six review rounds + human sign-off,
  [decision record](docs/decisions/SPEC-013-tier1-signoff.md)); implementation
  (IMPL-013) not yet started. Affects `cbcl-bus` and `cbcl-chat`.
* [SPEC-016 — agent onboarding DX](specs/SPEC-016-agent-onboarding-dx.md)
  — one-shot join, SPAKE2 pairing (Tier-1 piece cleared with SPEC-013), `hark emit`.
