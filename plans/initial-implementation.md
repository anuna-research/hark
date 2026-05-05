# Initial Implementation Plan

This plan breaks the MVP into small, reviewable chunks. Each chunk should be
implemented with focused tests and committed separately before moving to the
next chunk.

Assumptions from the specs:

* The project is a Rust CLI named `cbcl-router-client`.
* `daemon start` is local-only and must not require router configuration.
* `init` is the first command that opens a router WebSocket.
* CLI commands and the daemon both validate CBCL before sending agent-originated
  frames.
* Router authentication for MVP is `Authorization: Bearer shr_<key_id>.<secret>`.
* Agent handles are local daemon handles; router-visible ids are derived as
  `<agent_id_prefix>-<agent_handle>`.

Potential spec follow-ups to settle during implementation:

* Exact `cbcl-rs` public API and crate dependency shape need confirmation once
  the Rust workspace is scaffolded.
* The specs require agent-handle grammar but only give examples. Use a
  base32-like uppercase alphanumeric handle with at least 128 bits of entropy
  unless a stronger local convention appears during implementation.
* Foreground `daemon run` logging destination is not specified. Start with
  stderr for foreground mode and suppress or redirect stdio for detached
  `daemon start`.

## Checklist

### 1. Scaffold the Rust CLI Project

- [x] Create the Rust package structure with `Cargo.toml`, `src/main.rs`, and
  initial module layout for `cli`, `config`, `daemon`, `local_api`,
  `router`, `cbcl_validation`, and `errors`.
- [x] Add core dependencies for CLI parsing, async runtime, HTTP server/client,
  WebSockets, serde JSON, config loading, runtime directories, file locking,
  random token generation, time handling, and test utilities.
- [x] Define constants for binary version, local API version, command name, and
  default config values.
- [x] Wire a minimal `clap` command tree for all MVP commands:
  `daemon start`, `daemon run`, `daemon status`, `daemon stop`, `init`, `recv`,
  `reply`, `error`, `progress`, and `close`.
- [x] Return stable exit codes from a central error-to-exit-code mapper.
- [x] Add smoke tests for CLI parsing and exit-code mapping.
- [x] Run `cargo fmt`, `cargo clippy --all-targets --all-features`, and
  `cargo test`.
- [x] Commit with a focused message such as `scaffold router client cli`.

### 2. Implement Configuration Loading and Validation

- [x] Implement config loading in precedence order: built-in defaults, platform
  config file, then environment variables.
- [x] Resolve platform config paths with `directories` or `dirs`.
- [x] Model `[router]`, `[agent]`, and `[daemon]` config sections.
- [x] Validate daemon-runtime config at daemon startup:
  loopback-only bind address, positive queue limits, supported overflow policy,
  and valid `agent_id_prefix`.
- [x] Defer missing or malformed router URL and missing router auth token until
  agent creation.
- [x] Implement grammar validators for `agent_id_prefix`, capability names, and
  dialect ids.
- [x] Redact router auth tokens in debug output, status output, and errors.
- [x] Add unit tests for precedence, defaults, environment overrides, grammar
  validation, loopback rejection, queue limit validation, and router-config
  deferral.
- [x] Run `cargo fmt`, `cargo clippy --all-targets --all-features`, and
  `cargo test config`.
- [x] Commit with a focused message such as `implement mvp configuration`.

### 3. Implement Runtime Directory, Discovery, and Local Auth

- [x] Resolve and create the per-user runtime directory with owner-only
  permissions where supported.
- [x] Implement strict Unix checks for runtime directory, `daemon.json`, and
  `daemon.lock`: no symlinks, current-user ownership, and owner-only access.
- [x] Implement `daemon.lock` singleton locking with a held file handle for
  daemon lifetime.
- [x] Implement atomic `daemon.json` writes containing `pid`, `addr`, `token`,
  `started_at`, `version`, and `api_version`.
- [x] Generate local daemon tokens with at least 32 bytes of randomness encoded
  in a shell-safe format.
- [x] Implement discovery loading and authenticated local client request
  headers.
- [x] Add discovery-state classification helpers for missing, live, stale with
  free lock, stale with held lock, auth failure, and API incompatibility.
- [x] Add unit and integration tests for secure file checks, stale-state
  classification, token generation shape, and API version compatibility.
- [x] Run `cargo fmt`, `cargo clippy --all-targets --all-features`, and
  `cargo test discovery`.
- [x] Commit with a focused message such as `implement daemon discovery`.

### 4. Build the Local HTTP API Skeleton

- [ ] Implement the loopback-only HTTP server for foreground `daemon run`.
- [ ] Enforce `Authorization: Bearer <daemon-token>` on every local API
  endpoint.
- [ ] Define stable JSON success and error response types.
- [ ] Implement `GET /v1/ping`, `GET /v1/agents`, and `POST /v1/stop` without
  router integration.
- [ ] Implement graceful shutdown state, discovery-file removal, and lock
  release by process exit.
- [ ] Implement the local HTTP client used by CLI commands, including API
  compatibility checks.
- [ ] Add integration tests that start the HTTP server on loopback, verify auth
  failures, ping success, status shape, stop behavior, and incompatible API
  handling.
- [ ] Run `cargo fmt`, `cargo clippy --all-targets --all-features`, and
  `cargo test local_api`.
- [ ] Commit with a focused message such as `add local daemon api skeleton`.

### 5. Implement Daemon Lifecycle Commands

- [ ] Implement `daemon run` as the foreground long-lived process.
- [ ] Implement `daemon start` as an idempotent detached launcher that polls
  `daemon.json` and authenticated `ping` until ready or timeout.
- [ ] Ensure `daemon start` can replace stale `daemon.json` only after a
  short-lived successful lock probe.
- [ ] Implement `daemon status` human-readable output for missing, live, stale,
  auth failure, and API-incompatible daemon states.
- [ ] Implement `daemon stop` for live daemons and cleanable stale discovery
  state.
- [ ] Verify `daemon start` does not validate router URL/authentication, open a
  router WebSocket, or send a router `hello`.
- [ ] Add process-level integration tests for start/status/stop where practical,
  using isolated temp runtime and config directories.
- [ ] Run `cargo fmt`, `cargo clippy --all-targets --all-features`, and the
  daemon lifecycle test subset.
- [ ] Commit with a focused message such as `implement daemon lifecycle cli`.

### 6. Implement Agent State, Queues, and Handle Operations

- [ ] Add daemon state for active agent handles, router agent ids,
  capabilities, dialects, connection state, unhealthy reason/detail, inbound
  queues, queued byte counts, and a single optional blocking recv waiter.
- [ ] Implement handle generation and validation.
- [ ] Implement bounded FIFO queues with configured message and byte limits.
- [ ] Implement overflow behavior: reject the new inbound frame, mark the handle
  unhealthy with `queue_overflow`, and close the router WebSocket.
- [ ] Implement `DELETE /v1/agents/{handle}` to close connected handles and
  remove unhealthy handles.
- [ ] Implement `GET /v1/agents/{handle}/recv` against in-memory queues and
  waiters before router receive-loop integration.
- [ ] Enforce malformed, unknown, unhealthy, busy, timeout, and shutdown error
  behavior from the local API spec.
- [ ] Add unit tests for handle grammar, queue FIFO behavior, queue byte
  accounting, overflow, close semantics, one-waiter concurrency, timeout bounds,
  and status snapshots.
- [ ] Run `cargo fmt`, `cargo clippy --all-targets --all-features`, and
  `cargo test agent_state`.
- [ ] Commit with a focused message such as `implement agent state and queues`.

### 7. Integrate Router WebSocket Agent Creation

- [ ] Implement lazy router config validation during `POST /v1/agents`.
- [ ] Connect to configured `ws://` or `wss://` `/agent/v1` URLs with the shared
  secret bearer authorization header.
- [ ] Reject missing URL, malformed URL, missing token, authentication rejection,
  and connection failures with stable local API error codes.
- [ ] Build the CBCL `hello` frame from router agent id, capabilities, and
  dialects.
- [ ] Store the agent handle only after WebSocket upgrade succeeds and the
  binary hello frame is successfully written.
- [ ] Preserve capability and dialect order while rejecting duplicates.
- [ ] Spawn a receive loop per agent connection that treats router binary frames
  as CBCL text and enqueues dispatched work.
- [ ] Treat router-originated CBCL `error` frames as diagnostics, mark the
  handle unhealthy with `router_error`, and keep sanitized detail for status.
- [ ] Mark handles unhealthy on router close or receive-loop failure.
- [ ] Add integration tests with a local mock WebSocket router covering auth
  header, hello frame, successful init response, router auth rejection, router
  close, router error diagnostics, and dispatched ask enqueueing.
- [ ] Run `cargo fmt`, `cargo clippy --all-targets --all-features`, and the
  router integration test subset.
- [ ] Commit with a focused message such as `connect agent handles to router`.

### 8. Implement CBCL Validation and Message Kind Checking

- [ ] Integrate `cbcl-rs` parsing and validation behind a small local
  abstraction so CLI and daemon code share the same checks.
- [ ] Support bare CBCL messages and one `(lang ...)` wrapper for validation and
  kind checking.
- [ ] Implement command-kind checks for `reply`, `error`, and `progress`.
- [ ] Enforce exactly one `:thread` parameter on the unwrapped inner message.
- [ ] Reject missing, duplicate, empty, and non-string `:thread` values with
  stable error codes.
- [ ] Validate progress shape as `tell @router "progress"` after unwrapping.
- [ ] Add parser-focused tests for valid wrapped and bare messages, malformed
  CBCL, kind mismatch, missing and duplicate thread values, empty and non-string
  thread values, valid progress, and invalid progress recipient/content.
- [ ] Run `cargo fmt`, `cargo clippy --all-targets --all-features`, and
  `cargo test cbcl_validation`.
- [ ] Commit with a focused message such as `add cbcl send validation`.

### 9. Implement Agent Send API and CLI Send Commands

- [ ] Implement `POST /v1/agents/{handle}/send` with daemon-side CBCL
  validation, kind checking, health checks, and direct WebSocket write.
- [ ] Ensure send success means the frame was written to the selected router
  WebSocket, not merely queued locally.
- [ ] Mark handles unhealthy with `local_send_failed` when local WebSocket write
  fails.
- [ ] Implement CLI input rules for `reply [MESSAGE]` and `error [MESSAGE]`,
  including stdin reading and interactive-TTY usage failure.
- [ ] Implement CLI-side CBCL validation and kind checking before calling the
  daemon.
- [ ] Implement `progress --thread <receipt-id> [--text <text>] [--dialect <id>]`
  generation with correct CBCL string escaping and default dialect `elf`.
- [ ] Keep stdout empty on successful `reply`, `error`, and `progress`.
- [ ] Add integration tests with a mock router verifying binary send frames,
  send error mapping, CLI stdout/stderr discipline, stdin behavior, and progress
  generation.
- [ ] Run `cargo fmt`, `cargo clippy --all-targets --all-features`, and the send
  command test subset.
- [ ] Commit with a focused message such as `implement agent send commands`.

### 10. Implement `init`, `recv`, and `close` CLI Behavior

- [ ] Implement `init` discovery flow without auto-starting the daemon.
- [ ] Validate required and duplicate `--capability` values and duplicate
  `--dialect` values before calling the daemon.
- [ ] Implement default `init` shell-export output with no extra stdout text.
- [ ] Implement `init --json` output matching the local API response.
- [ ] Implement `recv` handle resolution from `CBCL_AGENT_HANDLE`.
- [ ] Implement `recv --timeout <duration>` parsing for `ms`, `s`, `m`, and `h`,
  including max `2160h`.
- [ ] Ensure `recv` prints only CBCL message text to stdout.
- [ ] Implement `close` handle resolution and success/error behavior.
- [ ] Map missing handle, unknown/unhealthy/busy handle, timeout, auth failure,
  daemon-not-running, router failure, validation failure, and API incompatibility
  to the stable CLI exit codes.
- [ ] Add CLI integration tests for output discipline, env var handling,
  timeout parsing, missing daemon hints, duplicate capability/dialect rejection,
  and local API error-to-exit-code mapping.
- [ ] Run `cargo fmt`, `cargo clippy --all-targets --all-features`, and the CLI
  command test subset.
- [ ] Commit with a focused message such as `implement agent workflow cli`.

### 11. End-to-End MVP Verification

- [ ] Add an end-to-end test harness with an isolated runtime directory,
  isolated config, a real daemon process, and a mock WebSocket router.
- [ ] Cover the main happy path:
  `daemon start`, `init`, mock router dispatch, `recv`, `progress`, `reply`,
  `close`, and `daemon stop`.
- [ ] Cover daemon startup without router config.
- [ ] Cover `init` failure when router config is missing, malformed, or rejected.
- [ ] Cover unhealthy-handle behavior after router close, router diagnostic
  error frame, queue overflow, and local send failure.
- [ ] Verify no status or error output leaks router auth token or local daemon
  token.
- [ ] Verify `daemon stop` removes `daemon.json` and makes authenticated `ping`
  stop succeeding.
- [ ] Run full `cargo fmt`, `cargo clippy --all-targets --all-features`, and
  `cargo test`.
- [ ] Commit with a focused message such as `add end-to-end mvp coverage`.

### 12. Documentation and Release Readiness

- [ ] Update `README.md` with build instructions, config file examples,
  environment overrides, and the core daemon/init/recv/reply/progress/close
  workflow.
- [ ] Document stable exit codes and local API error codes at a user-facing
  level, linking back to specs for deeper detail.
- [ ] Add short troubleshooting notes for daemon-not-running, stale discovery
  state, router auth rejection, missing capabilities, and unhealthy handles.
- [ ] Confirm generated `--help` output is consistent with the CLI UX spec.
- [ ] Run final full verification: `cargo fmt --check`,
  `cargo clippy --all-targets --all-features`, and `cargo test`.
- [ ] Commit with a focused message such as `document initial router client mvp`.
