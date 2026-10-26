---
id: IMPL-029
title: Media sharing and daemon validation dependencies
status: implemented
---

# Media sharing and daemon validation dependencies

| Field | Value |
|---|---|
| id | IMPL-029 |
| title | Media sharing and daemon validation dependencies |
| Source | Hark issue 58 |
| Tier | 2: attachment contract and local API |
| Owner | Implementation agent; fresh reviewer verifies the diff |
| Coordination | Elephant theory `hark-issue-58` |

## Failure mechanism and accepted contract

PDF bytes cannot satisfy the image/audio preview allowlist. Independently,
a daemon launched with a minimal PATH cannot execute the shell's Homebrew probe.
Neither failure permits skipping image/audio metadata validation.

The existing [[SPEC-101-channel-media-store#REQ-020]] contract in cbcl-bus
provides opaque general attachments under exactly `application/octet-stream`.
Hark reuses that descriptor and the existing file object, encryption, authorized
room controls and storage transfer. No PDF parser, MIME expansion or rendering
is introduced. The caller explicitly requests `--download-only`; the default
preview upload still rejects unknown formats and invalid metadata.

The absolute `daemon.ffprobe_path` setting selects the executable for the daemon's
existing bounded inspection. Absence preserves PATH lookup. Relative settings
fail startup validation; missing/unusable executables fail inspection closed.
`hark media doctor` uses an authenticated daemon API and the same bounded
inspection on a known image, without requiring an agent. The report names the
running daemon environment and selected executable, and gives config/restart
instructions on failure.

Composition-first placement: extend the existing media codec, config and media
API. Reuse the process limits, transfer semaphore, authentication and CLI output
patterns. No new dependency, service, descriptor field or file object is needed.

The governing requirements are the issue's desired behaviour and acceptance
examples plus the existing client contract, rather than a newly synthesised
specification. Synthetic profiles and a new specification comprehension gate
are omitted because this implementation consumes those existing requirements.

## Planning ledger

| Task | Owner | Prerequisite | Acceptance | Source |
|---|---|---|---|---|
| attachments | implementer | existing opaque client contract | TEST-001 | [[SPEC-101-channel-media-store#REQ-020]] |
| probe | implementer | daemon runtime config | TEST-002 | Issue 58 dependency and diagnostics requirements |
| verification | implementer and fresh reviewer | completed attachments and probe | TEST-003 | Issue 58 acceptance examples |

The local upstream-contract reference pins the authoritative cbcl-bus source.
The updated browser
codec fixture records its upstream revision and checksum in its README.

### TEST-001

Validates: [[SPEC-101-channel-media-store#REQ-020]]. Core: explicit opaque PDF
upload/list/download through the existing authorized room path and real HTTPS
storage returns byte-exact plaintext. Arbitrary bytes and malformed media can be
sealed only through the explicit opaque inspection mode. Integrity tampering,
oversized content and arbitrary descriptor MIME remain rejected. Native and
pinned browser codecs open each other's opaque ciphertext. Existing preview
metadata and public-room confirmation checks remain enforced.

### TEST-002

Validates: issue 58 daemon dependency and diagnostics requirements. Core:
`media_doctor_uses_configured_probe_with_empty_daemon_path` starts isolated real
daemons, proves configured image validation under empty PATH, then proves the
calling CLI's ordinary PATH cannot repair an unconfigured daemon. The API test
rejects unauthenticated diagnostics and proves missing validation emits no
storage reservation or file publication. Unit inspection checks reject relative
probe paths and report actionable setup instructions. Opaque downloads remain
independent of the preview dependency.

### TEST-003

Validates: issue 58 acceptance examples. Core: run the media tests, isolated
daemon integration, full repository test suite and clippy; inspect the diff and
run a fresh adversarial review. Deliberately mutate the opaque contract and
configured-probe selection and require their tests to fail before restoring.
Depth: production room sharing needs a matched deployed hub/client and member
session. Local evidence uses the actual codec and HTTPS storage with the test
room-control harness, without claiming production deployment verification.

## Enable and rollback

Users opt into general files with `--download-only`. Image/audio retains its
existing path. Probe selection loads at daemon startup; config changes require
stop/start. The documentation requires matched hub/client general attachment
support and notifying room members to reload old clients. The existing hub
media switch disables transfer before a matched-release rollback; stored bytes
and grants are retained. Ordinary chat remains available.

## Evidence

Verified on the feature branch:

- `cargo test --no-fail-fast` passed after API 5, including the CLI/API-v4
  incompatibility test. Live hub tests keep their existing ignored status.
- `cargo test --lib media --test local_api --test daemon_lifecycle` passed after
  the final opaque-list assertion and mock-server cleanup fix.
- `cargo clippy --all-targets -- -D warnings` passed.
- Changed Rust files pass `rustfmt --edition 2024 --config skip_children=true
  --check`. Global `cargo fmt --check` reports pre-existing formatting changes
  in untouched files; its first reported file, `examples/pairgrant_interop.rs`,
  was byte-compared with HEAD and is unchanged.
- Pinned browser codec interoperability runs inside the native media suite.
  Upstream `node --test apps/cbcl_chat/test/web/media-ref.test.mjs
  apps/cbcl_chat/test/web/hypermedia/media-session.test.mjs` passed at the
  recorded source revision, including refusal to render opaque content or
  expose it to guest fetch/decode.
- Removing opaque support from the descriptor allowlist caused
  `media_opaque_is_explicit_and_integrity_checked` to fail. Ignoring the
  configured probe caused the empty-daemon-PATH integration test to fail.
  Both mutations were restored before final passing checks.
- Fresh cross-model adversarial review found an API-version compatibility
  defect. API 5 and the real-CLI API-v4 rejection test address it. Re-review
  found no remaining implementation defects; its requested opaque-list
  assertion was added and passed.
- `zetl check --no-cache --dead-links --fail-on error` reports existing dead
  links elsewhere in the vault. The new plan, upstream-contract reference and
  amended local API page have no dead links. Their linked requirements resolve.
- `git diff --check` passed. No production daemon was restarted or deployment
  performed. Production hub/member-session verification remains outside this
  local code change, as stated under [[IMPL-029-media-sharing#TEST-003]].

Raw command output for this session is in `/tmp/hark-58-tests-final.log`,
`/tmp/hark-58-targeted-final.log`, `/tmp/hark-58-clippy-final.log`,
`/tmp/hark-58-mutation-opaque.log`, `/tmp/hark-58-mutation-probe.log`,
`/tmp/hark-58-fmt.log` and `/tmp/hark-58-zetl-final.log`. Commands above provide
reproduction after those temporary files expire.
