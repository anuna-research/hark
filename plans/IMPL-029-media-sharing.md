---
id: IMPL-029
title: General attachments without external media tools
status: implemented
---

# General attachments without external media tools

| Field | Value |
|---|---|
| id | IMPL-029 |
| title | General attachments without external media tools |
| Source | Hark issue 58 and the user's explicit dependency/flag removal instructions |
| Tier | 2: attachment contract and media format boundaries |
| Owner | Implementation agent; fresh reviewer verifies the diff |
| Coordination | Elephant theory `hark-issue-58` |

## Failure mechanism and accepted contract

General documents cannot satisfy the old image/audio allowlist. Separately,
metadata inspection depended on an executable unavailable in a restricted daemon
launch environment. Configuring an external probe would preserve that failure
mode. The user requires removing that dependency and the extra upload-mode flag.

`hark media upload FILE` classifies the bytes automatically. Recognized images
and audio retain metadata inspection. Other formats use exactly
`application/octet-stream` under [[SPEC-101-channel-media-store#REQ-020]].
Opaque transfers reuse the existing encrypted descriptor, file object, authorized
room controls and storage protocol. They receive no rendering or automatic open.
Files that fail preview metadata checks select opaque transfer, as required by
the upstream general attachment policy. Declared-preview downloads remain strict.
No extension or caller MIME string grants preview authority.

Image headers/dimensions are read by `image`, enabled only for PNG, JPEG, GIF and
WebP. Audio track metadata is read by Symphonia's WAV, MP3, Ogg, MP4 and Matroska
format readers. No pixel/sample decoding is requested, and no media is played.
Parsers run
on bounded in-memory bytes in a blocking worker. Images retain the pixel limit;
audio requires an identified audio track and refuses non-audio/unknown tracks.
Metadata tags are bounded and cover art is not loaded for inspection.

Composition-first placement: reuse established format readers rather than adding
hand-written container parsers. These libraries compile into Hark. No runtime
executable, private probe temporary file, tool configuration, diagnostic command,
or extra upload-mode field remains. Existing image/audio fixture types remain
supported. The file-size and concurrent-transfer bounds remain in force.

API 5 identifies native opaque-descriptor/general-upload support. Discovery
rejects old API 4 daemons before a transfer, with existing restart guidance.
The API request retains `data`, `title`, `caption` and `allow_public` only.
The existing public-room consent flag remains because it acknowledges disclosure
of the descriptor key outside MLS; it does not select a media format.

## Planning ledger

| Task | Owner | Prerequisite | Acceptance | Source |
|---|---|---|---|---|
| attachments | implementer | existing opaque client contract | TEST-001 | [[SPEC-101-channel-media-store#REQ-020]] |
| probe | implementer | user instruction to remove external tools | TEST-002 | User's dependency removal instruction |
| verification | implementer and fresh reviewer | completed attachments and probe | TEST-003 | Updated issue 58 acceptance |

The `probe` task identifier is retained for coordination history; its current
work is removing the external probe, not configuring it. Prior completion claims
were retracted when the user changed the requirements.

### TEST-001

Validates: [[SPEC-101-channel-media-store#REQ-020]] and automatic classification.
Core: the ordinary PDF upload/list/download path returns byte-exact plaintext
through real HTTPS storage and the existing room-control harness. General bytes,
empty files and active document bytes automatically become opaque; tampering,
oversize and arbitrary descriptor MIME remain refused. Existing preview fixture
types retain their MIME. Native and pinned browser codecs open each other's
opaque ciphertext. The CLI has no format-selection flag.

### TEST-002

Validates: user instruction to remove the external dependency. Core: run native
image/audio metadata tests with PATH pointing to an empty directory. Source and
CI contain no external probe process, configuration or installation step.
Malformed headers, invalid/oversized image dimensions and invalid audio metadata
never grant preview authority. A declared-preview download rejects them; a general
upload transfers them as opaque. An API regression proves over-cap files emit no
storage reservation or file publication. No daemon-session dependency diagnostics are needed because
validation has no separately installed tools.

### TEST-003

Validates: updated acceptance and regression safety. Core: full tests, clippy,
changed-file formatting, byte-level browser interoperability, fresh adversarial
review and mutations of the image limit/opaque classification. The real CLI
rejects a mock API 4 daemon before making a media operation request.
Depth: production sharing needs a matched deployed hub/client and member session.
Local evidence uses the actual codec and HTTPS storage with the room-control
harness, and does not claim production deployment verification.

## Enable and rollback

The ordinary upload command enables general attachments automatically. Users need
no new format flags, executable installation or PATH setup. The documentation
requires matched hub/client general attachment support and tells room members
to reload older clients. The existing hub media switch disables transfer before
a matched-release rollback; stored bytes and grants remain. Ordinary chat remains
available. No production daemon is restarted by this implementation work.

## Evidence

The final dependency-free implementation passed `cargo test --locked
--no-fail-fast` and `cargo clippy --all-targets --locked -- -D warnings`.
Logs: `/tmp/hark-58-native-tests.log` and `/tmp/hark-58-native-clippy.log`.
Live-hub tests retain their existing ignored status; no production session or
shared daemon was changed.

`media_metadata_has_no_runtime_tool_dependency` runs the existing actual-format
fixture test in a child copy of the test executable, with PATH pointing to an
empty directory. It passed for the supported preview formats. The ordinary
PDF API upload/list/download test passed against real HTTPS storage and the
room-control harness, without any upload-mode flag or additional dependency.

Native negative tests passed for truncated positive-dimension headers, malformed
audio containers, unsupported BMFF brands, wrong declared types, and an ID3
header prepended to WAV data. A valid encoded image beyond the preview pixel
budget is opaque on upload and refused as a declared preview on download. A
separate API check proves over-cap input sends no storage or publication frames.

The pixel-budget test failed after deliberately raising the accepted limit.
The negative metadata test failed after deliberately granting the original
preview MIME on failed inspection. Both mutations were restored before the full
passing run. Logs: `/tmp/hark-58-native-mutation-pixels.log` and
`/tmp/hark-58-native-mutation-opaque.log`.

Fresh adversarial review found dimension-only header extraction and an audio
container/MIME mismatch. The implementation now uses structural image header
readers and compares the audio reader's detected container with the byte
signature. Regression tests exercise the findings. Final review reports no
remaining actionable issues. The upload fallback matches the upstream contract.

Changed Rust files pass rustfmt and `git diff --check`. Global formatting
remains blocked by existing untouched files. The vault check reports pre-existing
dead links; the changed plan and local contract references resolve. Link output:
`/tmp/hark-58-native-links.log`. Commands above reproduce verification after the
temporary logs expire. The browser codec interoperability checks run as part of
the full test suite.
