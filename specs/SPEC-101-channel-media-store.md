---
mode: reference
---

# Upstream channel media store contract

This page records the upstream contract Hark consumes. The authoritative
specification is cbcl-bus `specs/SPEC-101-channel-media-store.md` at revision
`97f9fd52dd4c09b16e54d5d31e3f8cd874edca5a`, available at
https://git.anuna.io/anuna-research/cbcl-bus/src/commit/97f9fd52dd4c09b16e54d5d31e3f8cd874edca5a/specs/SPEC-101-channel-media-store.md.

## REQ-020

General attachments use exactly `application/octet-stream` in the existing
version-2 encrypted descriptor. They use the existing file object's `title` for
the display/download name. Authorized members explicitly download bytes after
size, digest, key commitment and AES-GCM authentication checks.

Opaque attachments have no automatic rendering, execution, navigation, playback,
or open action. Names and MIME hints cannot grant preview authority. Browser
custom views receive no opaque bytes or generic download capability.

Hark's `--download-only` selects this path explicitly. Default image/audio upload
retains the checked preview path. Existing descriptor encryption, size limits,
room authorization and media runtime controls apply to both paths.
