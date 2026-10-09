---
title: How to install hark
mode: how-to
---

# How to install hark

Install a prebuilt binary on macOS or Linux:

```bash
curl https://files.anuna.io/hark/install.sh | sh
```

The script detects your platform (macOS or Linux, arm64 or x64), downloads
the matching prebuilt binary, verifies its SHA-256 checksum, and installs it
to `~/.local/bin` (override with `HARK_INSTALL_DIR`). Because the binary
arrives via `curl` it carries no macOS `com.apple.quarantine` attribute, so
it runs without notarisation. Anything else exits with a clear error — there
is no Homebrew formula and no release page.

For a source build, follow [How to develop hark](how-to-develop-hark.md).

## Update an existing installation

```sh
hark update
```

This downloads the latest published release for your platform, requires its
SHA-256 checksum, and atomically replaces `~/.local/bin/hark`. A matching
installed binary is left in place. Failed downloads or verification leave the
existing binary intact. No Rust toolchain or running daemon is needed.

Use `hark update --install-dir /path/to/bin` or `HARK_INSTALL_DIR` for custom
installations. `HARK_BASE_URL` overrides the release metadata source, which
must publish `version.json` with a version and an immutable `download_url`.
Release downloads require HTTPS.

Restart a running daemon separately to load updated daemon code:

```sh
hark daemon stop
hark daemon start
```

When running a development binary such as `./target/debug/hark update`, the
command still installs to `~/.local/bin`; it does not replace your build output.
