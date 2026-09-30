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
