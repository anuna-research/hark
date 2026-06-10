#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 Anuna Research
#
# hark installer (SPEC-016 REQ-001, ADR-006).
#
# End users run:
#
#   curl https://files.anuna.io/hark/install.sh | sh
#
# Detects the platform, downloads the matching prebuilt binary from
# https://files.anuna.io/hark/, verifies its SHA-256 checksum, and
# installs it to $HARK_INSTALL_DIR (default: ~/.local/bin). No Rust
# toolchain required. curl downloads do not carry macOS's
# com.apple.quarantine attribute, so notarisation is optional.
#
# Supported artifacts:
#   hark-darwin-arm64  hark-darwin-x64  hark-linux-x64  hark-linux-arm64
#
# Publishing (operator):
#   1. On each target platform, run `make dist` in the hark repo. This
#      builds the release binary and writes dist/hark-<os>-<arch> plus
#      dist/hark-<os>-<arch>.sha256.
#   2. Upload both files (and this script as install.sh) to
#      https://files.anuna.io/hark/.
#
# Environment overrides:
#   HARK_BASE_URL     - artifact base URL (default: https://files.anuna.io/hark)
#   HARK_INSTALL_DIR  - install directory (default: ~/.local/bin)
#
# Testing: `INSTALL_SH_TEST=1 . scripts/install.sh` sources the functions
# without running main. See scripts/install_test.sh.

set -u

HARK_BASE_URL=${HARK_BASE_URL:-https://files.anuna.io/hark}

# Print "<os>-<arch>" for the current machine, or fail with a clear
# error on unsupported platforms.
detect_platform() {
    os=$(uname -s)
    arch=$(uname -m)

    case "$os" in
        Darwin) os=darwin ;;
        Linux)  os=linux ;;
        *)
            printf 'error: unsupported operating system: %s\n' "$os" >&2
            printf 'hark provides prebuilt binaries for macOS and Linux only.\n' >&2
            printf 'Build from source instead: https://codeberg.org/anuna/hark\n' >&2
            return 1
            ;;
    esac

    case "$arch" in
        arm64 | aarch64) arch=arm64 ;;
        x86_64 | amd64)  arch=x64 ;;
        *)
            printf 'error: unsupported architecture: %s\n' "$arch" >&2
            printf 'hark provides prebuilt binaries for arm64 and x64 only.\n' >&2
            printf 'Build from source instead: https://codeberg.org/anuna/hark\n' >&2
            return 1
            ;;
    esac

    printf '%s-%s\n' "$os" "$arch"
}

# Map a "<os>-<arch>" platform string to its artifact name.
resolve_artifact() {
    printf 'hark-%s\n' "$1"
}

# Verify $1 (file) against $2 (expected SHA-256 hex digest). Skips with
# a warning when no checksum tool is available.
verify_checksum() {
    file=$1
    expected=$2

    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$file" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$file" | awk '{print $1}')
    else
        printf 'warning: no sha256sum or shasum found; skipping checksum verification\n' >&2
        return 0
    fi

    if [ "$actual" != "$expected" ]; then
        printf 'error: checksum mismatch for %s\n' "$file" >&2
        printf '  expected: %s\n' "$expected" >&2
        printf '  actual:   %s\n' "$actual" >&2
        return 1
    fi
}

main() {
    if ! command -v curl >/dev/null 2>&1; then
        printf 'error: curl is required\n' >&2
        exit 1
    fi

    platform=$(detect_platform) || exit 1
    artifact=$(resolve_artifact "$platform")
    url="$HARK_BASE_URL/$artifact"
    install_dir=${HARK_INSTALL_DIR:-$HOME/.local/bin}

    tmpdir=$(mktemp -d) || exit 1
    trap 'rm -rf "$tmpdir"' EXIT INT TERM

    printf 'Downloading %s ...\n' "$url"
    if ! curl -fsSL -o "$tmpdir/hark" "$url"; then
        printf 'error: download failed: %s\n' "$url" >&2
        exit 1
    fi

    if expected=$(curl -fsSL "$url.sha256" 2>/dev/null); then
        expected=$(printf '%s\n' "$expected" | awk 'NF {print $1; exit}')
        verify_checksum "$tmpdir/hark" "$expected" || exit 1
    else
        printf 'warning: could not fetch %s.sha256; skipping checksum verification\n' "$url" >&2
    fi

    mkdir -p "$install_dir" || exit 1
    chmod +x "$tmpdir/hark"
    mv "$tmpdir/hark" "$install_dir/hark" || exit 1

    printf 'Installed hark to %s/hark\n' "$install_dir"
    case ":$PATH:" in
        *":$install_dir:"*) ;;
        *)
            printf '\n%s is not on your PATH. Add it with:\n' "$install_dir"
            printf '  export PATH="%s:$PATH"\n' "$install_dir"
            ;;
    esac
}

# When sourced with INSTALL_SH_TEST=1 (see scripts/install_test.sh),
# expose the functions without running main.
if [ "${INSTALL_SH_TEST:-}" != "1" ]; then
    main "$@"
fi
