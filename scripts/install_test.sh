#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 Anuna Research
#
# Tests for scripts/install.sh. Run with:
#
#   sh scripts/install_test.sh
#
# Sources install.sh with INSTALL_SH_TEST=1 so functions load without
# running main, then exercises platform detection and artifact naming
# by overriding `uname` with a shell function. Prints PASS/FAIL per
# case and exits non-zero if any case fails.

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

INSTALL_SH_TEST=1
. "$script_dir/install.sh"

failures=0

pass() {
    printf 'PASS: %s\n' "$1"
}

fail() {
    printf 'FAIL: %s\n' "$1"
    failures=$((failures + 1))
}

# Fake uname controlled by FAKE_UNAME_S / FAKE_UNAME_M. Shell functions
# shadow the real command inside command substitutions, so detect_platform
# picks this up without modification.
uname() {
    case "$1" in
        -s) printf '%s\n' "$FAKE_UNAME_S" ;;
        -m) printf '%s\n' "$FAKE_UNAME_M" ;;
        *) printf 'unexpected uname flag: %s\n' "$1" >&2; return 1 ;;
    esac
}

# assert_platform <uname -s> <uname -m> <expected platform>
assert_platform() {
    FAKE_UNAME_S=$1
    FAKE_UNAME_M=$2
    expected=$3
    desc="detect_platform: $1/$2 -> $expected"
    got=$(detect_platform 2>/dev/null)
    if [ $? -eq 0 ] && [ "$got" = "$expected" ]; then
        pass "$desc"
    else
        fail "$desc (got '$got')"
    fi
}

# assert_unsupported <uname -s> <uname -m>
assert_unsupported() {
    FAKE_UNAME_S=$1
    FAKE_UNAME_M=$2
    desc="detect_platform: $1/$2 -> error"
    if got=$(detect_platform 2>/dev/null); then
        fail "$desc (unexpectedly succeeded with '$got')"
    else
        pass "$desc"
    fi
}

# assert_artifact <platform> <expected artifact>
assert_artifact() {
    expected=$2
    desc="resolve_artifact: $1 -> $expected"
    got=$(resolve_artifact "$1")
    if [ $? -eq 0 ] && [ "$got" = "$expected" ]; then
        pass "$desc"
    else
        fail "$desc (got '$got')"
    fi
}

# The four supported platforms.
assert_platform Darwin arm64   darwin-arm64
assert_platform Darwin x86_64  darwin-x64
assert_platform Linux  x86_64  linux-x64
assert_platform Linux  aarch64 linux-arm64

# Alternate arch spellings that map to the same artifacts.
assert_platform Linux  arm64   linux-arm64
assert_platform Linux  amd64   linux-x64

# Unsupported OS and architecture must fail.
assert_unsupported SunOS x86_64
assert_unsupported Linux riscv64
assert_unsupported Darwin i386

# Artifact name resolution.
assert_artifact darwin-arm64 hark-darwin-arm64
assert_artifact darwin-x64   hark-darwin-x64
assert_artifact linux-x64    hark-linux-x64
assert_artifact linux-arm64  hark-linux-arm64

if [ "$failures" -gt 0 ]; then
    printf '%d test(s) failed\n' "$failures"
    exit 1
fi
printf 'all tests passed\n'
exit 0
