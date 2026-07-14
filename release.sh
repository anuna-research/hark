#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 Anuna Research

set -e

# hark release script (SPEC-016 REQ-001, ADR-006).
# Usage: ./release.sh [version]
# Example: ./release.sh 0.1.0
#
# Bumps the version, runs the gate (test + clippy), commits, tags, and pushes.
# Pushing the tag triggers .woodpecker/release.yaml on Codeberg, which
# cross-compiles the four prebuilt binaries and publishes them (plus install.sh)
# to Cloudflare R2, served at https://files.anuna.io/hark/.
#
# Requires the sibling ../cbcl-rs checkout (path dependency) for the local gate.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

VERSION="${1:-}"

if [[ -z "$VERSION" ]]; then
  CURRENT=$(grep '^version' Cargo.toml | head -1 | grep -o '"[^"]*"' | tr -d '"')
  echo "Current version: $CURRENT"
  read -p "Enter new version (without 'v' prefix): " VERSION
fi

[[ -z "$VERSION" ]] && error "Version is required"

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
  error "Invalid version format. Use semver: X.Y.Z or X.Y.Z-suffix"
fi

TAG="v$VERSION"

info "Preparing release $TAG"

if ! git diff --quiet || ! git diff --cached --quiet; then
  error "You have uncommitted changes. Commit or stash them first."
fi

if [[ "$(git rev-parse --abbrev-ref HEAD)" != "main" ]]; then
  error "Release from main; you are on $(git rev-parse --abbrev-ref HEAD)."
fi

if git rev-parse "$TAG" >/dev/null 2>&1; then
  error "Tag $TAG already exists"
fi

if [[ ! -d ../cbcl-rs ]]; then
  error "Sibling ../cbcl-rs not found (required path dependency). Clone it next to hark."
fi

info "Updating version in Cargo.toml..."
if [[ "$(uname)" == "Darwin" ]]; then
  sed -i '' "s/^version = \"[^\"]*\"/version = \"$VERSION\"/" Cargo.toml
else
  sed -i "s/^version = \"[^\"]*\"/version = \"$VERSION\"/" Cargo.toml
fi

info "Running tests..."
cargo test --quiet

info "Running clippy..."
cargo clippy --all-targets --quiet -- -D warnings

info "Committing version bump..."
# `cargo test` above refreshes hark's version in Cargo.lock.
git add Cargo.toml Cargo.lock
git commit -m "chore: release $TAG"

info "Creating tag $TAG..."
git tag -a "$TAG" -m "Release $VERSION"

info "Pushing to origin..."
git push origin main
git push origin "$TAG"

echo ""
info "Release $TAG published!"
echo ""
echo "Woodpecker release pipeline triggered (.woodpecker/release.yaml)."
echo "When it finishes, the release will be available at:"
echo "  https://files.anuna.io/hark/            (latest)"
echo "  https://files.anuna.io/hark/$TAG/"
echo ""
echo "Install:  curl https://files.anuna.io/hark/install.sh | sh"
