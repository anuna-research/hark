# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 Anuna Research

PREFIX ?= $(HOME)/.local

.PHONY: all build test check lint clippy fmt fmt-fix run man install uninstall dist clean doc doc-open help

all: build

build:
	cargo build --release

test:
	cargo test

check: lint test

lint:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings

clippy:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt --check

fmt-fix:
	cargo fmt

# Convenience: run the CLI against the current sources. Pass-through args
# with `make run ARGS="daemon status"`.
run:
	cargo run -- $(ARGS)

man: target/hark.1

target/hark.1: examples/gen-man.rs src/cli.rs Cargo.toml
	cargo run --quiet --example gen-man > $@

install: build man
	install -d $(PREFIX)/bin $(PREFIX)/share/man/man1
	install -m 755 target/release/hark $(PREFIX)/bin/hark
	install -m 644 target/hark.1 $(PREFIX)/share/man/man1/hark.1
	@echo ""
	@echo "Installed hark to $(PREFIX)/bin/hark"
	@echo "Installed man page to $(PREFIX)/share/man/man1/hark.1"
	@echo "Ensure $(PREFIX)/bin is on your PATH and"
	@echo "$(PREFIX)/share/man is on your MANPATH."

uninstall:
	rm -f $(PREFIX)/bin/hark
	rm -f $(PREFIX)/share/man/man1/hark.1

# Build the release binary and stage it as a distributable artifact for
# the host platform: dist/hark-<os>-<arch> plus its .sha256 checksum.
# Upload both to https://files.anuna.io/hark/ (see scripts/install.sh).
dist: build
	@set -e; \
	os=$$(uname -s); arch=$$(uname -m); \
	case "$$os" in \
	  Darwin) os=darwin ;; \
	  Linux) os=linux ;; \
	  *) echo "dist: unsupported OS: $$os" >&2; exit 1 ;; \
	esac; \
	case "$$arch" in \
	  arm64|aarch64) arch=arm64 ;; \
	  x86_64|amd64) arch=x64 ;; \
	  *) echo "dist: unsupported architecture: $$arch" >&2; exit 1 ;; \
	esac; \
	artifact="hark-$$os-$$arch"; \
	mkdir -p dist; \
	cp target/release/hark "dist/$$artifact"; \
	if command -v sha256sum >/dev/null 2>&1; then \
	  (cd dist && sha256sum "$$artifact" > "$$artifact.sha256"); \
	else \
	  (cd dist && shasum -a 256 "$$artifact" > "$$artifact.sha256"); \
	fi; \
	echo ""; \
	echo "Staged dist/$$artifact and dist/$$artifact.sha256"; \
	echo "Upload both to https://files.anuna.io/hark/ alongside scripts/install.sh."

clean:
	cargo clean
	rm -rf dist

doc:
	cargo doc --no-deps

doc-open:
	cargo doc --no-deps --open

help:
	@echo "hark - local CLI and daemon for cbcl-router agents"
	@echo ""
	@echo "Targets:"
	@echo "  make build     - Build release binary"
	@echo "  make test      - Run test suite"
	@echo "  make check     - Run lint + test"
	@echo "  make lint      - Run fmt check + clippy (deny warnings)"
	@echo "  make clippy    - Run clippy (deny warnings)"
	@echo "  make fmt       - Check formatting"
	@echo "  make fmt-fix   - Auto-fix formatting"
	@echo "  make run       - cargo run -- \$$ARGS  (e.g. ARGS=\"daemon status\")"
	@echo "  make man       - Generate target/hark.1 from the clap CLI"
	@echo "  make install   - Install binary + man page under \$$PREFIX"
	@echo "  make uninstall - Remove installed binary and man page"
	@echo "  make dist      - Stage dist/hark-<os>-<arch> + .sha256 for the host platform"
	@echo "  make clean     - Remove build artifacts"
	@echo "  make doc       - Generate documentation"
	@echo "  make doc-open  - Generate and open documentation"
	@echo ""
	@echo "Options:"
	@echo "  PREFIX=<path>  - Install prefix (default: \$$HOME/.local)"
