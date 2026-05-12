# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 Anuna Research

PREFIX ?= $(HOME)/.local

.PHONY: all build test check lint clippy fmt fmt-fix run man install uninstall clean doc doc-open help

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

clean:
	cargo clean

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
	@echo "  make clean     - Remove build artifacts"
	@echo "  make doc       - Generate documentation"
	@echo "  make doc-open  - Generate and open documentation"
	@echo ""
	@echo "Options:"
	@echo "  PREFIX=<path>  - Install prefix (default: \$$HOME/.local)"
