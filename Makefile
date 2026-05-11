# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 Anuna Research

PREFIX ?= $(HOME)/.local

.PHONY: all build test check lint clippy fmt fmt-fix run install uninstall clean doc doc-open help

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

install: build
	install -d $(PREFIX)/bin
	install -m 755 target/release/hark $(PREFIX)/bin/hark
	@echo ""
	@echo "Installed hark to $(PREFIX)/bin/hark"
	@echo "Ensure $(PREFIX)/bin is on your PATH."

uninstall:
	rm -f $(PREFIX)/bin/hark

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
	@echo "  make install   - Install release binary to \$$PREFIX/bin"
	@echo "  make uninstall - Remove installed binary"
	@echo "  make clean     - Remove build artifacts"
	@echo "  make doc       - Generate documentation"
	@echo "  make doc-open  - Generate and open documentation"
	@echo ""
	@echo "Options:"
	@echo "  PREFIX=<path>  - Install prefix (default: \$$HOME/.local)"
