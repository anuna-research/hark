---
title: How to develop hark
mode: how-to
---

# How to develop hark

Use Rust 1.85 or later and a C compiler for `ring`.

Clone the repository:

```bash
git clone https://git.anuna.io/anuna-research/hark.git
cd hark
```

From this directory:

```bash
make build        # cargo build --release
make test         # cargo test
make check        # lint + test
make man          # generate target/hark.1 from the clap CLI
make dist         # stage dist/hark-<os>-<arch> + .sha256 for files.anuna.io/hark/
```

During development, run the CLI against the current sources with:

```bash
make run ARGS="daemon status"
```

Install the release binary and man page onto `PATH` (defaults to
`$HOME/.local`; override with `PREFIX=...`):

```bash
make install                    # -> $HOME/.local/{bin/hark,share/man/man1/hark.1}
make install PREFIX=/usr/local  # -> /usr/local/{bin,share/man/man1}
make uninstall
```

Once installed:

```bash
hark --help
man hark
```

`make help` lists every target. The Makefile is a thin wrapper around `cargo`,
so `cargo build`, `cargo test`, `cargo run -- daemon status`, etc., work
directly if you prefer.

The build needs a C compiler for `ring` (the release workflow's per-target
`CC_*` variables cover it). The object runtime links `cbcl-wasm` as native
Rust code; it needs no WebAssembly target or JavaScript runtime. Cargo
fetches the pinned dependencies.

Before changing behaviour, read [Specifications](../reference/specifications.md) and identify the governing requirements, contracts, and tests.
Keep their traceability links current with the implementation and documentation.
Submit focused changes through https://git.anuna.io/anuna-research/hark.

## Maintain object compatibility

When the hub is redeployed, match `Cargo.toml`'s `cbcl-core`, `cbcl-parser` and `cbcl-wasm` revisions to cbcl-bus's `cbcl-rs.sha`.
Copy the upstream `tests/vectors/state` corpus at that revision.
Run the object conformance tests through `make test`.
Keep one shared revision so agent and browser clients use the same canonical bytes and object addresses.
