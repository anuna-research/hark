# Companion migration validation

Source base: Hark `8d0e295922a1770e1fc06dd304a78283ad60ab04`.
Dependency closure: all three CBCL crates at
`6b19878abf048725095fd39ffb3f73a1a9014536` (v0.2.0 plus parser depth guard).
This work ran in an isolated clone; the user's Hark checkout was unchanged.

Commands, from the Hark repository root:

```sh
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --no-fail-fast
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo clippy --all-targets --locked -- -D warnings
```

Result: 555 tests passed, 3 ignored (live-hub opt-in tests), no failures;
Clippy passed with warnings denied.

The target directory was the default `target/` in `/tmp/v020/hark`.
`cargo-test.txt` and `cargo-clippy.txt` retain the complete command output.
The v0.2 regression tests cover native installation of the exact bus settings
fixture, persisted host-clock restart and overwrite, declared-clock receipt
merging without interpreting prose as clock evidence, native recognition of
sealed-root transport metadata and inner authorship, and direct opener clocks
with the correct register replacement field. The ordinary API and chat-object
integration tests cover actual send/receive behavior; state conformance vectors
are copied from the pinned native dependency.

The browser file contract fixture is emitted by cbcl-bus's v0.2 file starter.
Frozen MLS-DS signature/canonical/wire vectors retain their previous bytes and
are tested by `parity_harness` and `ds_wire_interop`. The native DSL dialect
self-address has a distinct assertion from the frozen protocol identity.

This evidence does not claim a live bus/browser/Hark deployment or live data
cutover. Existing local journals retain historical bytes; old definitions and
messages are never rewritten as v0.2 artifacts.
