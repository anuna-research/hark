# CBCL v0.2 interoperability

Hark pins cbcl-core, cbcl-parser and cbcl-wasm to the same depth-guarded
v0.2.0 revision as cbcl-bus: `6b19878abf048725095fd39ffb3f73a1a9014536`.
Object dialects and act addresses use `f1220` plus 64 lowercase hex digits.
Object definitions use explicit HLC register rules; Hark supplies and retains
host clocks. See [object definitions](object-definitions.md).

The settings fixture in `tests/vectors/cbcl-v020-settings.cbcl` is the exact
cbcl-bus settings dialect at self-address
`f12206c01de420d0205674c385556d81c5344d00ecbcdc1ef16e65ed12c4168219693`.
The runtime tests install it through the native v0.2 verifier and recognize
its object frames. The three state conformance fixtures are copied byte for
byte from the pinned cbcl-rs checkout; the file contract fixture is emitted
by the matching cbcl-bus browser starter.

MLS-DS/v1's RFC 9804 tuple encoding is a separate, frozen wire protocol.
Its 21 canonical vectors and DS signature/wire vectors retain their bytes.
`sha256:` values inside those tuples remain protocol digests. The historical
`MLS_DS_V1_CANONICAL_HASH` constant remains the frozen protocol identity;
`MLS_DS_V1_NATIVE_HASH` asserts the current parser's self-address of the same
dialect source. Neither substitutes for the other. Likewise MLS-epoch's
capability remains SHA-256 of the exact grammar bytes, not a dialect address.

Existing local object journals retain their historical bytes. This upgrade does
not rewrite old sha256-addressed definitions or messages. Recreate channels and
open new v0.2 objects; archived v0.1 records are not current object state.
