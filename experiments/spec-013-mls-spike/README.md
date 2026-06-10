# SPEC-013 §10 Experiment Spike — OpenMLS 0.8 oracle probes

**Status:** complete — incl. the storage-pruning and cross-stack `.wasm` follow-ups.
**Gate-permitted:** isolated crate, detached from hark's build, no production code touched. This characterises the OpenMLS **primitive**
(the test oracle) — it does **not** implement the gated SPEC-013 design.

**Purpose.** Turn the round-3 review's "could NOT assess" OpenMLS assumptions
([[SPEC-013-round3-review-findings]]) into observed evidence for the human crypto
sign-off, and confirm NFR-001 byte-compat before committing IMPL-013. Versions are pinned
to `cbcl-chat/crates/cbcl-mls-wasm/Cargo.toml` (`openmls 0.8`, resolved to **0.8.1**), so
the behaviour here is the web artifact's behaviour at the same crate version.

## Run

```
cargo test --manifest-path experiments/spec-013-mls-spike/Cargo.toml -- --nocapture --test-threads=1
```

Every probe prints `[R3-xx] …` / `[NFR-001] …` — the stdout **is** the evidence.

## Findings (openmls 0.8.1, pinned ciphersuite MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)

| Probe | REQ/finding | Observed | Consequence for the spec |
|---|---|---|---|
| `r3_07_self_update_credential_rebind` | **R3-07 (Critical)** → REQ-017 | OpenMLS **accepts** a self-Update that rebinds a member's leaf BasicCredential from `bob` → `alice` (same signer), and the **peer accepts** the commit; the forged identity is peer-visible. | **REQ-017's credential-immutability clause is load-bearing and confirmed necessary.** Without it, REQ-018's `:from` check passes for a forged `alice`. The primitive does *not* enforce credential continuity across Update (RFC 9420 §7.3) — the app must. |
| `r3_10_expired_keypackage_rejected` | **R3-10** → REQ-022 | `KeyPackageIn::validate()` **rejects** a 1970-expired KeyPackage with `InvalidLifetime` (openmls `key_package_in.rs:196-197`). Default-lifetime KP validates. | **Leaf-lifetime enforcement is present in the primitive.** REQ-022's bounded last-resort via a short `lifetime` is implementable — `validate()` already rejects expired packages at add time. Set a short lifetime; expiry is enforced for free. |
| `r3_11_max_past_epochs_bounds_window` | **R3-11 / OQ-005** → NFR-004 | `max_past_epochs(0)` ⇒ a prior-epoch message is **undecryptable** after advancing; `max_past_epochs(1)` ⇒ **decryptable**. Knob set on the **decrypting** group's JoinConfig. Confirmed knobs on `MlsGroupJoinConfigBuilder`: `max_past_epochs`, `number_of_resumption_psks`, `sender_ratchet_configuration`. | NFR-004/OQ-005 can name concrete knobs instead of principle. The past-message window is genuinely bounded by `max_past_epochs`; the resumption-PSK reservoir the review flagged is bounded by `number_of_resumption_psks`. |
| `r3_11_storage_prunes_superseded_epoch_secrets` | **R3-11 (mechanism, follow-up)** → NFR-004 | After 12 epoch changes, persisted secret-state is **8.4 KB** under `max_past_epochs(0)` vs **36 KB** under `(12)` (~2.3 KB/epoch retained). | OpenMLS **prunes superseded epoch secrets from the persisted state** under `(0)` — the deletes are real and reflected **at rest**, not only in memory. A durable provider (ADR-004) writing the same state inherits the bound. **Residual:** only that provider's own on-disk fsync/delete fidelity remains its own test. |
| `two_member_roundtrip_through_bytes`, `three_member_commit_processing` | **NFR-001** | create→add→welcome→encrypt→decrypt round-trips through TLS-serialized bytes; the authenticated MLS sender leaf resolves to the expected handle. | NFR-001 byte-compat holds natively at the pinned ciphersuite. (The authenticated-sender hook is what REQ-018 reads.) |

## Two probe bugs the *run* (not the compile) caught — recorded as method notes

1. `Lifetime::new(t)` sets `not_after = now + t`, so it is **not** expired at check time. A
   genuinely-expired lifetime needs the explicit `Lifetime::init(not_before, not_after)`
   (e.g. `init(0, 1)`). The first run falsely reported "lifetime not enforced."
2. `max_past_epochs` is a property of the **decrypting** group instance — it must be set on
   the joiner's `MlsGroupJoinConfig`, not (only) the creator's `MlsGroupCreateConfig`. The
   first run set it on the creator and falsely reported the knob had no effect.

Both are now fixed; the table above is the corrected result.

## Cross-stack confirmation (`cross-stack/`) — NFR-001 against the REAL `.wasm`

The follow-up that the first pass deferred is now done. `cross-stack/` drives the
**actually-compiled `cbcl-mls-wasm`** (built for nodejs by `build-wasm.sh`, same openmls
0.8.1 + wasm-bindgen 0.2.114) against the **native** OpenMLS peer over a JSON-line stdio
protocol, exchanging MLS wire bytes as hex:

```
./cross-stack/build-wasm.sh      # builds cross-stack/wasm-node/ (gitignored)
node cross-stack/cross_stack.mjs
```

- native (hark stack) = group creator/committer; wasm (web stack) = added member.
- **native→wasm:** wasm joins a native-produced Welcome and decrypts a native app message.
- **wasm→native:** native decrypts a wasm-produced app message.
- Result: **PASS** — the two stacks interoperate **both directions** at the pinned
  ciphersuite. This is the genuine cross-stack NFR-001 confirmation (native ⇄ the shipped
  `.wasm`, not native↔native). `src/bin/native_peer.rs` is the native side.

## What this spike still does NOT establish (carry to sign-off)

- **Durable-provider on-disk fidelity (narrowed R3-11 residual).** The pruning probe now
  shows OpenMLS bounds **persisted** secret-state by `max_past_epochs` (deletes reflected at
  rest). What remains is only that the *durable* StorageProvider ADR-004 introduces honours
  delete/fsync on real disk — a provider-level test once that provider exists.
- **`cbcl_ristretto` SPAKE2 point validation** (SPEC-016 REQ-007) — out of scope here; a
  separate check for the human cryptographer.

## Next step

Fold these results into the SPEC-013 §8 round-4 confirmation packet: R3-07 hardens the case
for REQ-017; R3-10 and R3-11 let NFR-004/REQ-022 cite concrete OpenMLS knobs instead of
asserted behaviour. The two residuals above are the remaining items the human signer accepts
or defers.
